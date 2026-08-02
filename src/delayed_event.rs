//! Delegated MatrixRTC membership lifecycle tracking (MSC4140).
//!
//! Restarts the homeserver's leave timer while a participant is on the SFU and
//! fires the leave once they disconnect, so a crashed client leaves no ghost.
//!
//! One task owns each job's state; everything else goes through its channel.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use backon::{ExponentialBuilder, Retryable};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinSet,
    time::{Instant, sleep_until},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::cs_api::{
    ActionError, CsApi, CsApiUrlCache, DelayEventAction, execute_delayed_event_action,
    resolve_cs_api,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct JobKey {
    pub room: String,
    pub identity: String,
}

#[derive(Clone, Debug)]
pub struct JobParams {
    pub delay_id: String,
    pub delay_timeout: Duration,
    pub server_name: String,
    pub live_kit_room: String,
    pub live_kit_identity: String,
}

impl JobParams {
    #[must_use]
    pub fn key(&self) -> JobKey {
        JobKey {
            room: self.live_kit_room.clone(),
            identity: self.live_kit_identity.clone(),
        }
    }
}

/// Sticky-event timeout; past this the membership has expired anyway.
const MAX_WINDOW: Duration = Duration::from_hours(1);

/// 80% of the delay, leaving headroom for the call to complete.
fn restart_interval(delay_timeout: Duration) -> Duration {
    delay_timeout.mul_f64(0.8)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    ParticipantConnected,
    ParticipantLookupSuccessful,
    ParticipantDisconnectedIntentionally,
    ParticipantConnectionAborted,
    DelayedEventReset,
    DelayedEventTimedOut,
    DelayedEventNotFound,
    CsApiUrlNotFound,
    WaitingStateTimedOut,
    /// ActionRestart succeeded; re-arm the restart timer.
    DelayedEventRestarted,
    /// A disconnect webhook was missed.
    SfuParticipantGone,
    JobReplaced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    WaitingForInitialConnect,
    Connected,
    Disconnected,
    Aborted,
    Replaced,
}

/// Absent pairs cause no change, so duplicate webhooks and late timer fires
/// are harmless.
const fn transition(state: JobState, signal: Signal) -> Option<JobState> {
    use {JobState::*, Signal::*};

    match (state, signal) {
        (_, JobReplaced) => Some(Replaced),

        (WaitingForInitialConnect, ParticipantConnected | ParticipantLookupSuccessful) => {
            Some(Connected)
        }
        (WaitingForInitialConnect, ParticipantConnectionAborted) => Some(Aborted),
        (WaitingForInitialConnect, WaitingStateTimedOut) => Some(Disconnected),

        (
            Connected,
            ParticipantDisconnectedIntentionally
            | ParticipantConnectionAborted
            | SfuParticipantGone,
        ) => Some(Disconnected),
        (Connected, DelayedEventTimedOut | DelayedEventNotFound | CsApiUrlNotFound) => {
            Some(Aborted)
        }

        _ => None,
    }
}

pub struct JobContext {
    pub http: reqwest::Client,
    pub cs_api_overrides: HashMap<String, String>,
    pub cs_api_cache: Arc<CsApiUrlCache>,
    pub live_kit: LiveKitAuth,
    /// How often to re-check that a connected participant is still on the SFU.
    /// `None` disables the check.
    pub sanity_check_interval: Option<Duration>,
}

#[derive(Clone)]
pub struct LiveKitAuth {
    pub url: String,
    pub key: String,
    pub secret: String,
}

/// `None` means the SFU was unreachable, which is not the same as absent.
async fn participant_present(auth: &LiveKitAuth, room: &str, identity: &str) -> Option<bool> {
    use livekit_api::services::{ServiceError, TwirpError, TwirpErrorCode};

    let client =
        livekit_api::services::room::RoomClient::with_api_key(&auth.url, &auth.key, &auth.secret);

    match client.get_participant(room, identity).await {
        Ok(_) => Some(true),
        Err(ServiceError::Twirp(TwirpError::Twirp(code)))
            if code.code == TwirpErrorCode::NOT_FOUND =>
        {
            Some(false)
        }
        Err(e) => {
            debug!(%room, %identity, error = %e, "Participant lookup failed");
            None
        }
    }
}

impl JobContext {
    async fn cs_api(&self, server_name: &str) -> Option<CsApi> {
        resolve_cs_api(
            &self.http,
            server_name,
            &self.cs_api_overrides,
            &self.cs_api_cache,
        )
        .await
        .inspect_err(|e| warn!(%server_name, error = %e, "Could not resolve Client-Server API"))
        .ok()
    }
}

struct JobHandle {
    id: u64,
    events: mpsc::Sender<Signal>,
    cancel: CancellationToken,
}

impl JobHandle {
    /// Dropping a signal is equivalent to the FSM ignoring it.
    fn send(&self, signal: Signal) {
        if self.events.try_send(signal).is_err() {
            debug!(?signal, "Job event channel unavailable, dropping signal");
        }
    }

    fn stop(&self) {
        self.cancel.cancel();
    }
}

/// Returns once the job reaches a terminal state or is cancelled.
async fn run_job(
    id: u64,
    params: JobParams,
    ctx: Arc<JobContext>,
    jobs: Arc<Mutex<HashMap<JobKey, JobHandle>>>,
    mut events: mpsc::Receiver<Signal>,
    tx: mpsc::Sender<Signal>,
    cancel: CancellationToken,
) {
    let mut state = JobState::WaitingForInitialConnect;
    let mut background = JoinSet::new();

    spawn_participant_lookup(&mut background, &params, &ctx, &tx, cancel.clone());

    let mut waiting_deadline = Some(Instant::now() + params.delay_timeout.min(MAX_WINDOW));
    // Extended by each successful restart.
    let mut restart_deadline = Instant::now() + params.delay_timeout;
    let mut restart_at: Option<Instant> = None;

    loop {
        let signal = tokio::select! {
            () = cancel.cancelled() => break,
            Some(signal) = events.recv() => signal,
            () = wait_until(waiting_deadline) => Signal::WaitingStateTimedOut,
            () = wait_until(restart_at) => Signal::DelayedEventReset,
        };

        // The internal action for Connected + DelayedEventReset: restart the
        // homeserver timer without leaving the state.
        if state == JobState::Connected {
            match signal {
                Signal::DelayedEventReset => {
                    restart_at = None;
                    spawn_restart(
                        &mut background,
                        &params,
                        &ctx,
                        &tx,
                        cancel.clone(),
                        restart_deadline,
                    );
                    continue;
                }
                Signal::DelayedEventRestarted => {
                    restart_deadline = Instant::now() + params.delay_timeout;
                    restart_at = Some(Instant::now() + restart_interval(params.delay_timeout));
                    continue;
                }
                _ => (),
            }
        }

        let Some(next) = transition(state, signal) else {
            debug!(?state, ?signal, "FSM event ignored in current state");
            continue;
        };

        info!(from = ?state, to = ?next, ?signal, room = %params.live_kit_room, "FSM transition");

        // Exit actions: each timer belongs to exactly one state.
        match state {
            JobState::WaitingForInitialConnect => waiting_deadline = None,
            JobState::Connected => restart_at = None,
            _ => (),
        }

        state = next;

        match state {
            JobState::Connected => {
                restart_deadline = Instant::now() + params.delay_timeout;
                // Restart immediately: we do not know how much of the delay
                // elapsed before the client handed the job over.
                let _ = tx.try_send(Signal::DelayedEventReset);
            }
            JobState::Disconnected => {
                // Give ActionSend a real attempt even if the deadline has
                // already passed, and never keep trying past the sticky-event
                // timeout.
                let remaining = restart_deadline
                    .saturating_duration_since(Instant::now())
                    .clamp(Duration::from_secs(1), MAX_WINDOW);

                spawn_send(&mut background, &params, &ctx, remaining);
                break;
            }
            JobState::Aborted | JobState::Replaced => break,
            JobState::WaitingForInitialConnect => (),
        }
    }

    // Stop the lookup and any in-flight restart. The leave send deliberately
    // ignores this, so draining below still lets it finish.
    cancel.cancel();

    // Drain rather than abort, or the leave send would be killed and the
    // delegation would be pointless.
    while background.join_next().await.is_some() {}

    // Only evict ourselves: a replacement may already hold this key.
    let mut jobs = jobs.lock().await;
    if jobs
        .get(&params.key())
        .is_some_and(|current| current.id == id)
    {
        jobs.remove(&params.key());
    }
}

/// Watches the SFU for a participant the webhooks may never mention: phase one
/// waits for them to appear, phase two catches a missed disconnect webhook.
fn spawn_participant_lookup(
    background: &mut JoinSet<()>,
    params: &JobParams,
    ctx: &Arc<JobContext>,
    tx: &mpsc::Sender<Signal>,
    cancel: CancellationToken,
) {
    let (params, ctx, tx) = (params.clone(), Arc::clone(ctx), tx.clone());

    background.spawn(async move {
        cancel
            .run_until_cancelled(participant_lookup(params, ctx, tx))
            .await;
    });
}

async fn participant_lookup(params: JobParams, ctx: Arc<JobContext>, tx: mpsc::Sender<Signal>) {
    {
        let auth = &ctx.live_kit;
        let (room, identity) = (&params.live_kit_room, &params.live_kit_identity);

        let appeared = (|| async {
            match participant_present(auth, room, identity).await {
                Some(true) => Ok(()),
                // Absent and unreachable are both worth retrying here; we are
                // waiting for the participant to show up.
                Some(false) => Err("participant not present yet"),
                None => Err("SFU unreachable"),
            }
        })
        .retry(
            ExponentialBuilder::default()
                .with_min_delay(Duration::from_secs(1))
                .with_factor(1.5)
                .with_max_delay(Duration::from_secs(60))
                .with_jitter()
                .without_max_times()
                .with_total_delay(Some(params.delay_timeout.min(MAX_WINDOW))),
        )
        .await;

        if appeared.is_err() {
            debug!(%room, %identity, "Participant never appeared on the SFU");
            return;
        }

        let _ = tx.try_send(Signal::ParticipantLookupSuccessful);

        let Some(interval) = ctx.sanity_check_interval else {
            return;
        };

        loop {
            tokio::time::sleep(interval).await;

            // Only a confirmed absence ends the job. A transport blip must not
            // tear down a live call.
            if participant_present(auth, room, identity).await == Some(false) {
                warn!(%room, %identity, "Participant no longer on the SFU");
                let _ = tx.try_send(Signal::SfuParticipantGone);
                return;
            }
        }
    }
}

/// `sleep_until` for an optional deadline; pends forever when unset.
async fn wait_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

fn spawn_restart(
    background: &mut JoinSet<()>,
    params: &JobParams,
    ctx: &Arc<JobContext>,
    tx: &mpsc::Sender<Signal>,
    cancel: CancellationToken,
    deadline: Instant,
) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        info!(room = %params.live_kit_room, "Restart deadline exhausted");
        let _ = tx.try_send(Signal::DelayedEventTimedOut);
        return;
    }

    let (params, ctx, tx) = (params.clone(), Arc::clone(ctx), tx.clone());

    background.spawn(async move {
        cancel
            .run_until_cancelled(restart(params, ctx, tx, remaining))
            .await;
    });
}

async fn restart(
    params: JobParams,
    ctx: Arc<JobContext>,
    tx: mpsc::Sender<Signal>,
    remaining: Duration,
) {
    {
        let Some(cs_api) = ctx.cs_api(&params.server_name).await else {
            let _ = tx.try_send(Signal::CsApiUrlNotFound);
            return;
        };

        match retry_action(
            &ctx,
            &cs_api,
            &params.delay_id,
            DelayEventAction::Restart,
            remaining,
        )
        .await
        {
            Ok(()) => {
                debug!(room = %params.live_kit_room, "ActionRestart ok");
                let _ = tx.try_send(Signal::DelayedEventRestarted);
            }
            Err(ActionError::NotFound) => {
                warn!(room = %params.live_kit_room, "ActionRestart: delayed event not found");
                let _ = tx.try_send(Signal::DelayedEventNotFound);
            }
            Err(e) => {
                warn!(room = %params.live_kit_room, error = %e, "ActionRestart failed");
                let _ = tx.try_send(Signal::DelayedEventTimedOut);
            }
        }
    }
}

/// Not cancellation-guarded: if the service is shutting down we still want the
/// leave event delivered.
fn spawn_send(
    background: &mut JoinSet<()>,
    params: &JobParams,
    ctx: &Arc<JobContext>,
    remaining: Duration,
) {
    let (params, ctx) = (params.clone(), Arc::clone(ctx));

    background.spawn(async move {
        let Some(cs_api) = ctx.cs_api(&params.server_name).await else {
            warn!(room = %params.live_kit_room, "ActionSend could not resolve Client-Server API");
            return;
        };

        match retry_action(
            &ctx,
            &cs_api,
            &params.delay_id,
            DelayEventAction::Send,
            remaining,
        )
        .await
        {
            Ok(()) => info!(room = %params.live_kit_room, "Leave event sent"),
            Err(e) => warn!(room = %params.live_kit_room, error = %e, "ActionSend failed"),
        }
    });
}

/// Same schedule as lk-jwt-service: 1s initial, x1.5, capped at 60s, jittered,
/// giving up once `max_elapsed` of cumulative sleeping has passed.
async fn retry_action(
    ctx: &JobContext,
    cs_api: &CsApi,
    delay_id: &str,
    action: DelayEventAction,
    max_elapsed: Duration,
) -> Result<(), ActionError> {
    let policy = ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(1))
        .with_factor(1.5)
        .with_max_delay(Duration::from_secs(60))
        .with_jitter()
        .without_max_times()
        .with_total_delay(Some(max_elapsed));

    let attempts = (|| async {
        match execute_delayed_event_action(&ctx.http, cs_api, delay_id, action).await {
            // backon cannot vary its delay per error, so wait the server's hint
            // here and let it schedule the attempt after that.
            Err(ActionError::RetryAfter(hint)) => {
                tokio::time::sleep(hint).await;
                Err(ActionError::Transient("rate limited".to_owned()))
            }
            other => other,
        }
    })
    .retry(policy)
    .when(|e| !matches!(e, ActionError::NotFound | ActionError::Terminal(_)));

    // That sleep is invisible to backon's total-delay budget, so bound the
    // whole thing; otherwise a rate-limited server could stretch us well past
    // the deadline this window was derived from.
    tokio::time::timeout(max_elapsed, attempts)
        .await
        .unwrap_or_else(|_| Err(ActionError::Transient("retry budget exhausted".to_owned())))
        .map(|_| ())
}

/// Owns the set of running jobs and routes SFU events to them.
pub struct DelayedEventManager {
    ctx: Arc<JobContext>,
    jobs: Arc<Mutex<HashMap<JobKey, JobHandle>>>,
    next_id: AtomicU64,
}

impl DelayedEventManager {
    #[must_use]
    pub fn new(ctx: JobContext) -> Self {
        Self {
            ctx: Arc::new(ctx),
            jobs: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(0),
        }
    }

    /// Starts a job, replacing any existing one for the same participant.
    pub async fn add_job(&self, params: JobParams) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(10);
        let cancel = CancellationToken::new();

        let handle = JobHandle {
            id,
            events: tx.clone(),
            cancel: cancel.clone(),
        };

        if let Some(previous) = self.jobs.lock().await.insert(params.key(), handle) {
            previous.send(Signal::JobReplaced);
            previous.stop();
        }

        tokio::spawn(run_job(
            id,
            params,
            Arc::clone(&self.ctx),
            Arc::clone(&self.jobs),
            rx,
            tx,
            cancel,
        ));
    }

    /// Routes an SFU webhook signal to the job for that participant, if any.
    pub async fn dispatch(&self, room: &str, identity: &str, signal: Signal) {
        let key = JobKey {
            room: room.to_owned(),
            identity: identity.to_owned(),
        };

        match self.jobs.lock().await.get(&key) {
            Some(job) => job.send(signal),
            None => debug!(%room, %identity, ?signal, "No delayed event job for participant"),
        }
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.jobs.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> DelayedEventManager {
        DelayedEventManager::new(JobContext {
            http: reqwest::Client::new(),
            cs_api_overrides: HashMap::new(),
            cs_api_cache: Arc::new(CsApiUrlCache::new()),
            live_kit: LiveKitAuth {
                url: "http://127.0.0.1:1".to_owned(),
                key: "key".to_owned(),
                secret: "secret".to_owned(),
            },
            sanity_check_interval: None,
        })
    }

    fn params(identity: &str) -> JobParams {
        JobParams {
            delay_id: "delay".to_owned(),
            delay_timeout: Duration::from_secs(30),
            server_name: "example.com".to_owned(),
            live_kit_room: "room".to_owned(),
            live_kit_identity: identity.to_owned(),
        }
    }

    /// Re-delegating for the same participant must not accumulate handles.
    #[tokio::test]
    async fn replacing_a_job_keeps_one_entry() {
        let manager = manager();

        manager.add_job(params("alice")).await;
        manager.add_job(params("alice")).await;
        assert_eq!(manager.len().await, 1);

        manager.add_job(params("bob")).await;
        assert_eq!(manager.len().await, 2);
    }

    /// The sanity check loops forever by design, so a terminal state has to
    /// cancel it or the job would never finish draining.
    #[tokio::test(start_paused = true)]
    async fn a_finished_job_evicts_itself_with_sanity_checks_running() {
        let mut ctx_manager = manager();
        ctx_manager.ctx = Arc::new(JobContext {
            http: reqwest::Client::new(),
            cs_api_overrides: HashMap::new(),
            cs_api_cache: Arc::new(CsApiUrlCache::new()),
            live_kit: LiveKitAuth {
                url: "http://127.0.0.1:1".to_owned(),
                key: "key".to_owned(),
                secret: "secret".to_owned(),
            },
            sanity_check_interval: Some(Duration::from_secs(5)),
        });

        ctx_manager.add_job(params("alice")).await;
        tokio::time::sleep(Duration::from_secs(60 * 60 * 3)).await;
        tokio::task::yield_now().await;

        assert_eq!(ctx_manager.len().await, 0);
    }

    /// A job that reaches a terminal state must evict itself, or the map grows
    /// without bound over the life of the process.
    #[tokio::test(start_paused = true)]
    async fn a_finished_job_evicts_itself() {
        let manager = manager();
        manager.add_job(params("alice")).await;
        assert_eq!(manager.len().await, 1);

        // Nobody ever joins, so the wait times out, the leave is attempted
        // against an unreachable homeserver, and the job ends.
        tokio::time::sleep(Duration::from_secs(60 * 60 * 3)).await;
        tokio::task::yield_now().await;

        assert_eq!(manager.len().await, 0);
    }

    #[test]
    fn waiting_state_reaches_connected_on_either_connect_signal() {
        for signal in [
            Signal::ParticipantConnected,
            Signal::ParticipantLookupSuccessful,
        ] {
            assert_eq!(
                transition(JobState::WaitingForInitialConnect, signal),
                Some(JobState::Connected)
            );
        }
    }

    /// A client that never shows up still gets its leave event sent.
    #[test]
    fn waiting_state_timeout_sends_the_leave() {
        assert_eq!(
            transition(
                JobState::WaitingForInitialConnect,
                Signal::WaitingStateTimedOut
            ),
            Some(JobState::Disconnected)
        );
    }

    #[test]
    fn every_disconnect_from_connected_sends_the_leave() {
        for signal in [
            Signal::ParticipantDisconnectedIntentionally,
            Signal::ParticipantConnectionAborted,
            Signal::SfuParticipantGone,
        ] {
            assert_eq!(
                transition(JobState::Connected, signal),
                Some(JobState::Disconnected)
            );
        }
    }

    /// A restart failure must not send the leave: the homeserver's own timer
    /// is still authoritative.
    #[test]
    fn restart_failures_abort_rather_than_send() {
        for signal in [
            Signal::DelayedEventTimedOut,
            Signal::DelayedEventNotFound,
            Signal::CsApiUrlNotFound,
        ] {
            assert_eq!(
                transition(JobState::Connected, signal),
                Some(JobState::Aborted)
            );
        }
    }

    #[test]
    fn job_replaced_wins_from_any_state() {
        for state in [
            JobState::WaitingForInitialConnect,
            JobState::Connected,
            JobState::Disconnected,
            JobState::Aborted,
        ] {
            assert_eq!(
                transition(state, Signal::JobReplaced),
                Some(JobState::Replaced)
            );
        }
    }

    /// Duplicate webhooks and late timer fires arrive routinely.
    #[test]
    fn unknown_pairs_are_ignored() {
        assert_eq!(
            transition(JobState::Disconnected, Signal::DelayedEventTimedOut),
            None
        );
        assert_eq!(
            transition(JobState::Aborted, Signal::ParticipantConnected),
            None
        );
        assert_eq!(
            transition(
                JobState::WaitingForInitialConnect,
                Signal::DelayedEventReset
            ),
            None
        );
    }

    #[test]
    fn restart_fires_before_the_homeserver_timer_expires() {
        let timeout = Duration::from_secs(30);
        assert!(restart_interval(timeout) < timeout);
        assert_eq!(restart_interval(timeout), Duration::from_secs(24));
    }
}
