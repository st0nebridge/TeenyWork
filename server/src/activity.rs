//! The activity ledger: what the Challenger did (challenges, leases, proofs,
//! pool shares, verified forms), as lifetime totals and the newest records.
//!
//! Purpose: replay the ledger at startup, and append to it through one writer
//! thread that commits records in groups. Every record waiting when the writer
//! wakes is written, the file is synced once, and then each caller is answered.
//! A caller still returns only after its record is on disk, but concurrent
//! requests share one sync, and no request blocks the async runtime or holds a
//! request lock while the disk syncs.
//! Depends on: `ledger` (files, rotation, replay), `tokio::sync::oneshot` for
//! the answers, `std::thread` and `std::sync::mpsc` for the writer.
//! Used by: `main.rs` (`record_activity`, `/admin/activity`, `/metrics`).

use crate::ledger;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, PoisonError};
use std::thread;
use tokio::sync::oneshot;

/// Records kept in memory for `/admin/activity`.
pub const RECENT_ACTIVITY_LIMIT: usize = 100;
/// Most records written under one sync.
const MAX_GROUP: usize = 1024;

#[derive(Default)]
pub struct Analytics {
    pub challenges_issued: AtomicU64,
    pub leases_issued: AtomicU64,
    pub proofs_accepted: AtomicU64,
    pub proofs_rejected: AtomicU64,
    pub pool_candidates: AtomicU64,
    pub pool_shares_accepted: AtomicU64,
    pub pool_shares_rejected: AtomicU64,
    pub form_submissions_verified: AtomicU64,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    ChallengeIssued,
    LeaseIssued,
    ProofAccepted,
    ProofRejected,
    PoolShareCandidate,
    PoolShareAccepted,
    PoolShareRejected,
    FormSubmissionVerified,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ActivityRecord {
    pub occurred_at: DateTime<Utc>,
    pub event: ActivityKind,
    pub challenge_id: Option<String>,
    pub work_units: Option<u64>,
}

/// Lifetime count of each activity kind.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default)]
struct ActivityTotals {
    challenges_issued: u64,
    leases_issued: u64,
    proofs_accepted: u64,
    proofs_rejected: u64,
    pool_share_candidates: u64,
    pool_shares_accepted: u64,
    pool_shares_rejected: u64,
    form_submissions_verified: u64,
}

impl ActivityTotals {
    fn counters(&mut self) -> [&mut u64; 8] {
        [
            &mut self.challenges_issued,
            &mut self.leases_issued,
            &mut self.proofs_accepted,
            &mut self.proofs_rejected,
            &mut self.pool_share_candidates,
            &mut self.pool_shares_accepted,
            &mut self.pool_shares_rejected,
            &mut self.form_submissions_verified,
        ]
    }

    fn record(&mut self, event: ActivityKind) {
        let counter = match event {
            ActivityKind::ChallengeIssued => &mut self.challenges_issued,
            ActivityKind::LeaseIssued => &mut self.leases_issued,
            ActivityKind::ProofAccepted => &mut self.proofs_accepted,
            ActivityKind::ProofRejected => &mut self.proofs_rejected,
            ActivityKind::PoolShareCandidate => &mut self.pool_share_candidates,
            ActivityKind::PoolShareAccepted => &mut self.pool_shares_accepted,
            ActivityKind::PoolShareRejected => &mut self.pool_shares_rejected,
            ActivityKind::FormSubmissionVerified => &mut self.form_submissions_verified,
        };
        *counter = counter.saturating_add(1);
    }

    fn add(&mut self, mut other: Self) {
        for (total, added) in self.counters().into_iter().zip(other.counters()) {
            *total = total.saturating_add(*added);
        }
    }
}

/// The first line of every activity ledger file started by rotation: the
/// lifetime totals of everything written before that file. Replay adds the
/// newest checkpoint to the records after it, so the totals survive rotation
/// even after the oldest files are deleted.
#[derive(Deserialize, Serialize)]
struct ActivityCheckpoint {
    checkpoint: ActivityCheckpointBody,
}

#[derive(Deserialize, Serialize)]
struct ActivityCheckpointBody {
    rotated_at: DateTime<Utc>,
    totals: ActivityTotals,
}

fn checkpoint_line(totals: ActivityTotals) -> io::Result<Option<Vec<u8>>> {
    ledger::encode_line(&ActivityCheckpoint {
        checkpoint: ActivityCheckpointBody {
            rotated_at: Utc::now(),
            totals,
        },
    })
    .map(Some)
}

/// What one activity ledger file contributes at startup.
#[derive(Default)]
struct ReplayedActivityFile {
    checkpoint: Option<ActivityTotals>,
    counts: ActivityTotals,
    recent: VecDeque<ActivityRecord>,
    skipped_lines: u64,
}

fn replay_activity_file(path: &Path) -> io::Result<ReplayedActivityFile> {
    let mut checkpoint = None;
    let mut counts = ActivityTotals::default();
    let mut recent = VecDeque::new();
    let mut seen_record = false;
    let skipped_lines = ledger::replay_file(path, |line| {
        match serde_json::from_slice::<ActivityRecord>(line) {
            Ok(record) => {
                seen_record = true;
                counts.record(record.event);
                recent.push_back(record);
                if recent.len() > RECENT_ACTIVITY_LIMIT {
                    recent.pop_front();
                }
                Ok(())
            }
            Err(record_error) => match serde_json::from_slice::<ActivityCheckpoint>(line) {
                Ok(parsed) if !seen_record && checkpoint.is_none() => {
                    checkpoint = Some(parsed.checkpoint.totals);
                    Ok(())
                }
                Ok(_) => Err("a checkpoint is only valid before a file's first record".into()),
                Err(_) => Err(record_error.to_string()),
            },
        }
    })?;
    Ok(ReplayedActivityFile {
        checkpoint,
        counts,
        recent,
        skipped_lines,
    })
}

impl Analytics {
    fn from_totals(totals: &ActivityTotals) -> Self {
        Self {
            challenges_issued: AtomicU64::new(totals.challenges_issued),
            leases_issued: AtomicU64::new(totals.leases_issued),
            proofs_accepted: AtomicU64::new(totals.proofs_accepted),
            proofs_rejected: AtomicU64::new(totals.proofs_rejected),
            pool_candidates: AtomicU64::new(totals.pool_share_candidates),
            pool_shares_accepted: AtomicU64::new(totals.pool_shares_accepted),
            pool_shares_rejected: AtomicU64::new(totals.pool_shares_rejected),
            form_submissions_verified: AtomicU64::new(totals.form_submissions_verified),
        }
    }

    pub fn record(&self, event: ActivityKind) {
        let counter = match event {
            ActivityKind::ChallengeIssued => &self.challenges_issued,
            ActivityKind::LeaseIssued => &self.leases_issued,
            ActivityKind::ProofAccepted => &self.proofs_accepted,
            ActivityKind::ProofRejected => &self.proofs_rejected,
            ActivityKind::PoolShareCandidate => &self.pool_candidates,
            ActivityKind::PoolShareAccepted => &self.pool_shares_accepted,
            ActivityKind::PoolShareRejected => &self.pool_shares_rejected,
            ActivityKind::FormSubmissionVerified => &self.form_submissions_verified,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// The answer to one append: how many records shared its sync.
type Answer = io::Result<usize>;

struct Pending {
    record: ActivityRecord,
    answer: oneshot::Sender<Answer>,
}

type Recent = Arc<Mutex<VecDeque<ActivityRecord>>>;

/// Holds the activity ledger's writer between groups until released. Dropping
/// it releases the writer for good.
#[cfg(test)]
pub struct ActivityGate(mpsc::Sender<()>);

pub struct ActivityLog {
    queue: Option<mpsc::Sender<Pending>>,
    writer: Option<thread::JoinHandle<()>>,
    recent: Recent,
    pub skipped_lines: u64,
}

impl ActivityLog {
    #[cfg(test)]
    pub fn load(path: &Path) -> io::Result<(Self, Analytics)> {
        Self::load_with_max_bytes(path, ledger::DEFAULT_MAX_BYTES)
    }

    /// Replays the live file and its rotated predecessors, newest first, then
    /// starts the writer. Totals are the records counted back to (and
    /// including) the newest intact checkpoint; recent activity is the newest
    /// records across retained files. Malformed lines are skipped and counted
    /// rather than stopping startup.
    pub fn load_with_max_bytes(path: &Path, max_bytes: u64) -> io::Result<(Self, Analytics)> {
        Self::start(path, max_bytes, None)
    }

    /// Like [`ActivityLog::load_with_max_bytes`], with a writer that waits for
    /// the returned gate before each group.
    #[cfg(test)]
    pub fn load_gated(path: &Path, max_bytes: u64) -> io::Result<(Self, Analytics, ActivityGate)> {
        let (release, gate) = mpsc::channel();
        let (log, analytics) = Self::start(path, max_bytes, Some(gate))?;
        Ok((log, analytics, ActivityGate(release)))
    }

    fn start(
        path: &Path,
        max_bytes: u64,
        gate: Option<mpsc::Receiver<()>>,
    ) -> io::Result<(Self, Analytics)> {
        let mut totals = ActivityTotals::default();
        let mut counting = true;
        let mut recent = VecDeque::with_capacity(RECENT_ACTIVITY_LIMIT);
        let mut skipped_lines = 0;
        for file in ledger::retained_paths(path) {
            if !counting && recent.len() >= RECENT_ACTIVITY_LIMIT {
                break;
            }
            let replayed = replay_activity_file(&file)?;
            skipped_lines += replayed.skipped_lines;
            if counting {
                totals.add(replayed.counts);
                if let Some(checkpoint) = replayed.checkpoint {
                    totals.add(checkpoint);
                    counting = false;
                }
            }
            for record in replayed.recent.into_iter().rev() {
                if recent.len() >= RECENT_ACTIVITY_LIMIT {
                    break;
                }
                recent.push_front(record);
            }
        }
        let ledger = ledger::LedgerFile::open(path, max_bytes)?;
        let recent = Arc::new(Mutex::new(recent));
        let (queue, received) = mpsc::channel();
        let writer = Writer {
            ledger,
            totals,
            recent: recent.clone(),
        };
        let writer = thread::Builder::new()
            .name("activity-ledger".to_string())
            .spawn(move || writer.run(&received, gate.as_ref()))?;
        Ok((
            Self {
                queue: Some(queue),
                writer: Some(writer),
                recent,
                skipped_lines,
            },
            Analytics::from_totals(&totals),
        ))
    }

    /// Appends `record` and returns once it is synced to disk, with the number
    /// of records that were committed under the same sync.
    pub async fn append(&self, record: ActivityRecord) -> Answer {
        self.submit(record)?.await.map_err(|_| writer_stopped())?
    }

    /// Queues `record` for the writer and returns the receiver of its answer.
    fn submit(&self, record: ActivityRecord) -> io::Result<oneshot::Receiver<Answer>> {
        let (answer, answered) = oneshot::channel();
        self.queue
            .as_ref()
            .ok_or_else(writer_stopped)?
            .send(Pending { record, answer })
            .map_err(|_| writer_stopped())?;
        Ok(answered)
    }

    /// The newest records, oldest first.
    pub fn recent(&self) -> Vec<ActivityRecord> {
        lock(&self.recent).iter().cloned().collect()
    }
}

impl Drop for ActivityLog {
    /// Closes the queue and waits for the writer to finish the records it
    /// already holds, so the file is complete and closed afterwards.
    fn drop(&mut self) {
        self.queue.take();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

#[cfg(test)]
impl ActivityGate {
    /// Lets the writer commit one more group.
    pub fn release_one(&self) {
        let _ = self.0.send(());
    }
}

fn writer_stopped() -> io::Error {
    io::Error::other("the activity ledger writer has stopped")
}

fn lock(recent: &Recent) -> std::sync::MutexGuard<'_, VecDeque<ActivityRecord>> {
    recent.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The writer thread's state: the live file, the totals its next checkpoint
/// needs, and the recent records it shares with readers.
struct Writer {
    ledger: ledger::LedgerFile,
    totals: ActivityTotals,
    recent: Recent,
}

impl Writer {
    fn run(mut self, queue: &mpsc::Receiver<Pending>, gate: Option<&mpsc::Receiver<()>>) {
        while let Ok(first) = queue.recv() {
            if let Some(gate) = gate {
                let _ = gate.recv();
            }
            let mut group = vec![first];
            while group.len() < MAX_GROUP {
                match queue.try_recv() {
                    Ok(pending) => group.push(pending),
                    Err(_) => break,
                }
            }
            self.commit(group);
        }
    }

    /// Writes every record in `group`, syncs once, and answers each caller.
    /// A record is counted in the totals once written, because replay will
    /// count it; it joins the recent records, and its caller hears success,
    /// only once the sync has succeeded.
    fn commit(&mut self, group: Vec<Pending>) {
        let size = group.len();
        let mut written = Vec::with_capacity(size);
        for pending in group {
            let totals_before = self.totals;
            let result = self
                .ledger
                .write(&pending.record, || checkpoint_line(totals_before));
            if result.is_ok() {
                self.totals.record(pending.record.event);
            }
            written.push((pending, result));
        }
        let synced = self.ledger.sync();
        let mut recent = lock(&self.recent);
        for (pending, result) in written {
            let answer = match (result, &synced) {
                (Err(error), _) => Err(error),
                (Ok(()), Err(error)) => Err(io::Error::new(error.kind(), error.to_string())),
                (Ok(()), Ok(())) => {
                    recent.push_back(pending.record);
                    if recent.len() > RECENT_ACTIVITY_LIMIT {
                        recent.pop_front();
                    }
                    Ok(size)
                }
            };
            let _ = pending.answer.send(answer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ScratchDir;

    const KINDS: [ActivityKind; 8] = [
        ActivityKind::ChallengeIssued,
        ActivityKind::LeaseIssued,
        ActivityKind::ProofAccepted,
        ActivityKind::ProofRejected,
        ActivityKind::PoolShareCandidate,
        ActivityKind::PoolShareAccepted,
        ActivityKind::PoolShareRejected,
        ActivityKind::FormSubmissionVerified,
    ];

    fn line(event: &str, challenge_id: &str) -> String {
        format!(
            "{{\"occurred_at\":\"2026-10-14T10:00:00Z\",\"event\":\"{event}\",\
             \"challenge_id\":\"{challenge_id}\",\"work_units\":12}}\n"
        )
    }

    fn record(event: ActivityKind, challenge_id: String) -> ActivityRecord {
        ActivityRecord {
            occurred_at: Utc::now(),
            event,
            challenge_id: Some(challenge_id),
            work_units: Some(12),
        }
    }

    fn counts(analytics: &Analytics) -> [u64; 8] {
        [
            &analytics.challenges_issued,
            &analytics.leases_issued,
            &analytics.proofs_accepted,
            &analytics.proofs_rejected,
            &analytics.pool_candidates,
            &analytics.pool_shares_accepted,
            &analytics.pool_shares_rejected,
            &analytics.form_submissions_verified,
        ]
        .map(|counter| counter.load(Ordering::Relaxed))
    }

    fn recent_ids(recent: &[ActivityRecord]) -> Vec<String> {
        recent
            .iter()
            .map(|record| record.challenge_id.clone().unwrap_or_default())
            .collect()
    }

    /// Appends one record per index, cycling through every kind; returns the counts added.
    async fn append_cycle(log: &ActivityLog, range: std::ops::Range<usize>) -> [u64; 8] {
        let mut added = [0u64; 8];
        for index in range {
            let kind = index % KINDS.len();
            log.append(record(KINDS[kind], format!("c{index}")))
                .await
                .unwrap();
            added[kind] += 1;
        }
        added
    }

    /// What a crash between the rename and the new file would leave: the live file
    /// shifted to `.1` and nothing at the live path.
    fn shift_without_replacement(path: &Path) {
        let _ = std::fs::remove_file(ledger::rotated_path(path, ledger::ROTATED_FILES_KEPT));
        for index in (1..ledger::ROTATED_FILES_KEPT).rev() {
            let from = ledger::rotated_path(path, index);
            if from.exists() {
                std::fs::rename(from, ledger::rotated_path(path, index + 1)).unwrap();
            }
        }
        std::fs::rename(path, ledger::rotated_path(path, 1)).unwrap();
    }

    #[actix_web::test]
    async fn torn_final_activity_line_is_skipped_at_startup() {
        let dir = ScratchDir::new("activity-torn");
        let path = dir.join("activity.jsonl");
        let mut content = line("challenge_issued", "c1") + &line("lease_issued", "c1");
        content.push_str("{\"occurred_at\":\"2026-10-14T10:00:01Z\",\"event\":\"proof_acc");
        std::fs::write(&path, content).unwrap();

        let (log, analytics) =
            ActivityLog::load(&path).expect("a torn final line must not stop startup");
        assert_eq!(log.skipped_lines, 1);
        assert_eq!(counts(&analytics), [1, 1, 0, 0, 0, 0, 0, 0]);

        log.append(record(ActivityKind::ProofAccepted, "c1".to_string()))
            .await
            .unwrap();
        drop(log);
        let (reloaded, analytics) = ActivityLog::load(&path).unwrap();
        assert_eq!(
            reloaded.skipped_lines, 1,
            "the torn fragment stays isolated"
        );
        assert_eq!(counts(&analytics), [1, 1, 1, 0, 0, 0, 0, 0]);
        assert_eq!(recent_ids(&reloaded.recent()), ["c1", "c1", "c1"]);
    }

    #[actix_web::test]
    async fn garbage_middle_activity_line_is_skipped() {
        let dir = ScratchDir::new("activity-garbage");
        let path = dir.join("activity.jsonl");
        let mut content = line("challenge_issued", "c1").into_bytes();
        content
            .extend_from_slice(b"\x00\xffnot an activity record\n{\"event\":\"lease_issued\"}\n");
        content.extend_from_slice(line("challenge_issued", "c2").as_bytes());
        std::fs::write(&path, content).unwrap();

        let (log, analytics) =
            ActivityLog::load(&path).expect("a malformed line must not stop startup");
        assert_eq!(log.skipped_lines, 2);
        assert_eq!(counts(&analytics), [2, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(recent_ids(&log.recent()), ["c1", "c2"]);
    }

    #[actix_web::test]
    async fn lifetime_totals_survive_rotation() {
        let dir = ScratchDir::new("activity-rotation");
        let path = dir.join("activity.jsonl");
        let cap = 1024;
        let (log, _) = ActivityLog::load_with_max_bytes(&path, cap).unwrap();
        let mut expected = append_cycle(&log, 0..203).await;
        drop(log);

        assert!(
            ledger::rotated_path(&path, ledger::ROTATED_FILES_KEPT).exists(),
            "203 records at a 1 KiB cap must rotate past the retained count"
        );
        assert!(!ledger::rotated_path(&path, ledger::ROTATED_FILES_KEPT + 1).exists());
        for file in ledger::retained_paths(&path) {
            assert!(
                std::fs::metadata(&file).unwrap().len() <= cap,
                "{}",
                file.display()
            );
        }

        let (reloaded, analytics) = ActivityLog::load_with_max_bytes(&path, cap).unwrap();
        assert_eq!(reloaded.skipped_lines, 0);
        assert_eq!(
            counts(&analytics),
            expected,
            "totals must include rotated-out files"
        );
        let recent = recent_ids(&reloaded.recent());
        assert_eq!(recent.last().map(String::as_str), Some("c202"));
        let first = 203 - recent.len();
        assert_eq!(
            recent,
            (first..203)
                .map(|index| format!("c{index}"))
                .collect::<Vec<_>>(),
            "recent activity is the newest records, oldest first"
        );

        let more = append_cycle(&reloaded, 203..260).await;
        drop(reloaded);
        for (total, added) in expected.iter_mut().zip(more) {
            *total += added;
        }
        let (_, analytics) = ActivityLog::load_with_max_bytes(&path, cap).unwrap();
        assert_eq!(
            counts(&analytics),
            expected,
            "a restarted log keeps checkpointing"
        );
    }

    #[actix_web::test]
    async fn totals_survive_a_crash_part_way_through_rotation() {
        let dir = ScratchDir::new("activity-crash");
        let path = dir.join("activity.jsonl");
        let cap = 1024;
        let (log, _) = ActivityLog::load_with_max_bytes(&path, cap).unwrap();
        let expected = append_cycle(&log, 0..50).await;
        drop(log);

        shift_without_replacement(&path);
        let (log, analytics) = ActivityLog::load_with_max_bytes(&path, cap)
            .expect("a missing live file after a rename must not stop startup");
        drop(log);
        assert_eq!(
            counts(&analytics),
            expected,
            "live file renamed, replacement not written"
        );

        shift_without_replacement(&path);
        std::fs::write(&path, b"{\"checkpoint\":{\"rotated_at\":\"2026-10-").unwrap();
        let (log, analytics) = ActivityLog::load_with_max_bytes(&path, cap).unwrap();
        assert_eq!(log.skipped_lines, 1);
        assert_eq!(
            counts(&analytics),
            expected,
            "torn checkpoint at the top of the new file"
        );
    }

    #[actix_web::test]
    async fn records_waiting_together_share_one_sync() {
        let dir = ScratchDir::new("activity-group");
        let path = dir.join("activity.jsonl");
        let (log, _, gate) = ActivityLog::load_gated(&path, ledger::DEFAULT_MAX_BYTES).unwrap();
        let answers: Vec<_> = (0..20)
            .map(|index| {
                log.submit(record(KINDS[index % KINDS.len()], format!("c{index}")))
                    .unwrap()
            })
            .collect();
        assert!(log.recent().is_empty(), "nothing is committed while held");

        gate.release_one();
        for answer in answers {
            assert_eq!(
                answer.await.unwrap().unwrap(),
                20,
                "all 20 waiting records are committed under one sync"
            );
        }
        let expected: Vec<String> = (0..20).map(|index| format!("c{index}")).collect();
        assert_eq!(recent_ids(&log.recent()), expected, "in queue order");

        gate.release_one();
        assert_eq!(
            log.append(record(ActivityKind::ChallengeIssued, "c20".to_string()))
                .await
                .unwrap(),
            1,
            "a record on its own is committed on its own"
        );
        drop(gate);
        drop(log);
        let (reloaded, analytics) = ActivityLog::load(&path).unwrap();
        assert_eq!(reloaded.skipped_lines, 0);
        assert_eq!(counts(&analytics), [4, 3, 3, 3, 2, 2, 2, 2]);
    }

    #[actix_web::test]
    async fn a_group_holds_at_most_1024_records() {
        let dir = ScratchDir::new("activity-group-cap");
        let path = dir.join("activity.jsonl");
        let (log, _, gate) = ActivityLog::load_gated(&path, ledger::DEFAULT_MAX_BYTES).unwrap();
        let answers: Vec<_> = (0..1030)
            .map(|index| {
                log.submit(record(ActivityKind::ChallengeIssued, format!("c{index}")))
                    .unwrap()
            })
            .collect();
        gate.release_one();
        gate.release_one();
        let mut sizes = Vec::new();
        for answer in answers {
            sizes.push(answer.await.unwrap().unwrap());
        }
        assert_eq!(sizes[0], MAX_GROUP);
        assert_eq!(sizes[MAX_GROUP - 1], MAX_GROUP);
        assert_eq!(sizes[MAX_GROUP], 1030 - MAX_GROUP);
    }

    #[actix_web::test]
    async fn recent_activity_keeps_the_newest_hundred_records() {
        let dir = ScratchDir::new("activity-recent");
        let path = dir.join("activity.jsonl");
        let (log, _) = ActivityLog::load(&path).unwrap();
        append_cycle(&log, 0..150).await;
        let recent = recent_ids(&log.recent());
        assert_eq!(recent.len(), RECENT_ACTIVITY_LIMIT);
        assert_eq!(recent.first().map(String::as_str), Some("c50"));
        assert_eq!(recent.last().map(String::as_str), Some("c149"));
    }

    #[actix_web::test]
    async fn every_waiting_record_is_written_before_the_dropped_log_returns() {
        let dir = ScratchDir::new("activity-drop");
        let path = dir.join("activity.jsonl");
        let (log, _, gate) = ActivityLog::load_gated(&path, ledger::DEFAULT_MAX_BYTES).unwrap();
        let answers: Vec<_> = (0..50)
            .map(|index| {
                log.submit(record(ActivityKind::LeaseIssued, format!("c{index}")))
                    .unwrap()
            })
            .collect();
        // The writer stays held for a moment after the drop begins.
        let release = thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(200));
            drop(gate);
        });
        drop(log);
        let (reloaded, analytics) = ActivityLog::load(&path).unwrap();
        assert_eq!(
            counts(&analytics),
            [0, 50, 0, 0, 0, 0, 0, 0],
            "dropping the log waits for the writer"
        );
        assert_eq!(reloaded.recent().len(), 50);
        release.join().unwrap();
        for answer in answers {
            assert!(answer.await.unwrap().is_ok());
        }
    }

    #[actix_web::test]
    async fn replay_keeps_the_newest_hundred_records_of_a_file() {
        let dir = ScratchDir::new("activity-replay-recent");
        let path = dir.join("activity.jsonl");
        let content: String = (0..150)
            .map(|index| line("lease_issued", &format!("c{index}")))
            .collect();
        std::fs::write(&path, content).unwrap();
        let (log, analytics) = ActivityLog::load(&path).unwrap();
        assert_eq!(counts(&analytics), [0, 150, 0, 0, 0, 0, 0, 0]);
        let recent = recent_ids(&log.recent());
        assert_eq!(recent.len(), RECENT_ACTIVITY_LIMIT);
        assert_eq!(recent.first().map(String::as_str), Some("c50"));
    }

    #[actix_web::test]
    async fn a_checkpoint_counts_only_as_the_first_line_of_a_file() {
        let dir = ScratchDir::new("activity-checkpoint-place");
        let checkpoint = |issued: u64| {
            format!(
                "{{\"checkpoint\":{{\"rotated_at\":\"2026-10-14T10:00:00Z\",\
                 \"totals\":{{\"challenges_issued\":{issued}}}}}}}\n"
            )
        };

        let after_a_record = dir.join("after-record.jsonl");
        std::fs::write(&after_a_record, line("lease_issued", "c1") + &checkpoint(7)).unwrap();
        let (log, analytics) = ActivityLog::load(&after_a_record).unwrap();
        assert_eq!(
            log.skipped_lines, 1,
            "a checkpoint after a record is malformed"
        );
        assert_eq!(counts(&analytics), [0, 1, 0, 0, 0, 0, 0, 0]);

        let twice = dir.join("twice.jsonl");
        std::fs::write(&twice, checkpoint(7) + &checkpoint(9)).unwrap();
        let (log, analytics) = ActivityLog::load(&twice).unwrap();
        assert_eq!(log.skipped_lines, 1, "only the first checkpoint counts");
        assert_eq!(counts(&analytics), [7, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[actix_web::test]
    async fn startup_reads_older_files_until_totals_and_recent_are_complete() {
        let dir = ScratchDir::new("activity-older-files");

        // Totals end at the live file's checkpoint; recent activity still
        // reaches into the older file.
        let path = dir.join("checkpointed.jsonl");
        let older: String = (0..20)
            .map(|index| line("challenge_issued", &format!("o{index}")))
            .collect();
        std::fs::write(ledger::rotated_path(&path, 1), older).unwrap();
        let live = "{\"checkpoint\":{\"rotated_at\":\"2026-10-14T10:00:00Z\",\
                    \"totals\":{\"challenges_issued\":20}}}\n"
            .to_string()
            + &(0..5)
                .map(|index| line("lease_issued", &format!("l{index}")))
                .collect::<String>();
        std::fs::write(&path, live).unwrap();
        let (log, analytics) = ActivityLog::load(&path).unwrap();
        assert_eq!(counts(&analytics), [20, 5, 0, 0, 0, 0, 0, 0]);
        let recent = recent_ids(&log.recent());
        assert_eq!(recent.len(), 25, "{recent:?}");
        assert_eq!(recent.first().map(String::as_str), Some("o0"));
        assert_eq!(recent.last().map(String::as_str), Some("l4"));

        // A full recent list does not stop the count before a checkpoint.
        let path = dir.join("uncheckpointed.jsonl");
        let older: String = (0..10)
            .map(|index| line("challenge_issued", &format!("o{index}")))
            .collect();
        std::fs::write(ledger::rotated_path(&path, 1), older).unwrap();
        let live: String = (0..150)
            .map(|index| line("lease_issued", &format!("l{index}")))
            .collect();
        std::fs::write(&path, live).unwrap();
        let (log, analytics) = ActivityLog::load(&path).unwrap();
        assert_eq!(counts(&analytics), [10, 150, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            recent_ids(&log.recent()).first().map(String::as_str),
            Some("l50")
        );
    }
}
