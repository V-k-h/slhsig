//! A bounded signing service: the server pattern this crate recommends.
//!
//! - Signing runs on a fixed pool of worker threads, never on request-handling or async threads.
//!   It is CPU-bound and, for the "s" parameter sets, slow.
//! - A bounded queue caps the work in flight. When it is full, new requests are refused at once
//!   (backpressure) instead of piling up behind slow signatures.
//! - Messages over a size limit are refused before any cryptographic work.
//! - Outcomes are counted. `Error::SelfCheckFailed` gets its own counter and an alert, because
//!   it means the host produced a faulty signature (see `FaultCheck`).
//!
//! Run with `cargo run --release --example signing_service`. The equivalent with tokio is
//! sketched at the end of this file.

use slhsig::{Context, Error, Sha2_128f, Signature, SigningKey, VerifyingKey};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

type Set = Sha2_128f;

/// Pinned by the protocol, never chosen by the request.
const CONTEXT: Context<'static> = match Context::new(b"example-signing-service v1") {
    Ok(ctx) => ctx,
    Err(_) => panic!("context longer than 255 bytes"),
};
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Size the pool to the cores reserved for signing.
const WORKERS: usize = 2;
/// Requests allowed to wait for a worker; beyond this the service answers `Busy`.
const QUEUE_DEPTH: usize = 4;

type Reply = mpsc::Receiver<Result<Signature<Set>, Error>>;

#[derive(Debug, PartialEq, Eq)]
enum Refused {
    Busy,
    TooLarge,
}

#[derive(Default)]
struct Metrics {
    signed: AtomicU64,
    refused_busy: AtomicU64,
    refused_too_large: AtomicU64,
    self_check_failed: AtomicU64,
    other_errors: AtomicU64,
}

struct Job {
    msg: Vec<u8>,
    reply: mpsc::Sender<Result<Signature<Set>, Error>>,
}

struct SigningService {
    queue: mpsc::SyncSender<Job>,
    metrics: Arc<Metrics>,
    verifying_key: VerifyingKey<Set>,
    workers: Vec<JoinHandle<()>>,
}

impl SigningService {
    fn start(key: SigningKey<Set>) -> Self {
        let verifying_key = key.verifying_key();
        let key = Arc::new(key);
        let metrics = Arc::new(Metrics::default());
        let (queue, jobs) = mpsc::sync_channel::<Job>(QUEUE_DEPTH);
        let jobs = Arc::new(Mutex::new(jobs));

        let workers = (0..WORKERS)
            .map(|_| {
                let (key, jobs, metrics) = (Arc::clone(&key), Arc::clone(&jobs), Arc::clone(&metrics));
                thread::spawn(move || loop {
                    // The lock is held only while taking a job, not while signing.
                    let job = match jobs.lock().expect("queue lock").recv() {
                        Ok(job) => job,
                        Err(_) => return, // service dropped: shut down
                    };
                    let result = key.sign(&job.msg, CONTEXT);
                    match &result {
                        Ok(_) => metrics.signed.fetch_add(1, Ordering::Relaxed),
                        Err(Error::SelfCheckFailed) => {
                            eprintln!("ALERT: signature failed the fault check; check this host's hardware");
                            metrics.self_check_failed.fetch_add(1, Ordering::Relaxed)
                        }
                        Err(_) => metrics.other_errors.fetch_add(1, Ordering::Relaxed),
                    };
                    let _ = job.reply.send(result); // the requester may have given up
                })
            })
            .collect();

        Self { queue, metrics, verifying_key, workers }
    }

    /// Queues a message for signing, or refuses it immediately.
    fn submit(&self, msg: Vec<u8>) -> Result<Reply, Refused> {
        if msg.len() > MAX_MESSAGE_BYTES {
            self.metrics.refused_too_large.fetch_add(1, Ordering::Relaxed);
            return Err(Refused::TooLarge);
        }
        let (reply, receiver) = mpsc::channel();
        match self.queue.try_send(Job { msg, reply }) {
            Ok(()) => Ok(receiver),
            Err(TrySendError::Full(_)) => {
                self.metrics.refused_busy.fetch_add(1, Ordering::Relaxed);
                Err(Refused::Busy)
            }
            Err(TrySendError::Disconnected(_)) => unreachable!("workers outlive the service"),
        }
    }

    fn shutdown(self) -> Arc<Metrics> {
        drop(self.queue); // workers finish queued jobs, then see the closed channel
        for worker in self.workers {
            worker.join().expect("worker panicked");
        }
        self.metrics
    }
}

fn main() {
    let service = SigningService::start(SigningKey::<Set>::generate().expect("OS entropy"));
    let verifying_key = service.verifying_key.clone();

    // A burst of 12 requests against 2 workers and 4 queue slots: some are refused as Busy.
    let mut pending = Vec::new();
    for i in 0..12u32 {
        let msg = format!("request {i}").into_bytes();
        match service.submit(msg.clone()) {
            Ok(reply) => pending.push((msg, reply)),
            Err(refused) => println!("request {i}: refused ({refused:?})"),
        }
    }
    assert_eq!(service.submit(vec![0; MAX_MESSAGE_BYTES + 1]).err(), Some(Refused::TooLarge));

    for (msg, reply) in pending {
        let sig = reply.recv().expect("worker reply").expect("signing succeeds");
        verifying_key.verify(&msg, CONTEXT, &sig).expect("signature verifies");
    }

    let m = service.shutdown();
    println!(
        "signed {} | refused busy {} | refused too large {} | self-check failures {} | other errors {}",
        m.signed.load(Ordering::Relaxed),
        m.refused_busy.load(Ordering::Relaxed),
        m.refused_too_large.load(Ordering::Relaxed),
        m.self_check_failed.load(Ordering::Relaxed),
        m.other_errors.load(Ordering::Relaxed),
    );
}

// The same shape in a tokio service (not compiled here):
//
//     let permits = Arc::new(tokio::sync::Semaphore::new(WORKERS + QUEUE_DEPTH));
//     let permit = permits.clone().try_acquire_owned().map_err(|_| Refused::Busy)?;
//     let key = Arc::clone(&key);
//     let sig = tokio::task::spawn_blocking(move || {
//         let _permit = permit; // released when signing finishes
//         key.sign(&msg, CONTEXT)
//     })
//     .await??;
