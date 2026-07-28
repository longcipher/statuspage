use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

use super::trait_def::{EmailResult, EmailSender, MessageId, TransactionalEmail};

/// In-memory email sender used by tests. Stores every accepted email in a
/// `parking_lot::Mutex<Vec<_>>` behind an `Arc` so clones share the queue.
///
/// `parking_lot::Mutex` is used (not `std::sync::Mutex`) per AGENTS.md: the
/// guard is not `Result`-returning (no poisoning) and the lock is never held
/// across an `.await` — `send` pushes synchronously and returns.
#[derive(Default, Clone, Debug)]
pub struct InMemoryEmailSender {
    inner: Arc<Mutex<Vec<TransactionalEmail>>>,
}

impl InMemoryEmailSender {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of every email send() has accepted. Cheap clone of the inner
    /// vector; tests typically read once at assertion time.
    pub fn sent(&self) -> Vec<TransactionalEmail> {
        self.lock().clone()
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.lock().clear();
    }

    /// Lock the inner mutex. `parking_lot::Mutex::lock` blocks until acquired
    /// and returns a guard directly (no poisoning, no `Result`).
    fn lock(&self) -> parking_lot::MutexGuard<'_, Vec<TransactionalEmail>> {
        self.inner.lock()
    }
}

#[async_trait]
impl EmailSender for InMemoryEmailSender {
    async fn send(&self, email: TransactionalEmail) -> EmailResult<MessageId> {
        // Lock is acquired and dropped within this synchronous block — never
        // held across the function's (empty) await points.
        let mut guard = self.lock();
        let id = MessageId(format!("memory-{}", guard.len()));
        guard.push(email);
        drop(guard);
        Ok(id)
    }
}
