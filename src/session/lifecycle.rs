//! Cloneable per-connection drain state and active-work observation.
//!
//! The lifecycle is protocol-owned: it exposes no Quinn or oinq types. Every
//! clone, incoming owner, accepted stream runner, and outgoing exchange owner
//! belonging to one connection shares the same instance. The application owns
//! task cancellation and the deadline at which it aborts leftover tasks; the
//! lifecycle only records drain state and the number of admitted exchanges.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::Notify;

use super::SessionError;

/// A cloneable drain state shared by every owner of one connection.
///
/// Call [`Self::drain`] to stop incoming acceptance and refuse new outgoing
/// exchanges. Work admitted with [`Self::try_admit`] before that ordering point
/// keeps the lifecycle active until its [`SessionActivity`] guard drops.
/// [`Self::wait_idle`] observes that count returning to zero; it does not stop
/// tasks and applies no deadline, so the application must drain first and abort
/// leftover tasks itself.
#[derive(Clone, Debug)]
pub struct SessionLifecycle {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    draining: AtomicUsize,
    closed: AtomicUsize,
    active: AtomicUsize,
    changed: Notify,
}

impl Default for SessionLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionLifecycle {
    /// Creates an open lifecycle with no admitted work.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                draining: AtomicUsize::new(0),
                closed: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                changed: Notify::new(),
            }),
        }
    }

    /// Starts draining. Repeated calls are idempotent and wake every waiter.
    ///
    /// After this call new incoming streams are no longer returned by a drained
    /// accept, and [`Self::try_admit`] fails with [`SessionError::Draining`].
    pub fn drain(&self) {
        if self.inner.draining.swap(1, Ordering::SeqCst) == 0 {
            self.inner.changed.notify_waiters();
        }
    }

    /// Returns whether draining has started.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.inner.draining.load(Ordering::SeqCst) != 0
    }

    /// Returns whether a local close or abort has marked the lifecycle closed.
    ///
    /// Closing implicitly drains first, so [`Self::is_draining`] is also true.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst) != 0
    }

    /// Marks the lifecycle closed. Closing implies draining.
    ///
    /// This does not close the transport; a control handle or session owner does
    /// that. It makes later admissions fail and wakes drain and idle waiters.
    pub fn mark_closed(&self) {
        self.inner.closed.store(1, Ordering::SeqCst);
        self.drain();
        self.inner.changed.notify_waiters();
    }

    /// Returns the number of admitted exchanges that have not completed.
    #[must_use]
    pub fn active_work(&self) -> usize {
        self.inner.active.load(Ordering::SeqCst)
    }

    /// Registers one exchange as active unless draining or closed.
    ///
    /// The ordering point is a single atomic swap: an admission that wins the
    /// race with [`Self::drain`] is counted before the drain is visible to
    /// waiters, while an admission that loses cannot be handed to a caller.
    ///
    /// # Errors
    /// Returns [`SessionError::Draining`] with `OutcomeCertainty::NotSent` once
    /// draining or closure has started.
    pub fn try_admit(&self) -> Result<SessionActivity, SessionError> {
        // A closed connection keeps its historical transport error instead of
        // the drain refusal, because its close already stopped the transport.
        if self.is_draining() && !self.is_closed() {
            return Err(SessionError::Draining);
        }
        self.inner.active.fetch_add(1, Ordering::SeqCst);
        // Re-check after the increment so a drain that ran concurrently either
        // observed this work or this admission observes the drain.
        if self.is_draining() && !self.is_closed() {
            self.release();
            return Err(SessionError::Draining);
        }
        Ok(SessionActivity {
            lifecycle: self.clone(),
        })
    }

    /// Waits until draining starts. Cancelling the wait leaves the state alone.
    pub async fn wait_drained(&self) {
        loop {
            let notified = self.inner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_draining() {
                return;
            }
            notified.await;
        }
    }

    /// Waits until no admitted exchange remains active.
    ///
    /// If new exchanges can still be admitted this may never resolve; drain
    /// first. Cancelling the wait does not stop or abort any work.
    pub async fn wait_idle(&self) {
        loop {
            let notified = self.inner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.active_work() == 0 {
                return;
            }
            notified.await;
        }
    }

    fn release(&self) {
        if self.inner.active.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.inner.changed.notify_waiters();
        }
    }
}

/// A guard representing one admitted exchange.
///
/// Dropping it releases the active-work count. It is created only by
/// [`SessionLifecycle::try_admit`], and the protocol stores it in accepted
/// stream owners and owned outgoing exchanges so the count follows their
/// lifetime without a detached task.
#[derive(Debug)]
pub struct SessionActivity {
    lifecycle: SessionLifecycle,
}

impl SessionActivity {
    /// Returns the lifecycle whose count this guard holds.
    #[must_use]
    pub fn lifecycle(&self) -> &SessionLifecycle {
        &self.lifecycle
    }
}

impl Drop for SessionActivity {
    fn drop(&mut self) {
        self.lifecycle.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admission_and_drain_have_one_ordering_point() {
        let lifecycle = SessionLifecycle::new();
        let activity = lifecycle.try_admit().unwrap();
        assert_eq!(lifecycle.active_work(), 1);
        lifecycle.drain();
        assert!(lifecycle.is_draining());
        assert!(matches!(lifecycle.try_admit(), Err(SessionError::Draining)));
        let idle = lifecycle.wait_idle();
        tokio::pin!(idle);
        assert!(futures_pending(idle.as_mut()).await);
        drop(activity);
        idle.await;
        assert_eq!(lifecycle.active_work(), 0);
    }

    async fn futures_pending(
        future: std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
    ) -> bool {
        tokio::select! {
            () = future => false,
            () = tokio::task::yield_now() => true,
        }
    }

    #[tokio::test]
    async fn repeated_drain_release_and_close_are_idempotent() {
        let lifecycle = SessionLifecycle::new();
        lifecycle.drain();
        lifecycle.drain();
        assert!(matches!(lifecycle.try_admit(), Err(SessionError::Draining)));
        lifecycle.mark_closed();
        lifecycle.mark_closed();
        assert!(lifecycle.is_closed());
        assert!(lifecycle.is_draining());
        lifecycle.wait_drained().await;
        lifecycle.wait_idle().await;
    }
}
