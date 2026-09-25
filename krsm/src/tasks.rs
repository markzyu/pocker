// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
use crate::{AsyncRuntime, AsyncRuntimeError, FixedSizedMap};

/// This is a helper struct for managing tasks offloaded from AsyncRuntime to a
/// worker thread. It should not be called from within async.
///
/// This is helpful, for example, if you use a second core/thread that runs
/// synchronous I/O in batches, such that I/O is nonblocking.
///
/// This struct is `Send` and not `Sync`. To use it, you should:
///
/// 1. Create a `TaskTracker` on the async thread
/// 2. Call `TaskTracker::sync` to keep the tracker and `AsyncRuntime` in sync.
/// 3. Call `TaskTracker::register_if` to track relevant YieldReason from async.
/// 4. Pass `TaskTracker` to a worker thread, which runs `TaskTracker::work`
/// 6. Upon thread completion, pass `TaskTracker` back, so that `TaskTracker::sync` can unblock completed futures.
#[derive(Debug)]
pub struct TaskTracker<
    YieldReason: Copy + Eq + Ord,
    YieldResponse: PartialEq,
    const MAX_PENDING: usize = 1024,
> {
    tasks: FixedSizedMap<YieldReason, Option<YieldResponse>, MAX_PENDING>,
}

impl<YieldReason: Copy + Eq + Ord, YieldResponse: PartialEq, const MAX_PENDING: usize>
    TaskTracker<YieldReason, YieldResponse, MAX_PENDING>
{
    pub fn new() -> Self {
        Self {
            tasks: FixedSizedMap::new(),
        }
    }

    /// Returns true if both runtime and tracker are ready for new tasks to `register()`
    pub fn sync(
        &self,
        runtime: &AsyncRuntime<YieldReason, YieldResponse, MAX_PENDING>,
    ) -> Result<bool, AsyncRuntimeError> {
        self.tasks.sync_keys(&runtime.pending_futures);
        let completed_reason = runtime.check_pending_reasons(|x| {
            if let Some(x) = x {
                self.is_task_complete(&x)
            } else {
                false
            }
        })?;
        if let Some(reason) = completed_reason {
            // We have just unblocked a future, and must run_async_step
            let response = self.remove_completed(&reason).unwrap();
            runtime.unblock_futures(reason, response)?;
            return Ok(false);
        }

        if self.len() > 0 {
            // We can't register new tasks until we unblock the completed ones, one by one
            return Ok(false);
        }
        Ok(true)
    }

    fn is_task_complete(&self, reason: &YieldReason) -> bool {
        self.tasks.read(reason, |x| x.is_some()) == Some(true)
    }

    fn remove_completed(&self, reason: &YieldReason) -> Option<YieldResponse> {
        self.tasks.remove(reason).flatten()
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Register a new pending task
    pub fn register(&self, reason: YieldReason) -> Result<(), AsyncRuntimeError> {
        self.tasks.set_default(reason, None)?;
        Ok(())
    }

    /// Register many new pending tasks, only if match_fn returns true. This function does not short circuit.
    pub fn register_if(
        &self,
        runtime: &AsyncRuntime<YieldReason, YieldResponse, MAX_PENDING>,
        match_fn: impl Fn(&YieldReason) -> bool,
    ) -> Result<(), AsyncRuntimeError> {
        let mut err: Option<AsyncRuntimeError> = None;
        runtime.check_pending_reasons(|reason| {
            let Some(reason) = reason else {
                return false;
            };
            if match_fn(&reason) {
                if let Err(e) = self.register(reason) {
                    err.replace(e);
                }
            }
            false
        })?;
        if let Some(e) = err {
            return Err(e.into());
        }
        Ok(())
    }

    /// Run worker_fn, per pending task
    pub fn work<E>(
        &self,
        worker_fn: impl Fn(YieldReason) -> Result<YieldResponse, E>,
    ) -> Result<(), E> {
        let mut err: Option<E> = None;
        self.tasks.map_edit(|item| {
            match worker_fn(item.0) {
                Ok(response) => {
                    item.1 = Some(response);
                }
                Err(e) => {
                    err.replace(e);
                }
            }
            false
        });
        if let Some(e) = err {
            return Err(e);
        }
        Ok(())
    }
}
