// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
use crate::{AsyncRuntime, AsyncRuntimeError, FixedSizedMap};

/// This is a helper struct for tracking tasks that you manually offload from
/// AsyncRuntime to a worker thread. It should not be called from within async.
///
/// This is helpful, for example, if you use a second OS thread that runs your
/// synchronous network I/O, so that the I/O becomes nonblocking.
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

/// This might help you write the worker function for `TaskTracker::work_in_batches()`
pub type TaskBatch<YieldReason, YieldResponse> = [Option<(YieldReason, Option<YieldResponse>)>];

impl<YieldReason: Copy + Eq + Ord, YieldResponse: PartialEq, const MAX_PENDING: usize>
    TaskTracker<YieldReason, YieldResponse, MAX_PENDING>
{
    pub fn new() -> Self {
        Self {
            tasks: FixedSizedMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.len() == 0
    }

    /// Returns true if both runtime and tracker are ready for new tasks to `register()`
    ///
    /// Returns false if any of the following is true:
    ///
    /// * We have just informed [AsyncRuntime] of a newly completed task, and need to `run_async_step()`
    /// * We have incomplete tasks and should wait for them to complete
    pub fn sync(
        &self,
        runtime: &AsyncRuntime<YieldReason, YieldResponse, MAX_PENDING>,
    ) -> Result<bool, AsyncRuntimeError> {
        self.tasks.inner_join_keys(&runtime.pending_futures);
        let completed_reason = runtime.check_pending_reasons(|x| self.is_task_complete(&x));
        if let Some(reason) = completed_reason {
            // We have just unblocked a future, and must run_async_step
            let response = self.remove_completed(&reason).unwrap();
            runtime.unblock_futures(reason, response);
            return Ok(false);
        }

        if !self.is_empty() {
            // We can't register new tasks until we complete all existing tasks, one by one
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

    /// Register a new pending task.
    pub fn register(&self, reason: YieldReason) -> Result<(), AsyncRuntimeError> {
        self.tasks.set_default(reason, None)?;
        Ok(())
    }

    /// Register many new pending tasks, by looking through `runtime.check_pending_reasons()`,
    /// and selecting the reasons for which `match_fn` returns true. This function does not short circuit.
    pub fn register_if(
        &self,
        runtime: &AsyncRuntime<YieldReason, YieldResponse, MAX_PENDING>,
        match_fn: impl Fn(&YieldReason) -> bool,
    ) -> Result<(), AsyncRuntimeError> {
        let mut err: Option<AsyncRuntimeError> = None;
        runtime.check_pending_reasons(|reason| {
            if match_fn(&reason) {
                if let Err(e) = self.register(reason) {
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

    /// Run `worker_fn`, once per pending task.
    ///
    /// You should call this from the worker thread.
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

    /// Run `worker_fn`, once per batch of tasks
    ///
    /// You should call this from the worker thread.
    pub fn work_in_batches<E>(
        &self,
        batch_size: usize,
        worker_fn: impl Fn(&mut TaskBatch<YieldReason, YieldResponse>) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut err: Option<E> = None;
        self.tasks.map_edit_batches(batch_size, |batch| {
            if let Err(e) = worker_fn(batch) {
                err.replace(e);
            }
            false
        });
        if let Some(e) = err {
            return Err(e);
        }
        Ok(())
    }
}

impl<YieldReason: Copy + Eq + Ord, YieldResponse: PartialEq, const MAX_PENDING: usize> Default
    for TaskTracker<YieldReason, YieldResponse, MAX_PENDING>
{
    fn default() -> Self {
        Self::new()
    }
}
