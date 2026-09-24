// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
use crate::{AsyncRuntimeError, FixedSizedMap};

/// This is a helper struct that tracks any YieldReason that is currently
/// running on the "synchronous" side of your code. It should not be used
/// from within async.
///
/// This is helpful, for example, if you use a second core/thread that runs
/// synchronous I/O in batches, such that I/O is nonblocking.
///
/// This struct is `Send` and not `Sync`. You should create a `TaskTracker`
/// on the async thread, call `register` to track as many pending tasks as
/// you would like, then pass it to a worker thread, and upon worker thread
/// completion, pass it back, for async thread to unblock tracked futures
#[derive(Debug)]
#[allow(dead_code)]
pub struct TaskTracker<
    YieldReason: Copy + Eq + Ord,
    YieldResponse: PartialEq,
    const MAX_PENDING: usize = 1024,
> {
    tasks: FixedSizedMap<YieldReason, Option<YieldResponse>, MAX_PENDING>,
}

#[allow(dead_code)]
impl<YieldReason: Copy + Eq + Ord, YieldResponse: PartialEq, const MAX_PENDING: usize>
    TaskTracker<YieldReason, YieldResponse, MAX_PENDING>
{
    pub fn new() -> Self {
        Self {
            tasks: FixedSizedMap::new(),
        }
    }

    pub fn is_task_complete(&self, reason: &YieldReason) -> bool {
        self.tasks.read(reason, |x| x.is_some()) == Some(true)
    }

    pub fn remove_completed(&self, reason: &YieldReason) -> Option<YieldResponse> {
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
