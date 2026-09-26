// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
use crate::common::{AsyncRuntimeError, FixedSizedMap};
use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

/// The KRSM async runtime
///
/// Type Parameters:
///
/// * YieldReason: This must be a fieldless enum that derivces Copy, Eq, PartialEq, Ord, PartialOrd
/// * YieldResponse: This can be any Rust struct that derives PartialEq
///
/// This runtime does not support tokio, async I/O, or external async utilities.
///
/// It only supports parts of futures_lite, these three helper functions:
///
/// > `zip()`, `or()`, `poll_fn()`.
///
/// It especially does not support any invocation of the Waker. If you await on
/// an external async function which tries to access the Waker, the runtime
/// **will panic**.
///
/// The use of `async` is purely to avoid writing a state machine switch-case.
#[derive(Debug)]
pub struct AsyncRuntime<
    YieldReason: Copy + Eq + Ord,
    YieldResponse: PartialEq,
    const MAX_PENDING: usize = 1024,
> {
    has_unblock: RefCell<Option<(YieldReason, YieldResponse)>>,
    has_new_future: AtomicBool,
    pub(crate) pending_futures: FixedSizedMap<YieldReason, usize, MAX_PENDING>,
}

/// AsyncYield is a helper for KRSM async loops.
///
/// This is useful when your async future contains two or more competing loops:
///      `futures_lite::or(loop1, loop2).await`
///
/// Futures lite's parallel `or()` function always runs the loops in the same order.
/// Yet if both `loop1` and `loop2` are waiting on the same YieldReason, then, `loop2`
/// will never get a chance to run.
///
/// In that case, loop1 can use AsyncYielder to yield until the other loops get a chance
/// to run. But those other loops must also remember to `unblock()` us.
#[derive(Default)]
pub struct AsyncYielder {
    // When A yeilds to B, count the number of times B has been polled
    num_polls: RefCell<usize>,
}

/// This internal struct helps untrack any futures dropped from the async runtime
struct FutureDropGuard<
    'a,
    YieldReason: Copy + Eq + Ord,
    YieldResponse: PartialEq,
    const MAX_PENDING: usize,
> {
    future_type: YieldReason,
    runtime: &'a AsyncRuntime<YieldReason, YieldResponse, MAX_PENDING>,
}

type Result<T> = core::result::Result<T, AsyncRuntimeError>;

const RAW_WAKER_SHOULD_NOT_BE_CALLED: &'static str =
    "Internal error, KRSM Async Runtime detected invalid usage of external async library";

/// This RawWaker is similar to core::task::RawWaker::NOOP, but with an assertion:
/// It panicks whenever any async code calls the waker at all.
const RAW_WAKER_WITH_ASSERTIONS: RawWaker = {
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        // clone
        |_| RAW_WAKER_WITH_ASSERTIONS,
        // wake
        |_| {
            panic!("{}", RAW_WAKER_SHOULD_NOT_BE_CALLED);
        },
        // wake_by_ref
        |_| {
            panic!("{}", RAW_WAKER_SHOULD_NOT_BE_CALLED);
        },
        // drop does nothing
        |_| {},
    );
    RawWaker::new(core::ptr::null(), &VTABLE)
};

impl<YieldReason: Copy + Eq + Ord, YieldResponse: PartialEq, const MAX_PENDING: usize>
    AsyncRuntime<YieldReason, YieldResponse, MAX_PENDING>
{
    /// Create a new instance of pending future.
    ///
    /// Your async code should have access to this method. This is the **primary method**
    /// through which your async code yields back during an async step.
    pub async fn new_pending_future<'a>(
        &'a self,
        future_type: YieldReason,
    ) -> Result<YieldResponse> {
        let guard = FutureDropGuard::<YieldReason, YieldResponse, MAX_PENDING> {
            future_type,
            runtime: &self,
        };

        // tally relevant counters
        self.has_new_future.store(true, Ordering::Relaxed);
        self.pending_futures.set_default(future_type, 0)?;
        self.pending_futures.edit(&future_type, |v| v + 1);

        guard.build().await
    }

    /// This method is not meant to be called from within async.
    ///
    /// The caller of async runtime uses this to unblock the futures that caused the async step to yield.
    /// Must call this at least once between run_async_step calls
    pub fn unblock_futures(&self, future_type: YieldReason, status: YieldResponse) {
        let has_unblock = { self.has_unblock.borrow().is_some() };
        if has_unblock {
            panic!("Unblocking more than one future in a single async step is disallowed");
        }

        self.has_unblock.borrow_mut().replace((future_type, status));
    }

    /// This method is not meant to be called from within async.
    ///
    /// This is a debugging and profiling utility meant to help the downstream programmer
    /// measure how large MAX_PENDING should be, in order to create a large enough, but
    /// finite, state machine, for their use cases.
    pub fn _pending_futures_size(&self) -> usize {
        self.pending_futures.len()
    }

    /// This method is not meant to be called from within async.
    ///
    /// Returns: None if the future is still incomplete, and has yielded.
    ///          Some(async result) if the future has finished running.
    pub fn run_async_step<F: Future>(&self, future: &mut Pin<&mut F>) -> Option<F::Output> {
        let waker = unsafe { Waker::from_raw(RAW_WAKER_WITH_ASSERTIONS) };
        let mut cx = Context::from_waker(&waker);

        // Poll the future exactly once
        self.has_new_future.store(false, Ordering::Relaxed);
        let result = match future.as_mut().poll(&mut cx) {
            Poll::Ready(val) => Some(val),
            Poll::Pending => None,
        };

        self.has_unblock.replace(None);
        result
    }

    /// This is a function used for unit testing only. It doesn't actually reflect all blockages.
    /// For example, AsyncYield's pending status won't be reflected here.
    fn _has_new_blockage(&self) -> bool {
        self.has_new_future.load(Ordering::Relaxed)
    }

    /// Creates a new Async Runtime.
    /// This function returns a Result but currently has no error case.
    pub fn new() -> Self {
        Self {
            has_unblock: RefCell::new(None),
            has_new_future: AtomicBool::default(),
            pending_futures: FixedSizedMap::new(),
        }
    }

    /// This method is not meant to be called from within async.
    /// It's meant to help the caller of async runtime find out how to unblock the futures
    ///
    /// The func callback can short circuit and end iteration early by returning true.
    ///
    /// Returns: The item that `func` returned true for. (None otherwise)
    pub fn check_pending_reasons<F>(&self, mut func: F) -> Option<YieldReason>
    where
        F: FnMut(YieldReason) -> bool,
    {
        let result = self
            .pending_futures
            .find(|x| x.map(|v| func(v.0)) == Some(true), |(k, _)| *k);
        result
    }
}

impl<'a, YieldReason: Copy + Eq + Ord, YieldResponse: PartialEq, const MAX_PENDING: usize>
    FutureDropGuard<'a, YieldReason, YieldResponse, MAX_PENDING>
{
    async fn build(&'a self) -> Result<YieldResponse> {
        let result = futures_lite::future::poll_fn(|_| {
            let matches = if let Some((curr_type, _)) = self.runtime.has_unblock.borrow().as_ref() {
                curr_type == &self.future_type
            } else {
                false
            };
            if matches && let Some((_, status)) = self.runtime.has_unblock.take() {
                return Poll::Ready(status);
            }
            Poll::Pending
        })
        .await;
        Ok(result)
    }
}

impl<'a, YieldReason: Copy + Eq + Ord, YieldResponse: PartialEq, const MAX_PENDING: usize> Drop
    for FutureDropGuard<'a, YieldReason, YieldResponse, MAX_PENDING>
{
    fn drop(&mut self) {
        let key = self.future_type;
        self.runtime
            .pending_futures
            .edit(&key, |x| if x > 0 { x - 1 } else { 0 });

        let is_empty = self.runtime.pending_futures.read(&key, |x| x == &0);
        if is_empty == Some(true) {
            self.runtime.pending_futures.remove(&key);
        }
    }
}

impl AsyncYielder {
    /// In the example from above, `loop1` calls this function yield to `loop2`
    pub async fn yield_now(&self) {
        let original_poll_num = { *self.num_polls.borrow() };
        futures_lite::future::poll_fn(|_| {
            let new_poll_num = { *self.num_polls.borrow() };
            // To prevent overflow issues, do not compare with <= or >=
            if new_poll_num == original_poll_num {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
    }

    /// In the example from above, as soon as `loop2` gets to execute and finishes its turn,
    /// `loop2` must call this function, to allow `loop1` to run again.
    pub fn unblock(&self) {
        *self.num_polls.borrow_mut() += 1;
    }
}

#[cfg(test)]
mod tests {
    use crate::AsyncRuntimeError;
    use crate::futures;
    use core::pin::pin;

    /// This is just an example YieldReason.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    #[repr(usize)]
    enum PtraceFutureTypes {
        WaitForPtraceSyscall,
        WaitForSignal,
    }

    #[derive(Clone, Debug, PartialEq)]
    /// This is just an example YieldResponse
    struct PtraceStatus {}

    type PtraceAsyncRuntime = futures::AsyncRuntime<PtraceFutureTypes, PtraceStatus>;

    #[test]
    fn test_basic_async_function() {
        let runtime = PtraceAsyncRuntime::new();
        let mut test_future = pin!(futures_lite::future::ready(123));
        assert_eq!(runtime.run_async_step(&mut test_future), Some(123));
    }

    fn _assert_one_pending_at(runtime: &PtraceAsyncRuntime, idx: usize, reason: PtraceFutureTypes) {
        assert_eq!(
            runtime.pending_futures.read_idx(idx, |x| *x),
            Some((reason, 1))
        );
    }

    #[test]
    fn test_basic_blocking_on_built_future() {
        let runtime = PtraceAsyncRuntime::new();
        assert_eq!(runtime._pending_futures_size(), 0);

        let mut test_future =
            pin!(runtime.new_pending_future(PtraceFutureTypes::WaitForPtraceSyscall));
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(runtime._has_new_blockage());
        assert_eq!(runtime._pending_futures_size(), 1);
        _assert_one_pending_at(&runtime, 0, PtraceFutureTypes::WaitForPtraceSyscall);

        // Unblock an irrelevant future
        let event1 = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, event1);
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(!runtime._has_new_blockage());
        assert_eq!(runtime._pending_futures_size(), 1);
        _assert_one_pending_at(&runtime, 0, PtraceFutureTypes::WaitForPtraceSyscall);

        // Unblock the original future
        let event2 = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceSyscall, event2.clone());
        assert_eq!(runtime._pending_futures_size(), 1);
        let output = runtime.run_async_step(&mut test_future);
        assert_eq!(runtime._pending_futures_size(), 0);
        assert_eq!(output, Some(Ok(event2)));
        assert!(!runtime._has_new_blockage());
    }

    #[test]
    fn test_blocking_on_two_built_futures() {
        let runtime = PtraceAsyncRuntime::new();
        let mut test_future = pin!(async {
            runtime
                .new_pending_future(PtraceFutureTypes::WaitForPtraceSyscall)
                .await?;
            runtime
                .new_pending_future(PtraceFutureTypes::WaitForSignal)
                .await?;
            Ok::<i32, AsyncRuntimeError>(42)
        });
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(runtime._has_new_blockage());

        // Unblock an irrelevant future
        let event1 = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, event1);
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(!runtime._has_new_blockage());

        // Unblock the first future
        let event2 = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceSyscall, event2.clone());
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(runtime._has_new_blockage());

        // Unblock the second future (ignoring the first irrelevant unblock for WaitForSignal)
        let event3 = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, event3.clone());
        let output = runtime.run_async_step(&mut test_future);
        assert_eq!(output, Some(Ok(42)));
        assert!(!runtime._has_new_blockage());
    }

    #[test]
    fn test_compatible_with_futures_lite_zip_in_order() {
        let runtime = PtraceAsyncRuntime::new();
        let mut test_future = pin!(futures_lite::future::zip(
            runtime.new_pending_future(PtraceFutureTypes::WaitForPtraceSyscall),
            runtime.new_pending_future(PtraceFutureTypes::WaitForSignal),
        ));
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(runtime._has_new_blockage());

        // Unblock the first future
        let event2 = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceSyscall, event2.clone());
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(!runtime._has_new_blockage());

        // Unblock the second future
        let event3 = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, event3.clone());
        let (output1, output2) = runtime.run_async_step(&mut test_future).unwrap();
        assert_eq!(output1, Ok(event2));
        assert_eq!(output2, Ok(event3));
        assert!(!runtime._has_new_blockage());
    }

    #[test]
    fn test_compatible_with_futures_lite_zip_in_reversed_order() {
        let runtime = PtraceAsyncRuntime::new();
        let mut test_future = pin!(futures_lite::future::zip(
            runtime.new_pending_future(PtraceFutureTypes::WaitForPtraceSyscall),
            runtime.new_pending_future(PtraceFutureTypes::WaitForSignal),
        ));
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(runtime._has_new_blockage());

        // Unblock the second future
        let event2 = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, event2.clone());
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(!runtime._has_new_blockage());

        // Unblock the first future
        let event3 = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceSyscall, event3.clone());
        let (output1, output2) = runtime.run_async_step(&mut test_future).unwrap();
        assert_eq!(output1, Ok(event3));
        assert_eq!(output2, Ok(event2));
        assert!(!runtime._has_new_blockage());
    }

    #[test]
    fn test_compatible_with_futures_lite_or_resolves_first() {
        let runtime = PtraceAsyncRuntime::new();
        let mut test_future = pin!(futures_lite::future::or(
            async {
                runtime
                    .new_pending_future(PtraceFutureTypes::WaitForPtraceSyscall)
                    .await?;
                Ok::<i32, AsyncRuntimeError>(234)
            },
            async {
                runtime
                    .new_pending_future(PtraceFutureTypes::WaitForSignal)
                    .await?;
                Ok::<i32, AsyncRuntimeError>(456)
            },
        ));
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(runtime._has_new_blockage());
        assert_eq!(runtime._pending_futures_size(), 2);
        _assert_one_pending_at(&runtime, 0, PtraceFutureTypes::WaitForPtraceSyscall);
        _assert_one_pending_at(&runtime, 1, PtraceFutureTypes::WaitForSignal);

        // Unblock the first future
        let event = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceSyscall, event.clone());
        assert_eq!(runtime._pending_futures_size(), 2);
        let output = runtime.run_async_step(&mut test_future);
        assert_eq!(runtime._pending_futures_size(), 1);
        assert_eq!(output, Some(Ok(234)));
        assert!(!runtime._has_new_blockage());
    }

    #[test]
    fn test_compatible_with_futures_lite_or_resolves_second() {
        let runtime = PtraceAsyncRuntime::new();
        let mut test_future = pin!(futures_lite::future::or(
            async {
                runtime
                    .new_pending_future(PtraceFutureTypes::WaitForPtraceSyscall)
                    .await?;
                Ok::<i32, AsyncRuntimeError>(234)
            },
            async {
                runtime
                    .new_pending_future(PtraceFutureTypes::WaitForSignal)
                    .await?;
                Ok::<i32, AsyncRuntimeError>(456)
            },
        ));
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(runtime._has_new_blockage());
        assert_eq!(runtime._pending_futures_size(), 2);
        _assert_one_pending_at(&runtime, 0, PtraceFutureTypes::WaitForPtraceSyscall);
        _assert_one_pending_at(&runtime, 1, PtraceFutureTypes::WaitForSignal);

        // Unblock the second future
        let event = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, event.clone());
        assert_eq!(runtime._pending_futures_size(), 2);
        let output = runtime.run_async_step(&mut test_future);
        assert_eq!(runtime._pending_futures_size(), 1);
        _assert_one_pending_at(&runtime, 0, PtraceFutureTypes::WaitForPtraceSyscall);
        assert_eq!(output, Some(Ok(456)));
        assert!(!runtime._has_new_blockage());
    }

    async fn _future_with_waker(runtime: &PtraceAsyncRuntime) -> Result<(), AsyncRuntimeError> {
        futures_lite::future::or(
            async {
                runtime
                    .new_pending_future(PtraceFutureTypes::WaitForPtraceSyscall)
                    .await?;
                futures_lite::future::yield_now().await;
                Ok::<i32, AsyncRuntimeError>(234)
            },
            async {
                runtime
                    .new_pending_future(PtraceFutureTypes::WaitForSignal)
                    .await?;
                Ok::<i32, AsyncRuntimeError>(456)
            },
        )
        .await?;
        Ok(())
    }

    #[test]
    fn test_incompatible_with_waker_such_as_futures_lite_yield_now_step1() {
        // futures_lite::future::yield_now() uses a Waker.
        let runtime = PtraceAsyncRuntime::new();
        let mut test_future = pin!(_future_with_waker(&runtime));

        // Run the first async step, which should not panic
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(runtime._has_new_blockage());

        // Unblock the first await
        let event = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceSyscall, event.clone());
    }

    #[test]
    #[should_panic(
        expected = "Internal error, KRSM Async Runtime detected invalid usage of external async library"
    )]
    fn test_incompatible_with_waker_such_as_futures_lite_yield_now_step2() {
        // futures_lite::future::yield_now() uses a Waker.
        let runtime = PtraceAsyncRuntime::new();
        let mut test_future = pin!(_future_with_waker(&runtime));

        // Run the first async step, which should not panic
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(runtime._has_new_blockage());

        // Unblock the first await
        let event = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceSyscall, event.clone());

        // Run the first async step, which should panic
        let _ = runtime.run_async_step(&mut test_future);
    }
}
