// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
use core::cell::{Ref, RefCell};
use core::future::Future;
use core::marker::PhantomPinned;
use core::ops::Deref;
use core::pin::Pin;
use core::task::{Context, Poll};

/// AsyncYielder is a helper for concurrent loops in async.
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

struct AsyncYielderFuture<'a> {
    orig_poll_number: usize,
    async_yielder: &'a AsyncYielder,
}

/// This is a builder struct + RAII guard, for both [StrongFuture] and [WeakFuture]
///
/// You can obtain one by calling [upgrade] on any [Future]
pub struct StrongWeakBuilder<T, F: Future<Output = T>> {
    result: RefCell<Option<T>>,
    timing: RefCell<F>,
    _marker: PhantomPinned,
}

/// This is a Future that drives the completion of both the original future, and any related
/// [WeakFuture] instances
///
/// You can obtain one by calling [upgrade] on any [Future], and then calling [StrongWeakBuilder::build]
///
/// **What is Strong? and what is Weak?**
///
/// The "strong-weak" naming is meant to highlight the borrow relationship between the two.
/// But another name for this pair could be "timing-data":
///
/// * The [StrongFuture] holds ownership of the original future, and drives it execution.
/// * The [WeakFuture] holds a readonly reference to the `Future::Output` data of the original future
///
/// This "strong-weak" arrangement is helpful if you ever need to duplicate access to
/// the same future across many `futures_lite::future::zip()` branches.
///
/// The zipped future, whose branches wait for [WeakFuture], is called a `weak_wrapper`
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct StrongFuture<'a, T, F: Future<Output = T>, F2: Future> {
    result: &'a RefCell<Option<T>>,
    timing: &'a RefCell<F>,
    weak_wrapper: RefCell<F2>,
}

/// A weak future is like a borrowed reference to a [StrongFuture]. You can have as
/// many weak futures as you would like, by calling [downgrade]. However, just like weak `Arc`
/// pointers, all [WeakFuture] references expire when your [StrongWeakBuilder] is dropped.
///
/// You can obtain one by calling [downgrade] on any [StrongWeakBuilder]
///
/// But there is a catch:
///
/// > The output from `weak_future.await` is a [WeakFutureGuard]. And you **must** drop this guard
/// > manually before any other `await` in your own async code. Otherwise, Rust **will panic**.
///
/// **What is Strong? and what is Weak?**
///
/// The "strong-weak" naming is meant to highlight the borrow relationship between the two.
/// But another name for this pair could be "timing-data":
///
/// * The [StrongFuture] holds ownership of the original future, and drives it execution.
/// * The [WeakFuture] holds a readonly reference to the `Future::Output` data of the original future
///
/// This "strong-weak" arrangement is helpful if you ever need to duplicate access to
/// the same future across many `futures_lite::future::zip()` branches.
///
/// The zipped future, whose branches wait for [WeakFuture], is called a `weak_wrapper`
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct WeakFuture<'a, T> {
    result: &'a RefCell<Option<T>>,
}

/// This is an RAII guard to help you access the output from `.await` of a [WeakFuture]
///
/// You **must** drop this guard manually before any other `await` in your own async code.
/// Otherwise, Rust **will panic**.
pub struct WeakFutureGuard<'a, T> {
    guard: Ref<'a, Option<T>>,
}

impl AsyncYielder {
    /// In the example from above, `loop1` calls this function yield to `loop2`
    pub async fn yield_now(&self) {
        let orig_poll_number = { *self.num_polls.borrow() };
        let future = AsyncYielderFuture {
            async_yielder: self,
            orig_poll_number,
        };
        future.await;
    }

    /// In the example from above, as soon as `loop2` gets to execute and finishes its turn,
    /// `loop2` must call this function, to allow `loop1` to run again.
    pub fn unblock(&self) {
        *self.num_polls.borrow_mut() += 1;
    }
}

impl<'a> Future for AsyncYielderFuture<'a> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let new_poll_num = { *self.async_yielder.num_polls.borrow() };
        // To prevent overflow issues, do not compare with <= or >=
        if new_poll_num == self.orig_poll_number {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

impl<'a, T> Future for WeakFuture<'a, T> {
    type Output = WeakFutureGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let is_some = { self.result.borrow().is_some() };
        match is_some {
            true => Poll::Ready(WeakFutureGuard {
                guard: self.result.borrow(),
            }),
            false => Poll::Pending,
        }
    }
}

impl<'a, T> Deref for WeakFutureGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.guard.as_ref().unwrap()
    }
}

impl<'a, T, F, F2> Future for StrongFuture<'a, T, F, F2>
where
    F: Future<Output = T>,
    F2: Future,
{
    type Output = F2::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut future = self.timing.borrow_mut();
        let pinned = unsafe { Pin::new_unchecked(&mut *future) };
        match pinned.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(v) => {
                self.result.replace(Some(v));

                let mut future2 = self.weak_wrapper.borrow_mut();
                let pinned2 = unsafe { Pin::new_unchecked(&mut *future2) };
                pinned2.poll(cx)
            }
        }
    }
}

/// Upgrades any future to obtain a [StrongWeakBuilder], which builds a [StrongFuture]
///
/// Caveat: This [StrongFuture] consumes your original future. This means two things:
///
/// 1. You **must** await on [StrongWeakBuilder::build]. Otherwise, the original future won't run at all.
/// 2. You **must** create a [WeakFuture] to obtain access to the resulting data.
///
/// Why?
///
/// This strong-weak execution model helps if you need multiple "Weak" references to
/// the same future, so that different handling logics can blend together, using a
/// `futures_lite::future::zip()` call.
///
/// The zipped future is called a `weak_wrapper`.
pub fn upgrade<'a, T, F>(future: F) -> StrongWeakBuilder<T, F>
where
    F: Future<Output = T>,
{
    StrongWeakBuilder {
        result: RefCell::new(None),
        timing: RefCell::new(future),
        _marker: PhantomPinned::default(),
    }
}

/// Obtains a [WeakFuture], which is a borrowed reference to a [StrongFuture]
///
/// This reference serves as a new Future that can be awaited on.
///
/// Caveat: The result from `weak_future.await` is a [WeakFutureGuard]. And you **must** drop this guard
/// manually before any other `await` in your own async code. Otherwise, Rust **will panic**.
pub fn downgrade<'a, T, F>(strong: &'a StrongWeakBuilder<T, F>) -> WeakFuture<'a, T>
where
    F: Future<Output = T>,
{
    WeakFuture {
        result: &strong.result,
    }
}

impl<T, F: Future<Output = T>> StrongWeakBuilder<T, F> {
    /// This function allows you to pass [WeakFuture] instances to async wrapper functions,
    /// as a `weak_wrapper` future, which can be, for example: `futures_lite::future::zip()`
    ///
    /// This function will build a [StrongFuture] which runs the resulting `weak_wrapper` future,
    /// as well as the original future that was consumed by [upgrade].
    pub fn build<F2>(&self, weak_wrapper: F2) -> StrongFuture<'_, T, F, F2>
    where
        F: Future<Output = T>,
        F2: Future,
    {
        StrongFuture {
            weak_wrapper: RefCell::new(weak_wrapper),
            result: &self.result,
            timing: &self.timing,
        }
    }

    /// Take the result of the original, completed [StrongFuture]
    ///
    /// This method should only be called after the future from [StrongWeakBuilder::build]
    /// completes.
    ///
    /// If the future is not complete, this method **will panic**.
    pub fn take_result(&self) -> T {
        let mut guard = self.result.borrow_mut();
        guard.take().expect(
            "StrongFuture should have completed before calling StrongWeakBuilder::take_result",
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{AsyncRuntimeError, futures, runtime};
    use core::pin::pin;

    /// This is just an example YieldReason.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    #[repr(usize)]
    #[allow(unused)]
    enum PtraceFutureTypes {
        WaitForPtraceSyscall,
        WaitForSignal,
    }

    #[derive(Clone, Debug, PartialEq)]
    /// This is just an example YieldResponse
    struct PtraceStatus {}

    type PtraceAsyncRuntime = runtime::AsyncRuntime<PtraceFutureTypes, PtraceStatus>;

    fn _assert_one_pending_at(runtime: &PtraceAsyncRuntime, idx: usize, reason: PtraceFutureTypes) {
        assert_eq!(
            runtime.pending_futures.read_idx(idx, |x| *x),
            Some((reason, 1))
        );
    }

    #[test]
    fn test_strong_weak_futures_can_be_used_to_blend_logics() {
        let runtime = PtraceAsyncRuntime::new();
        let strong_future = futures::upgrade(async {
            runtime
                .new_pending_future(PtraceFutureTypes::WaitForSignal)
                .await?;
            Ok::<i32, AsyncRuntimeError>(100)
        });
        let mut test_future = pin!(async {
            let weak_wrapper = futures_lite::future::zip(
                async {
                    let guard1 = futures::downgrade(&strong_future).await;
                    match guard1.as_ref() {
                        Ok(val1) => Ok::<i32, AsyncRuntimeError>(val1 * 5),
                        Err(err) => Err::<i32, AsyncRuntimeError>(err.clone()),
                    }
                },
                async {
                    let guard2 = futures::downgrade(&strong_future).await;
                    match guard2.as_ref() {
                        Ok(val2) => Ok::<i32, AsyncRuntimeError>(val2 * 6),
                        Err(err) => Err::<i32, AsyncRuntimeError>(err.clone()),
                    }
                },
            );
            let (result1, result2) = strong_future.build(weak_wrapper).await;
            Ok::<i32, AsyncRuntimeError>(result1? + result2?)
        });
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(runtime._has_new_blockage());
        assert_eq!(runtime._pending_futures_size(), 1);
        _assert_one_pending_at(&runtime, 0, PtraceFutureTypes::WaitForSignal);

        // Unblock the future
        let event = PtraceStatus {};
        runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, event.clone());
        let output = runtime.run_async_step(&mut test_future);

        assert_eq!(runtime._pending_futures_size(), 0);
        assert_eq!(strong_future.result.borrow().clone(), Some(Ok(100)));
        assert_eq!(output, Some(Ok(1100)));
        assert_eq!(strong_future.take_result(), Ok(100));
        assert!(!runtime._has_new_blockage());
    }

    #[test]
    #[should_panic(
        expected = "StrongFuture should have completed before calling StrongWeakBuilder::take_result"
    )]
    fn test_incompatible_with_waker_such_as_futures_lite_yield_now_step2() {
        let runtime = PtraceAsyncRuntime::new();
        let strong_future = futures::upgrade(async {
            runtime
                .new_pending_future(PtraceFutureTypes::WaitForSignal)
                .await?;
            Ok::<i32, AsyncRuntimeError>(100)
        });
        let mut test_future = pin!(async {
            let weak_wrapper = async {
                let guard1 = futures::downgrade(&strong_future).await;
                match guard1.as_ref() {
                    Ok(val1) => Ok::<i32, AsyncRuntimeError>(val1 * 5),
                    Err(err) => Err::<i32, AsyncRuntimeError>(err.clone()),
                }
            };
            let result = strong_future.build(weak_wrapper).await;
            Ok::<i32, AsyncRuntimeError>(result?)
        });
        assert_eq!(runtime.run_async_step(&mut test_future), None);
        assert!(runtime._has_new_blockage());
        assert_eq!(runtime._pending_futures_size(), 1);
        _assert_one_pending_at(&runtime, 0, PtraceFutureTypes::WaitForSignal);

        // take_result() now, without completing the StrongFuture, will panic
        let _ = strong_future.take_result();
    }
}
