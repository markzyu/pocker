# KRSM: KRSM Rust State Machine

This crate is a single-threaded, pinned, no_std async runner for futures. It's barely an async runtime, because it:

* Requires you to pin the `Future`, and to manually poll it until completion.
* Does not interact with any system call through async I/O  
* Does not rely on the wakers to determine when to wake up the polling thread.

Instead of providing an executor and a reactor, KRSM lets you (the downstream) define yields, perform non-blocking I/O on behalf of async functions, and take control of each individual polling step.


```rust,ignore
// async side: wait for various yields, tagged by reason
let status = futures_lite::future::or(
    runtime.new_pending_future(WaitForIOResponse),
    runtime.new_pending_future(WaitForUserInput),
).await?;

// sync side: you own the loop
let mut future = your_async_fn();
loop {
    if let Some(result) = unsafe { runtime.run_async_step(&mut future) }? {
        return result;
    }
    if let Some(event) = check_user_input_non_blocking() {      // your I/O, outside async
        runtime.unblock_futures(WaitForUserInput, event)?;      // resume exactly one of the many concurrent futures
        continue;
    }
}
```

And unlike a generator, or a sans-io request/response channel, KRSM keeps several yields alive at the same time. Each one is tagged with a `YieldReason`, and the caller chooses exactly one to resume per polling step — which means KRSM allows the direct usage of `futures_lite::future::or`.


## Goal

This library aims to be a bare minimum abstraction of Rust compiler's ability to translate async functions into pollable state machines. The goal is to write non-blocking, single-threaded, determinstic state machines using readable, asynchronous descriptions.

Please check out the example state machines in [the `examples` folder](https://github.com/markzyu/pocker/tree/master/krsm/examples).

This crate will not eliminate the need for a non blocking I/O. The "non blocking input" part happens outside async.

This "synchronous caller" part of your code would feel a lot like writing old schooled "stack ripping" non-blocking code. It even still has the `YieldReason` switch cases, except some of that spaghetti is now managed by the Rust compiler, and written as async functions.

## Caveat 1: Extra constraints on `async` syntax

Your async code must satisfy both of the following conditions:

1. It is written as if everything runs concurrently, like a non-determinstic state machine (through `futures_lite::future::or`)
2. And yet, it is executed deterministically: only one of those possible transitions can be taken, per async turn.

As a result:

* Unblocking multiple futures in one turn can lead to undefined behaviors and is forbidden.
* The downstream caller must properly prioritize between different `YieldReason` reasons, to choose only one reason when unblocking the state machine.

And worst of all:

* If two branches of `futures_lite::future::or` are awaiting on the exact same `YieldReason`, then only the first future branch will be unblocked. And, the order for "the first" await is the same as the `or()` function parameters' order.

Thus, there is very little margin of error in the resulting code. And two versions of code might look equivalent when only one of them is correct.

## Caveat 2: Limitations on the size of `YieldReason` enum

This crate is `no_std` and cannot allocate additional heap memory at runtime. If your `YieldReason` is a simple, C-like Enum, this doesn't pose a problem until you have 1000+ variants of `YieldReason`.

However, if your YieldReason is a complex enum, then:

* At any moment of an async future's execution, there is a limit on the maximum number of pending futures that can be tracked by the runtime.
* This number is `MAX_PENDING` and can be controlled at compile time, through Rust const generics.

Upon hitting this limit, all further async calls will fail due to `AsyncRuntimeError::TooManyPending`. To avoid this scenario, it's recommended to

* Please choose a concise representation for `YieldReason`, so that there are less variants in flight during any single async step, and
* Please choose a `MAX_PENDING` value that can accomodate the maximum `_pending_futures_size()` of your biggest use case

Alternatively, if your business logics can establish error boundaries, please handle `AsyncRuntimeError::TooManyPending` by rejecting the offending requests. It is a Result returned within the async logics, and it can be recoverable.

Ultimately, KRSM is a finite state machine (FSM). The size of its internal state is fixed at compilation time. Please be aware of these limits. If your use cases need to scale, then you most likely need a different async runtime.

## License

Copyright (c) 2026 Zhongzhi Yu

This KRSM crate is dual licensed, under both the MIT License, and the GPLv3 License.
