**todo**: update the first example to be `do_skip_syscall` which in fact benefitted more from async than clone()

## Why use Async

Ptrace as it is designed, is event-based. Some logics, like the handling of a clone() syscall
can be so complicated and involve waiting for a specific sequence of events, in a generic event
loop.

This is perfect for single-threaded async logics like the JavaScript's Promise callbacks. 

Rust provides a zero-cost compilation of async functions into synchronous state machines.
Why not make use of it, in a single-threaded fashion, through our own lightweight runtime?

### Spaghetti Ptrace logics

One benefit this provides is that Rust will automatically compile meaningful, human-readable
async logics into the synchronous Spaghetti state machine that the kernel expects from ptrace 

Consider the flow of handling a clone() system call.

* There is the initial `PTRACE_SYSCALL` event that marks the beginning of clone
* There is the interception of SIGCHLD to detect the child's PID
* There is the interception of a special `PTRACE_EVENT` event to handle clone-specific updates


#### Implementation #1: Spaghetti, Synchronous Syntax

In a normal event loop, the logics for all such steps must be defined as an enum, manually:

```
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum TraceeInitStage {
    /// Waiting for Exec
    Begin = 0,
    /// Intercepted exec
    ExecSeen = 1,
    /// Intercepted first call
    FirstCallSeen = 2,
    /// Intercepted the mmap call that replaced the first call
    FirstCallReplacedWithMmap = 3,
    /// Intercepted the final actual first call
    FirstCallActuallyDone = 4,
}
```


```
pub fn event_loop(self: Arc<TraceeHandler<PtraceClient>>) -> Result<u8, SysAugError> {
    // ... skipped some irrelevant code ...
    loop {

        // ... skipped some irrelevant code ...
        let _ = self.on_tracee_signaled(&status, &mut maybe_exit)?
            && self.on_tracee_exited(&status, &mut maybe_exit)?

            // ADDING the next line
            && self.on_tracee_init_syscalls(&status, &mut maybe_exit)?
            && self.on_tracee_syscall(&status, &mut maybe_exit)?
            && self.on_tracee_clone(&status, &mut maybe_exit)?
            && self.on_tracee_unknown_event(&status, &mut maybe_exit)?;
```

```
fn on_tracee_syscall(&self, s: &WaitStatus, exit: &mut Option<u8>) -> BoolResult {
    let pid = self.pid;
    if ptrace::is_syscall_stop(s) {
        // ... reading the syscall number, registers ...

        let last_syscall = rwlock_read(&self.last_syscall)?;
        let tracee_init_stage = { *(rwlock_read(&self.tracee_init_stage)?) };

        // ... skipped the augment calls ...

        drop(last_syscall); // Otherwise, deadlock.
        self.maybe_skip_syscall()?;
        if tracee_init_stage != TraceeInitStage::FirstCallActuallyDone && which_aug == Some(&Augments::Exec) {
            rwlock_replace(&self.tracee_init_stage, TraceeInitStage::ExecSeen)?;
            return Ok(true);
        }
        return Ok(false);
    }
}
```

```
// ------------------------- This function demonstrates "sync vs async" ------------------------
// ------------------------- (Compare with "_insert_syscall" below) ------------------------
fn on_tracee_init_syscalls(&self, s: &WaitStatus, exit: &mut Option<u8>) -> BoolResult {
    let pid = self.pid;
    let mut last_stage = { *(rwlock_read(&self.tracee_init_stage)?) };
    if last_stage == TraceeInitStage::Begin {
        // Waiting for exec (which will be marked by on_tracee_syscall)
        return Ok(true);
    }
    if last_stage == TraceeInitStage::FirstCallActuallyDone {
        return Ok(true);
    }
    if ptrace::is_syscall_stop(s) {
        let mut regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;
        let syscall_info = SYSCALL_INFOS.get(&regs.last_syscall_num);
        if regs.last_syscall_num == NO_MOD_SYSCALL {
            // If we are trying to skip a syscall, allow that to go through
            return Ok(true);
        }
        if syscall_info.map(|x| &x.augment) == Some(&Augments::Exec) {
            return Ok(true);
        }

        if last_stage == TraceeInitStage::ExecSeen {
            // Last stage is ExecSeen and we are no longer seeing Exec syscall
            last_stage = TraceeInitStage::FirstCallSeen;
        }

        // Make sure we bookkeep the value of tracee_init_stage for next round
        let new_stage: TraceeInitStage = (last_stage as u8 + 1).try_into().unwrap();
        rwlock_replace(&self.tracee_init_stage, new_stage)?;

        // Handle a few special stages for the current round
        match last_stage {
            TraceeInitStage::FirstCallSeen => {
                rwoption_replace(&self.orig_request_regs, regs.clone())?;

                // TODO: Block Tracee from accessing the entire MMAP. Expose only its own.
                regs.arg0 = 0;
                regs.arg1 = SHARED_MMAP_SIZE;
                regs.arg2 = libc::PROT_READ as usize;
                regs.arg3 = libc::MAP_SHARED as usize;
                regs.arg4 = self.shared_fd as usize;
                regs.arg5 = 0;

                self.ptrace_client
                    .execute(move || ptrace::setregs(pid, regs))??;
                self.ptrace_client
                    .execute(move || ptrace::set_syscall_num(pid, libc::SYS_mmap as usize))??;
                return Ok(false);
            }
            TraceeInitStage::FirstCallReplacedWithMmap => {
                let orig_regs = rwoption_take(&self.orig_request_regs)?
                    .ok_or(SysAugError::InitMissingSavedRegs)?;
                let orig_syscall_num = orig_regs.last_syscall_num;
                let mut tracee_addr = rwlock_write(&self.mmap_tracee_addr)?;
                *tracee_addr = regs.syscall_retval();

                self.ptrace_client
                    .execute(move || ptrace::setregs(pid, orig_regs))??;
                self.ptrace_client
                    .execute(move || ptrace::set_syscall_num(pid, orig_syscall_num))??;
                return Ok(false);
            }
            _ => {}
        }
    }
    Ok(true)
}
```

Here is a link to the actual code: https://github.com/markzyu/pocker/commit/5a95bbc18a62ac691ad3ffa4594e01a990b08306#diff-ba3485e82dd442c512db671a5fe0b0c367b00667537f2d7a44b71df6f4d89927

Side Note:

> Fundamentally, the code is scattered because tracee can encounter other surprises during this
> time, and simply crash or receives a signal, etc. So the synchronous event loop cannot simply
> **block** all handling of other events to simply serve clone() only
>
> You could say that we can make an exception for clone(). But then there are plenty of other
> system calls that require specific chain of events admist a chaos of other possible outcomes.
>
> Why make an exception when there is a clean pattern to rely on? Especially when we know
> there will simply be more and more "exceptions" to make? That's how Spaghetti code starts.

#### Implementation #2: Asynchronous Syntax

In an async event loop, the logics will look much simpler. In fact, the purely async part of the code will look too simple to be true. So I will show both the relevant async code, and the synchronous setup around the async logics.

When combined, this implementation doesn't reduce the lines of code, but it makes the semantics much clearer.

```
pub fn event_loop(self: Arc<TraceeHandler<PtraceClient>>) -> Result<u8, SysAugError> {
    // ... skipped some irrelevant code ...

    let mut main_loop_future = async_handlers.all_tracee_loops();
    self.ptrace_client.attach_to(pid)?;
    self.set_ptrace_options()?;

    loop {
        // Drive async logic until it is pending on a future by resuming from where we left off
        if let Some(exit_code) = async_runtime.run_async_step(&mut main_loop_future)? {
            // Handle signals, special gdb exit, etc
            if *async_handlers.notifiers.transfer_to_gdb.borrow() {
                return Ok(self.transfer_to_gdb()?);
            }

            return Ok(exit_code?);
        }

        let mut maybe_signal = { async_handlers.notifiers.signal_tracee.borrow_mut().take() };

        loop {
            // Send ptrace calls, resume tracee, until we have unblocked a future
            // Also, use maybe_signal.take() so that the signal is only sent once
            self.ptrace_syscall(maybe_signal.take())?;

            // ... (wait for child, get status, handle crashes) ...

            // Unblock different futures in the proper order
            // --------------------------------------------------
            // Note: This might look equally complex as the if conditions on TraceeInitStage enums
            //       But here the number of conditions grow with the TYPES of ptrace events, 
            //       And that does not grow with the complexity of async logics.
            // --------------------------------------------------
            if let Some(..) = self.get_tracee_maybe_signal(&wait_status)? {
                async_runtime.unblock_futures(PtraceFutureTypes::WaitForSignal, status);
                break;
            } else if let WaitStatus::PtraceEvent(..) = &wait_status {
                async_runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceEvent, status);
                break;
            } else if let WaitStatus::PtraceSyscall(..) = &wait_status {
                async_runtime.unblock_futures(PtraceFutureTypes::WaitForPtraceSyscall, status);
                break;
            } else {
                event!(Level::INFO, "Unknown ptrace event: {:?}", &wait_status);
            }
        }
    }
}
```

```
async fn all_tracee_loops(&self) -> Result<u8, SysAugError> {
    self.call_mods(ModFeature::OnTraceeStartup, |m| m.on_tracee_startup())
        .await?;

    // The order here matters. It's the order of polling precedence.
    let result = futures_lite::future::or(
        futures_lite::future::or(
            self.loop_handle_tracee_signals(),
            self.loop_handle_tracee_syscalls(),
        ),
        self.loop_handle_tracee_other_events(),
    )
    .await;

    let pid = self.pid;
    let MemHelpers { close_tracee, .. } = get_mem_helper();
    (close_tracee)(&pid)?;
    result
}
```

```
async fn loop_handle_tracee_syscalls(&self) -> Result<u8, SysAugError> {
    let pid = self.pid;

    // Take notice that this variable doesn't need to be in an Arc or RefCell,
    let mut total_times: u64 = 0;

    loop {
        // ... skipped some irrelevant code ...

        self.wait_for_syscall().await?;
        
        // ... skipped some irrelevant code ...

        // Check how we should augment the syscall
        if let Some(syscall_info) = maybe_syscall_info {
            call_augment!(self, which_aug, regs.clone(), &syscall_info);
        } else {
            self.do_resume_syscall().await?;
        }

        // ... skipped some irrelevant code ...

        
        // This is the new logic that's equivalent to TraceeInitStage::ExecSeen
        if which_aug == Some(&Augments::Exec) {
            /// Take over the syscall async loop, right after execve() to establish mmap
            self._insert_syscall("SYS_mmap", /* ... ... */).await?;
            set_tracee_write_region_addr(/* The tracee side address created by mmap */);
        }
    }
}
```

```
// ------------------------- This function demonstrates "sync vs async" ------------------------
// ------------------------- (Compare with "on_tracee_init_syscalls" above) ------------------------
async fn _insert_syscall(
    &self,
    syscall_name: &'static str,
    syscall_num: usize,
    args: [usize; 6],
) -> Result<GenericPurposeRegs, SysAugError> {
    // Wait the next system call entry, could be anything, including NO_MOD_SYSCALL
    let pid = self.pid;
    self.yielder_syscall.unblock();
    self.wait_for_syscall().await?;

    let orig_regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;

    // ... (some other code) ...

    // Override that system call to run mmap instead
    regs.arg0 = args[0];
    regs.arg1 = args[1];
    regs.arg2 = args[2];
    regs.arg3 = args[3];
    regs.arg4 = args[4];
    regs.arg5 = args[5];

    self.ptrace_client
        .execute(move || ptrace::setregs(pid, regs))??;
    self.ptrace_client
        .execute(move || ptrace::set_syscall_num(pid, syscall_num))??;

    // Wait for mmap to return
    self.wait_for_syscall().await?;
    let result_regs = self.ptrace_client.execute(move || ptrace::getregs(pid))??;

    // Reset tracee to register state before system call
    // and decrement PC pointer to immediately rerun system call
    let mut new_regs = orig_regs;
    new_regs.pc -= SYSCALL_INSTRUCTION_SIZE;
    event!(
        Level::DEBUG,
        "TraceeInit: Continuing syscall {} from {:x}",
        new_regs.last_syscall_num,
        new_regs.pc
    );
    self.ptrace_client
        .execute(move || ptrace::setregs(pid, new_regs))??;
    Ok(result_regs)
}
```

That's it. There is no need to manually define Enums for a State Machine. There is no need to split functions to make the compiler happy. Instead, the functions are split based on semantics like "wait for the next system call", and "yield here just in case" (for example to handle a signal sent to the tracee)


We can gather all these steps in one place, and then simply wait for a "ptrace future" that
unblocks us whenever the correct next stage happens

### RwLocks

Another benefit this provides, is to reduce overhead from RwLocks

Ptrace is oddly a very good example of an async event loop that is always wrongly
implemented as a synchronos tracer... Consider the typical Rust code needed to
track the current pointer location of a stack

```
pub struct TraceeHandler<PtraceClient: executor::PtraceClient> {
    pub pid: Pid,
    pub ptrace_client: PtraceClient,
    pub states: Arc<TraceeHandlerStates>,
    pub parent: Option<Arc<TraceeHandler<PtraceClient>>>,

    // ...

    pub tracee_stack_offset: RwLock<usize>,

    // ...
}

```

```
    // Send the content of `bytes` to tracee's stack, and return its address.
    // This can be called multiple times and will add new content to the end of
    // previous contents.
    pub fn tracee_stack_append(&self, bytes: Vec<u8>) -> Result<usize, SysAugError> {
        let pid = self.pid;
        let mut offset = rwlock_write(&self.tracee_stack_offset)?;
        let old_offset = *offset;
        let (addr, new_offset) = self.ptrace_client.execute(move || {
            let final_bytes = bytes.as_slice();
            unsafe { ptrace::write_bytes_to_tracee(pid, old_offset, final_bytes) }
        })??;
        *offset = new_offset;
        Ok(addr)
    }

    pub fn tracee_stack_append_path(&self, path: PathBuf) -> Result<usize, SysAugError> {
        let bytes = path.into_os_string().into_vec();
        self.tracee_stack_append(bytes)
    }

    // Change the address, to which the next tracee_stack_append will write contents.
    // offset = how many bytes of previously written contents will stay after this
    pub fn tracee_stack_seek(&self, offset: usize) -> Result<(), SysAugError> {
        let mut ref_offset = rwlock_write(&self.tracee_stack_offset)?;
        *ref_offset = offset;
        Ok(())
    }
```

Whenever synchronous logic is involved, we introduce a global state and must have a RwLock.

> Note: One way to avoid the RwLock is to use a second single-threaded Struct. We could
> have also used thread_local! and a RefCell

And yet, with a async and an local thread executor, you immediately get RefCell for free: 

If you look at the [async version](https://github.com/markzyu/pocker/blob/817f6b8e492fd177a51957e0c142d0b52ef01cf9/sysaug/src/handler.rs#L158) of `tracee_stack_offset` today, it's a `RefCell`.


## Implementing our own Lightweight Async Runtime

Note: The implementation would work MUCH better if we can do tokio runtime one turn at a
time (pausing at each await) instead of block_on 
    And, this would also need a special PendingOrReady struct that can change between
    the two states while being awaited on (without "replacing" the future?)

ALTERNATIVELY, maybe implement our own future that wraps ALL ptrace actions
    |
    .--> THIS IS BETTER!

    Need to have our own struct PtraceFuture impl Future

    IF tokio doesn't support turn-by-turn execeution, then we also need to write 
    our own Async runtime, which essentially just runs one
    "turn"/poll each time, returning the PtraceFuture that caused the await.

    And this PtraceFuture will describe to the ptrace crate what we are waiting FOR.

    Why?

    This will allow us to write async code in the most semantic way.

    await tracee_init_mmap()
    while (syscall = syscall_status_generator.next().await) {
      await syscall_augtable[syscall.num]();
    }

    And the turn-by-turn execution make sure we restart from the last "yield"
