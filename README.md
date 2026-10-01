## So this is just PRoot?

This is inspiried by PRoot -- both make use of SECCOMP to improve performance. Both can intercept system calls through ptrace() and simulate the chroot() system call so that we can chroot into a different Linux Distro on a non-rooted phone. The main difference is this: This solution is multithreaded, while proot itself is single threaded.

You should just use PRoot instead. It has a history of proven stability and success.

My project is still in its early stage. It barely works right now. Basic shell commands work but `apt-get` is broken.

My goal is to run OCI containers on modern Android devices, without rooting the phone, without a full Linux VM, by creating an accompanying configuration file that tells the ptrace how to glue the file system back together.

```
LD_PRELOAD="" cargo run --bin pocker -- run alpine
```

## Caveat 1: `pocker run` cannot actually keep the container layer intact

Containers expect their layers to be readonly.

As of this early version, Pocker writes directly to the layer. So it would write changes to that layer, even if it's supposed to be readonly.

And, it only works if there is just one layer in the current container. 

This caveat will be resolved later, by adding support for fs overlays.

Due to this caveat, the `pocker run` command is currently "hidden", but you can still invoke it if you'd like to.

## Caveat 2: You need to manually unset `LD_PRELOAD`

Termux has a dynamic loader in `LD_PRELOAD`, which exists outside our pocker container. And the loader seems to inject  `LD_PRELOAD` back for a child process, if a parent (1) tried to unset it, and (2) if the parent was not launched with `LD_PRELOAD=""` in its explicit command line.

Because of this, you must manually unset the env var on Android

```
cargo build
LD_PRELOAD="" ./target/debug/pocker run alpine
```

## Multi-threading mode 

By default, pocker will try to run ptrace() syscalls on dedicated threads (one thread per tracee process)

![Multi-threading mode](MultiThreadingMode.png)

But this requires the permission for PTRACE_ATTACH. And on some systems, this permission is blocked, and tracer can only attach to their direct children from main threads.

## Fallback mode (single-threaded)

If the host OS does not permit PTRACE_ATTACH, pocker will try to cumulate ptrace() syscalls on main thread from all tracee processes, and offload each tracee's own event loop and calculations to other threads. (Main thread is busy executing ptrace() calls while other threads queue ptrace actions)

![Fallback threading mode](FallbackThreadingMode.png)

## Project structure

Sysaug crate contains the core logics of pconainer. The full name is System Augmentation, meaning a backend, low level ability to modify specific syscalls (such as remapping a path before it is sent to openat())

Within `sysaug` crate, there are two major parts:

* `aug_*.rs` defines Augments which have separate concerns based on the type of syscalls they augment
* `handler_*.rs` defines the core "state machine" that translates TraceeHandlerConsts and various trackers of tracee's stack and hacky mmap injection addresses, into how exactly to rewrite every syscalls + followup on them in multi-step algorithms.

Additionally, 

* `ptrace` crate is responsible for abstracting away the low level pointer safety of translating tracee pointers to/from ptrace calls
* `executor` crate is responsible for abstracting away the low level thread safety of running ptrace calls across threads
* And, `executor` crate also implements a basic Thread-Per-Core "async" runtime that fits my realtime tracer needs better: `PtraceAsyncRuntime`


This `PtraceAsyncRuntime` is mostly an enabler of an anti-pattern: I chose to write the state machine of a tracer using async syntax sugar, instead of manually writing out the state machine as literal switch case listing and migrating between all checkpoint states. Another added benefit of `PtraceAsyncRuntime` is that all logics within it are forced to run on the same thread, so I can avoid `Arc<Mutex<>>` and use `RefCell` instead.

## For Developers

On Android, please install Rust through Termux: `pkg install rust`. After that, this project should compile with no issues.

To actually run a chroot, you'd need to overwrite a few environment variables. Here is an example command:

```bash
PATH=/sbin:/usr/sbin:/bin:/usr/bin LD_PRELOAD="" target/debug/pocker-runtime --sudo --chroot ~/.pocker/storage/layers/sha256\:333125b5cee9fb6718bdcb523fc93b4adc71b7c37ada6146a20c193430e549b9/ --cmd /bin/bash

# Then, run:
cd /
```

How to debug problems:

```bash
RUST_LOG=TRACE RUST_LOG_BLOCKING=1 RUST_LOG_NO_COLOR=1 RUST_BACKTRACE=1 RUST_LOG_DIR=~/.logs cargo run --bin pocker-runtime -- --chroot ./xxx --root | grep -v TRACE | grep -v DEBUG

# Verbose debug logs will show up in both stderr, and in the ~/.logs/ folder
```

## Cross compilation (outdated instructions)

As long as our parallel proot doesn't slow down the tracee by more than 5x. It should be fine.

It's highly recommended to simply install rust on Termux and perform native compilation.

Here are some (outdated) instructions about Android cross-compilation without Termux:

- Install GNU toolchains (`arm-linux-*-gcc` and `aarch64-linux-*-gcc`)
- Update your `~/.cargo/config`:
  ```
  [target.armv7-unknown-linux-gnueabihf]
  rustflags = ["-C", "target-feature=+crt-static"]
  linker = "arm-linux-foobar-gcc"
  ```
- Run `cargo build --target=armv7-unknown-linux-gnueabihf --release`
- **Android permissions**
  - The terminal emulator must request specific permissions to unlock the ability to execute `./pocker`. The exact permission name is unknown.
  - Older Android versions work better with https://f-droid.org/en/packages/org.galexander.sshd/
  - [Android 10 and above require executables to be codesigned](https://github.com/greenaddress/abcore/issues/97)
    - Termux is the only solution that works well in this situation. [Here is a page from their discussion.](https://github.com/termux/termux-app/issues/1072)
    - But apparently, IT'S EASIER IF `pocker` IS CODE SIGNED AS part of the readonly APK.

## AI Usage

I re-use the same IDE across many projects. When I use the AI coding functionalities, I only use the Cursor TAB model. This project doesn't contain unreviewed AI code, and doesn't include large patches of purely AI generated code.

## Prior project names

This project has existed for many years and had used other names such as `pcontainer` and `dockify`

## License

Copyright (c) 2026 Zhongzhi Yu

This project is licensed under the GNU General Public License v3.0 (GPLv3) - 
see [COPYING](COPYING) for details

Additionally, for the krsm crate, and that crate only, you can choose to use
the [MIT License](krsm/LICENSE) instead
