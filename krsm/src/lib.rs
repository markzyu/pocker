// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
#![no_std]
#![doc = include_str!("../README.md")]

pub mod common;
pub mod futures;
pub mod runtime;
pub mod tasks;

pub use crate::common::{AsyncRuntimeError, FixedSizedMap};
pub use crate::futures::{
    AsyncYielder, StrongFuture, StrongWeakBuilder, WeakFuture, WeakFutureGuard, downgrade, upgrade,
};
pub use crate::runtime::AsyncRuntime;
pub use crate::tasks::{TaskBatch, TaskTracker};
