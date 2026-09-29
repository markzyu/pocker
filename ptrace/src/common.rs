// Copyright 2026 Zhongzhi Yu <7296488+markzyu@users.noreply.github.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

use crate::mem_slow;
use lazy_static::lazy_static;
use nix::sys;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::RwLock;
use thiserror::Error;
use tracing::{Level, event};

pub const NT_PRSTATUS: libc::c_int = 1;

/// Due to arm limitations, this must be a multiple of 4096
pub const STACK_SAFE_ZONE_SIZE: usize = 16 * 1024;
pub const MAX_NUM_TRACEES: usize = 8192;
pub const MAX_STRUCT_SIZE: usize = 2048;

/// One single writeable mmap, shared across all tracees.
///
/// Should be exactly 128MB of RAM, divided into 8192 regions of shared 'stack'
///
/// This RAM is shared from tracer to all tracees, readonly for tracees.
///
/// Each region is indexed and there will be a global hashmap + vec in tracer's
/// private RAM, to allocate and track regions for tracees. Every alive tracee
/// keeps their index once allocated and releases it back into the vec + hashmap
/// when tracee exits.
pub const SHARED_MMAP_SIZE: usize = MAX_NUM_TRACEES * STACK_SAFE_ZONE_SIZE;

/// Max number of total structs in the entire shared mmap
// pub const MAX_NUM_STRUCTS: usize = SHARED_MMAP_SIZE / MAX_STRUCT_SIZE;

/// Max number of total structs in the an individual region of shared mmap
// pub const MAX_NUM_STRUCTS_PER_TRACEE: usize = STACK_SAFE_ZONE_SIZE / MAX_STRUCT_SIZE;

#[cfg(not(any(target_env = "gnu")))]
pub const PTRACE_GETEVENTMSG: i32 = libc::PTRACE_GETEVENTMSG as i32;

#[cfg(any(target_env = "gnu"))]
pub const PTRACE_GETEVENTMSG: u32 = sys::ptrace::Request::PTRACE_GETEVENTMSG as u32;

#[cfg(not(any(target_env = "gnu")))]
pub const PTRACE_GETREGSET: i32 = libc::PTRACE_GETREGSET as i32;

#[cfg(any(target_env = "gnu"))]
pub const PTRACE_GETREGSET: u32 = sys::ptrace::Request::PTRACE_GETREGSET as u32;

#[cfg(not(any(target_env = "gnu")))]
pub const PTRACE_SETREGSET: i32 = libc::PTRACE_SETREGSET as i32;

#[cfg(any(target_env = "gnu"))]
pub const PTRACE_SETREGSET: u32 = sys::ptrace::Request::PTRACE_SETREGSET as u32;

// Used by aarch64 and arm to set system call number. Does not exist in rust libc
#[cfg(all(not(target_env = "gnu"), target_arch = "aarch64"))]
pub const NT_ARM_SYSTEM_CALL: i32 = 0x404;

// Used by aarch64 and arm to set system call number. Does not exist in rust libc
#[cfg(all(target_env = "gnu", target_arch = "aarch64"))]
pub const NT_ARM_SYSTEM_CALL: u32 = 0x404;

// Used by aarch64 and arm to set system call number. Does not exist in rust libc
#[cfg(all(not(target_env = "gnu"), target_arch = "arm"))]
pub const NT_ARM_SYSTEM_CALL: i32 = 0x404;

// Used by aarch64 and arm to set system call number. Does not exist in rust libc
#[cfg(all(target_env = "gnu", target_arch = "arm"))]
pub const NT_ARM_SYSTEM_CALL: u32 = 0x404;

/// To help us index the structs within a tracee's own mmap region
pub type SharedRegionContent = [u8; STACK_SAFE_ZONE_SIZE];
pub type SharedRegions = [RwLock<Option<Box<SharedRegionContent>>>; MAX_NUM_TRACEES];

pub const USIZE_SIZE: usize = std::mem::size_of::<usize>();

lazy_static! {
    // The actual shared regions will be initialized in start() in lib.rs
    pub static ref SHARED_REGIONS: SharedRegions = core::array::from_fn(|_| RwLock::new(None));

    pub static ref AVAILABLE_REGION_IDS: RwLock<Vec<usize>> = RwLock::new((0..MAX_NUM_TRACEES).collect());

    pub static ref REGION_IDS_BY_PID: RwLock<HashMap<Pid, usize>> = RwLock::new(HashMap::new());
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub type NixISize = i64;

#[cfg(any(target_arch = "x86", target_arch = "arm"))]
pub type NixISize = i32;

#[derive(Debug, Error)]
pub enum PtraceError {
    #[error("Failed to run the command specified in --cmd: {0}")]
    StartInitCmd(nix::Error),

    #[error("Failed to run the command specified in --cmd: {0}")]
    InitCmdFailed(std::io::Error),

    #[error("Failed to parse pid {0}: {1}")]
    ParsePid(u64, <u64 as TryInto<libc::pid_t>>::Error),

    #[error("Failed to parse usize {0:#x}: {1}")]
    ParseUsize(i64, <i64 as TryInto<usize>>::Error),

    #[error("Failed to parse usize from {0}")]
    ParseUsizeFromString(String),

    #[error("PTRACE_GETEVENTMSG error: {0}")]
    GetEventMsg(nix::Error),

    #[error("Cannot get tracee's CPU registers: {0}")]
    GetRegs(nix::Error),

    #[error("Cannot set tracee's CPU registers: {0}")]
    SetRegs(nix::Error),

    #[error("Cannot read tracee memory: {0}")]
    Read(nix::Error),

    #[error("Cannot read tracee memory: {0}")]
    ReadStdIoError(std::io::Error),

    #[error("Cannot read tracee memory: could not find memory file to read from")]
    ReadMmapNotFound,

    #[error("Cannot read tracee memory of size {0} (not aligned)")]
    ReadItemNotAligned(usize),

    #[error("Cannot read tracee memory: item too big: {0} > {1}")]
    ReadItemTooBig(usize, usize),

    #[error("Cannot read tracee memory: header too big: {1} > {0}")]
    ReadInvalidItemSize1(usize, usize),

    #[error("Accessing tracee memory: buffer overflow: {1:#x} + {0} > {2:#x}")]
    BufferOverflow(usize, usize, usize),

    #[error("Accessing tracee memory: buffer underflow: {0:#x} < {1:#x}")]
    BufferUnderflow(usize, usize),

    #[error("Accessing tracee memory: object header is too big: {0} > {1}")]
    HeaderTooBig(usize, usize),

    #[error("Accessing tracee memory: failed to convert pointers")]
    Pointer,

    #[error("Cannot write tracee memory: {0}")]
    Write(nix::Error),

    #[error("Cannot write tracee memory of offset {0} (not aligned)")]
    WriteOffsetNotAligned(usize),

    #[error("Failed to wait/waitpid for tracee: {0}")]
    Waitpid(nix::Error),

    #[error("Integer overflow: {0} {1} {2}")]
    IntOverflow(usize, &'static str, usize),

    #[error("Integer {0} is zero")]
    IntIsZero(&'static str),

    #[error("Integer too big: {0} >= {1}")]
    IntTooBigEqual(usize, usize),

    #[error("Failed to convert integert types for {0}")]
    IntoInt(&'static str),

    #[error("Cannot create linux memfd: {0}")]
    CreateMemoryFile(nix::Error),

    #[error("Cannot lock/unlock global mmap")]
    LockGlobalMmap,

    #[error("Tracee side of shared mmap is not initialized")]
    MmapUninitialized,

    #[error("Cannot unmap memory: {0}")]
    Unmap(nix::Error),

    #[error("Reached the maximum limit on the number of tracees")]
    MaxTracee,
}

pub trait CHeader {
    /// See read_bytes_to_structs
    fn item_size_deducer(&self) -> usize;

    /// See structs_to_tracee_buffer
    fn item_size_updater(&mut self, _size: usize);
}

pub trait CStruct {
    type H: CHeader;
}

/// To faciliate the swapping of memory implementation (slow ptrace calls vs direct mmap)
#[derive(Clone, Debug)]
pub struct MemHelpers {
    /// Closes any shared resources created for a tracee
    pub close_tracee: for<'a> fn(&'a nix::unistd::Pid) -> Result<(), PtraceError>,

    /// params (pid, addr) returns the usize at the read
    pub read: fn(nix::unistd::Pid, usize) -> Result<usize, PtraceError>,
    /// params (pid, addr, size, result_buffer) returns nothing
    pub read_bytes: fn(nix::unistd::Pid, usize, usize, &mut [u8]) -> Result<(), PtraceError>,
    /// params (pid, addr, num_zeroes) returns the usizes
    pub read_bytes_until_num_zeroes:
        fn(nix::unistd::Pid, usize, usize) -> Result<Vec<u8>, PtraceError>,
    /// params (pid, addr) returns the usizes
    pub read_bytes_until_zero: fn(nix::unistd::Pid, usize) -> Result<Vec<u8>, PtraceError>,

    /// params (pid, offset, bytes) returns (start, new_offset)
    pub write_bytes_to_tracee:
        unsafe fn(nix::unistd::Pid, usize, &[u8]) -> Result<(usize, usize), PtraceError>,
    // Note: read_bytes_to_structs, write_structs_to_tracee are not here because they use Generics
    // Note: write_structs_to_tracee is true random write, which is always slow and implemented below
}

impl Default for MemHelpers {
    fn default() -> Self {
        mem_slow::SLOW_MEM_HELPERS
    }
}

// Helper used by write_structs_to_tracee
pub fn write(pid: nix::unistd::Pid, addr: usize, value: usize) -> Result<(), PtraceError> {
    event!(Level::TRACE, "PTRACE_WRITE addr: {:x}", addr);
    sys::ptrace::write(pid, addr as *mut libc::c_void, value as NixISize)
        .map_err(PtraceError::Write)?;
    Ok(())
}

// Helper used by write_structs_to_tracee
fn checked_write(
    pid: nix::unistd::Pid,
    addr: usize,
    overflow_addr: usize,
    value: usize,
) -> Result<(), PtraceError> {
    if addr >= overflow_addr {
        Err(PtraceError::BufferOverflow(0, addr, overflow_addr))
    } else {
        write(pid, addr, value)
    }
}

/// Read multiple Rust "repr(C)" structures from tracee memory.
/// Here is an explannation:
///
/// C struct layout    [ ..int.. ..char*.. (up to 512 chars)         ]
/// Rust struct layout [ ..int.. ..[char; 512].. (exactly 512 chars) ]
///
/// Notes about terminology:
///     "C struct" just means the original in-memory data.
///     "Rust struct" just means the result of the read. It must still declare #[repr(C)]
///
/// The function returns values in the layout of Rust structs, not C structs.
///
/// Input arguments:
///     T: Rust version of the C structure
///     T::H: Rust version of the header part of the C structure, which should
///                  contain enough information for item_size_deducer to deduce
///                  item_size of this specific structure.
///     item_size: the size of one of the C structure, in syscall layout
///     item_size_deducer: This function will receive T::H,
///                        which only contains the header information. The remaining
///                        information is instantiated as if their byte representations
///                        were zeroed out. This function should return the item_size
///     total_size: The number of bytes representing the entire list of C structures,
///                 as seen in tracee memory.
///     mem_helpers: The implementation of MemHelpers to use
///
/// Note: The Rust struct must align to the size of machine word:
///             sizeof(T) % sizeof(usize) == 0
///       Otherwise, this function will fail with ReadItemNotAligned
///
/// Note: If Rust struct didn't reserve enough space for item_size, this function will
///       fail with ReadItemTooBig.
///
/// Note: This function reserves a buffer of MAX_STRUCT_SIZE bytes to represent T. If T is bigger,
///       it will fail with ReadItemTooBig.
///
/// Note: If item_size_deducer returns a value smaller than sizeof(T::H), this function
///       will fail with ReadInvalidItemSize1.
///
/// Note: If item_size_deducer returns a value too big for total_size, this function
///       will fail with BufferOverflow.
///
/// Note: Any pointer conversion failure will be reported as Pointer
pub fn read_bytes_to_structs<T>(
    pid: nix::unistd::Pid,
    addr: usize,
    total_size: usize,
    mem_helpers: MemHelpers,
) -> Result<Vec<T>, PtraceError>
where
    T: Sized + Clone + CStruct,
{
    let mut result: Vec<T> = Vec::new();
    let mut curr_addr = addr;
    let final_addr = checked_add(addr, total_size)?;
    let t_size = std::mem::size_of::<T>();
    let header_size = std::mem::size_of::<T::H>();
    if t_size % USIZE_SIZE != 0 {
        return Err(PtraceError::ReadItemNotAligned(t_size));
    }
    if t_size > MAX_STRUCT_SIZE {
        return Err(PtraceError::ReadItemTooBig(t_size, MAX_STRUCT_SIZE));
    }
    if t_size < header_size {
        return Err(PtraceError::HeaderTooBig(header_size, t_size));
    }

    while curr_addr < final_addr {
        let mut buffer = [0_u8; MAX_STRUCT_SIZE];
        let header: &T::H = unsafe {
            (buffer.as_ptr() as *const T::H)
                .as_ref()
                .ok_or(PtraceError::Pointer)?
        };
        let item: &T = unsafe {
            (buffer.as_ptr() as *const T)
                .as_ref()
                .ok_or(PtraceError::Pointer)?
        };

        // Read header
        if checked_add(curr_addr, header_size)? > final_addr {
            return Err(PtraceError::BufferOverflow(
                header_size,
                curr_addr,
                final_addr,
            ));
        }
        (mem_helpers.read_bytes)(pid, curr_addr, header_size, &mut buffer[..])?;
        curr_addr = checked_add(curr_addr, header_size)?;

        // Deduce item_size, remainder_size
        let item_size = header.item_size_deducer();
        let remainder_size = item_size - header_size;
        if item_size < header_size {
            return Err(PtraceError::ReadInvalidItemSize1(item_size, header_size));
        }
        if item_size > t_size {
            return Err(PtraceError::ReadItemTooBig(item_size, t_size));
        }
        if checked_add(curr_addr, remainder_size)? > final_addr {
            return Err(PtraceError::BufferOverflow(
                remainder_size,
                curr_addr,
                final_addr,
            ));
        }

        // Read remainder of item
        (mem_helpers.read_bytes)(pid, curr_addr, remainder_size, &mut buffer[header_size..])?;
        curr_addr = checked_add(curr_addr, remainder_size)?;

        // Save item to result
        result.push(item.clone());
    }
    Ok(result)
}

pub fn read_bytes_to_fixed_sized_objs<T>(
    pid: nix::unistd::Pid,
    addr: usize,
    num_objs: usize,
    mem_helpers: MemHelpers,
) -> Result<Vec<T>, PtraceError>
where
    T: Sized + Clone,
{
    let mut result: Vec<T> = Vec::new();
    let mut curr_addr = addr;
    let t_size = std::mem::size_of::<T>();
    let total_size = checked_mul(t_size, num_objs)?;
    let final_addr = checked_add(addr, total_size)?;
    if t_size % USIZE_SIZE != 0 {
        return Err(PtraceError::ReadItemNotAligned(t_size));
    }
    if t_size > MAX_STRUCT_SIZE {
        return Err(PtraceError::ReadItemTooBig(t_size, MAX_STRUCT_SIZE));
    }

    while curr_addr < final_addr {
        let mut buffer = [0_u8; MAX_STRUCT_SIZE];
        let item: &T = unsafe {
            (buffer.as_ptr() as *const T)
                .as_ref()
                .ok_or(PtraceError::Pointer)?
        };

        (mem_helpers.read_bytes)(pid, curr_addr, t_size, &mut buffer)?;
        curr_addr = checked_add(curr_addr, t_size)?;

        // Save item to result
        result.push(item.clone());
    }
    Ok(result)
}

/// Write multiple "repr(C)" structs back to tracee memory.
/// Here is an explannation:
///
/// C struct layout    [ ..int.. ..char*.. (up to 512 chars)         ]
/// Rust struct layout [ ..int.. ..[char; 512].. (exactly 512 chars) ]
///
/// Notes about terminology:
///     "C struct" just means the native in-memory data.
///     "Rust struct" just means the source data in Rust. It must still declare #[repr(C)]
///
/// The function consumes a list of T objects, and writes them out as structs in
/// syscall layouts, by shrinking down the size of T structs, whenever there are
/// too many repeated recurrances of zeroed bytes.
///
/// Input arguments:
///     T: Rust version of the C structure
///     T::H: Rust version of the header part of the C structure, which should
///                  contain a field representing the size of the C structure
///                  itself. Bytes in the header part of the structure will never
///                  be shrunk (see shrink_criteria).
///     shrink_criteria: how many words of consecutive zeroes must be seen before
///                      the remaining consecutive zeroes will be deleted. One word
///                      is the same size as one usize integer. Bytes in T::H will
///                      never be shrunk.
///     item_size_updater: This closure will receive T::H, which is the header part of
///                        the T object, and also receive the correct size after
///                        T is shrunk to syscall format. This closure must update
///                        the correct field in T::H to reflect the change in size.
///                        (Usually this is the `size` field in the structure itself)
///     buffer_size: The maximum number of bytes that can be safely written to
///                  tracee's buffer.
///
/// Returns: Number of bytes written
///
/// Note: The Rust struct must align to the size of machine word:
///             sizeof(T) % sizeof(usize) == 0
///       Otherwise, this function will fail with ReadItemNotAligned
///
/// Note: This function reserves a buffer of MAX_STRUCT_SIZE bytes to represent T. If T is bigger,
///       it will fail with ReadItemTooBig.
///
/// Note: Any pointer conversion failure will be reported as Pointer
pub fn write_structs_to_tracee<T>(
    pid: nix::unistd::Pid,
    addr: usize,
    buffer_size: usize,
    mut items: Vec<T>,
    shrink_criteria: usize,
) -> Result<usize, PtraceError>
where
    T: Sized + CStruct,
{
    event!(
        Level::TRACE,
        "Writing ~{} bytes to tracee buffer, {:#x}",
        buffer_size,
        addr
    );
    let mut curr_addr = addr;
    let max_addr = checked_add(addr, buffer_size)?;
    let t_size = std::mem::size_of::<T>();
    let header_size = std::mem::size_of::<T::H>();
    if t_size % USIZE_SIZE != 0 {
        return Err(PtraceError::ReadItemNotAligned(t_size));
    }
    if t_size > MAX_STRUCT_SIZE {
        return Err(PtraceError::ReadItemTooBig(t_size, MAX_STRUCT_SIZE));
    }
    if t_size < header_size {
        return Err(PtraceError::HeaderTooBig(header_size, t_size));
    }
    let skip_header = checked_div(aligned(header_size)?, USIZE_SIZE)?;
    let skip_header_bytes = checked_mul(skip_header, USIZE_SIZE)?;

    for item in items.iter_mut() {
        let mut curr_remainder_addr = checked_add(curr_addr, skip_header_bytes)?;
        let buffer: &mut [usize] = unsafe {
            let ptr = item as *mut T as *mut usize;
            let len = t_size / USIZE_SIZE;
            std::slice::from_raw_parts_mut(ptr, len)
        };
        let header: &mut T::H = unsafe {
            (buffer.as_mut_ptr() as *mut T::H)
                .as_mut()
                .ok_or(PtraceError::Pointer)?
        };
        if curr_remainder_addr > max_addr {
            return Err(PtraceError::BufferOverflow(
                skip_header_bytes,
                curr_addr,
                max_addr,
            ));
        }

        // Remove excess zeroes and write T without writing T::H
        let mut count_zeroes: usize = 0;
        let mut skipped_zeroes: usize = 0;
        for machine_word in buffer.iter().skip(skip_header) {
            if *machine_word == 0 {
                count_zeroes = checked_add(count_zeroes, 1)?;
                if count_zeroes > shrink_criteria {
                    skipped_zeroes = checked_add(skipped_zeroes, 1)?;
                    continue;
                }
            } else {
                count_zeroes = 0;
            }
            checked_write(pid, curr_remainder_addr, max_addr, *machine_word)?;
            curr_remainder_addr = checked_add(curr_remainder_addr, USIZE_SIZE)?;
        }

        // Update T::H and write T::H
        if skipped_zeroes > 0 {
            header.item_size_updater(checked_sub(t_size, skipped_zeroes * USIZE_SIZE)?);
        }
        for machine_word in buffer.iter().take(skip_header) {
            write(pid, curr_addr, *machine_word)?;
            curr_addr = checked_add(curr_addr, USIZE_SIZE)?;
        }
        curr_addr = curr_remainder_addr;
    }
    Ok(curr_addr - addr)
}

pub fn write_fixed_sized_objs_to_tracee<T>(
    pid: nix::unistd::Pid,
    addr: usize,
    buffer_size: usize,
    items: Vec<T>,
) -> Result<usize, PtraceError>
where
    T: Sized,
{
    event!(
        Level::TRACE,
        "Writing ~{} bytes to tracee buffer, {:#x}",
        buffer_size,
        addr
    );
    let mut curr_addr = addr;
    let max_addr = checked_add(addr, buffer_size)?;
    let t_size = std::mem::size_of::<T>();
    if t_size % USIZE_SIZE != 0 {
        return Err(PtraceError::ReadItemNotAligned(t_size));
    }
    if t_size > MAX_STRUCT_SIZE {
        return Err(PtraceError::ReadItemTooBig(t_size, MAX_STRUCT_SIZE));
    }

    for item in items.iter() {
        let buffer: &[usize] = unsafe {
            let ptr = item as *const T as *const usize;
            let len = t_size / USIZE_SIZE;
            std::slice::from_raw_parts(ptr, len)
        };
        if curr_addr + t_size > max_addr {
            return Err(PtraceError::BufferOverflow(t_size, curr_addr, max_addr));
        }

        for machine_word in buffer.iter() {
            write(pid, curr_addr, *machine_word)?;
            curr_addr = checked_add(curr_addr, USIZE_SIZE)?;
        }
    }
    Ok(curr_addr - addr)
}

/// For Android, See https://android.googlesource.com/platform/prebuilts/ndk/+/1b55d7b281f282232ee58da5d09d3da5969ff11d/9/platforms/android-19/arch-arm64/usr/include/sys/user.h
/// https://android.googlesource.com/kernel/common/+/60ffc30d5652810dd34ea2eec41504222f5d5791/arch/arm64/include/asm/ptrace.h (user_pt_regs)
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone)]
#[repr(C)]
#[allow(dead_code)]
pub struct GenericPurposeRegs {
    pub arg0: usize,
    pub arg1: usize,
    pub arg2: usize,
    pub arg3: usize,
    pub arg4: usize,
    pub arg5: usize,
    pub arg6: usize,
    unknown_x7: usize,
    /// on arm, this is the only syscall register. But tracer CANNOT use it alone to replace syscall.
    pub reg_x8: usize,
    unknown_x9: usize,
    unknown_x10: usize,
    unknown_x11: usize,
    unknown_x12: usize,
    unknown_x13: usize,
    unknown_x14: usize,
    unknown_x15: usize,
    unknown_x16: usize,
    unknown_x17: usize,
    unknown_x18: usize,
    unknown_x19: usize,
    unknown_x20: usize,
    unknown_x21: usize,
    unknown_x22: usize,
    unknown_x23: usize,
    unknown_x24: usize,
    unknown_x25: usize,
    unknown_x26: usize,
    unknown_x27: usize,
    unknown_x28: usize,
    unknown_x29: usize,
    unknown_x30: usize,
    pub sp: usize,
    pub pc: usize,
    pstate: usize,
}

#[cfg(target_arch = "arm")]
#[derive(Debug, Clone)]
#[repr(C)]
#[allow(dead_code)]
pub struct GenericPurposeRegs {
    pub arg0: usize,
    pub arg1: usize,
    pub arg2: usize,
    pub arg3: usize,
    pub arg4: usize,
    pub arg5: usize,
    pub arg6: usize,
    /// on arm, this is the only syscall register. But tracer CANNOT use it alone to replace syscall.
    pub reg_r7: usize,
    unknown_x8: usize,
    unknown_x9: usize,
    unknown_x10: usize,
    unknown_x11: usize,
    unknown_x12: usize,
    pub sp: usize,
    unknown_x14: usize,
    pub pc: usize,
    unknown_x16: usize,
    pub orig_r0: usize,
}

// https://man7.org/linux/man-pages/man2/syscall.2.html
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone)]
#[repr(C)]
#[allow(dead_code)]
pub struct GenericPurposeRegs {
    unknown_x1: usize,
    unknown_x2: usize,
    unknown_x3: usize,
    unknown_x4: usize,
    unknown_x5: usize,
    unknown_x6: usize,
    unknown_x7: usize,
    pub arg3: usize,
    pub arg5: usize,
    pub arg4: usize,
    // "rax"
    rax: usize,
    unknown_x12: usize,
    pub arg2: usize,
    pub arg1: usize,
    pub arg0: usize,
    /// On x86_64 this is "original syscall number". It CANNOT be used to set the next syscall
    orig_rax: usize,
    pub pc: usize,
    unknown_x18: usize,
    unknown_x19: usize,
    pub sp: usize,
    unknown_x21: usize,
    unknown_x22: usize,
    unknown_x23: usize,
    unknown_x24: usize,
    unknown_x25: usize,
    unknown_x26: usize,
    unknown_x27: usize,
}

#[cfg(target_arch = "aarch64")]
impl GenericPurposeRegs {
    pub fn syscall_retval(&self) -> usize {
        self.arg0
    }

    pub fn set_syscall_retval(&mut self, val: usize) {
        event!(Level::INFO, "Setting return value: {}", val);
        self.arg0 = val
    }

    pub fn syscall_num(&self) -> usize {
        self.reg_x8
    }
}

#[cfg(target_arch = "arm")]
impl GenericPurposeRegs {
    pub fn syscall_retval(&self) -> usize {
        self.arg0
    }

    pub fn set_syscall_retval(&mut self, val: usize) {
        event!(Level::INFO, "Setting return value: {}", val);
        self.arg0 = val
    }

    pub fn syscall_num(&self) -> usize {
        self.reg_r7
    }
}

#[cfg(target_arch = "x86_64")]
impl GenericPurposeRegs {
    pub fn syscall_retval(&self) -> usize {
        self.rax
    }

    pub fn set_syscall_retval(&mut self, val: usize) {
        event!(Level::INFO, "Setting return value: {}", val);
        self.rax = val
    }

    pub fn syscall_num(&self) -> usize {
        self.orig_rax
    }

    pub fn next_syscall(&self) -> usize {
        self.rax
    }

    pub fn set_next_syscall(&mut self, val: usize) {
        self.orig_rax = val;
        self.rax = val;
    }
}

/// Use this as reference: https://android.googlesource.com/platform/system/core/+/59d16c9e9171f4367ad3a0516e7000c0d95e89cf/debuggerd/arm64/machine.cpp
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub fn getregs(pid: nix::unistd::Pid) -> Result<GenericPurposeRegs, PtraceError> {
    let mut data = std::mem::MaybeUninit::uninit();
    let res = unsafe {
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr() as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<GenericPurposeRegs>(),
        };
        libc::ptrace(
            PTRACE_GETREGSET,
            libc::pid_t::from(pid),
            NT_PRSTATUS as *mut libc::c_void,
            &mut iov as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::GetRegs)?;
    Ok(unsafe { data.assume_init() })
}

/// Use this as reference: https://android.googlesource.com/platform/prebuilts/ndk/+/refs/heads/lollipop-dev/9/platforms/android-5/arch-arm/usr/include/asm/ptrace.h
#[cfg(target_arch = "arm")]
pub fn getregs(pid: nix::unistd::Pid) -> Result<GenericPurposeRegs, PtraceError> {
    let mut data = std::mem::MaybeUninit::uninit();
    let res = unsafe {
        libc::ptrace(
            // PTRACE_GETREGS
            12,
            libc::pid_t::from(pid),
            std::ptr::null_mut::<i32>(),
            data.as_mut_ptr() as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::GetRegs)?;
    Ok(unsafe { data.assume_init() })
}

/// Use this as reference: https://android.googlesource.com/platform/system/core/+/59d16c9e9171f4367ad3a0516e7000c0d95e89cf/debuggerd/arm64/machine.cpp
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub fn setregs(pid: nix::unistd::Pid, mut data: GenericPurposeRegs) -> Result<(), PtraceError> {
    event!(
        Level::TRACE,
        "setregs, syscall {:#x} args {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}",
        data.syscall_num(),
        data.arg0,
        data.arg1,
        data.arg2,
        data.arg3,
        data.arg4,
        data.arg5
    );
    let res = unsafe {
        let mut iov = libc::iovec {
            iov_base: &mut data as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<GenericPurposeRegs>(),
        };
        libc::ptrace(
            PTRACE_SETREGSET,
            libc::pid_t::from(pid),
            NT_PRSTATUS as *mut libc::c_void,
            &mut iov as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::SetRegs)?;
    Ok(())
}

/// Use this as reference: https://android.googlesource.com/platform/prebuilts/ndk/+/refs/heads/lollipop-dev/9/platforms/android-5/arch-arm/usr/include/asm/ptrace.h
#[cfg(target_arch = "arm")]
pub fn setregs(pid: nix::unistd::Pid, mut data: GenericPurposeRegs) -> Result<(), PtraceError> {
    event!(
        Level::TRACE,
        "setregs, syscall {:#x} args {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}",
        data.syscall_num(),
        data.arg0,
        data.arg1,
        data.arg2,
        data.arg3,
        data.arg4,
        data.arg5
    );
    let res = unsafe {
        libc::ptrace(
            13,
            libc::pid_t::from(pid),
            std::ptr::null_mut::<i32>(),
            &mut data as *mut _ as *mut libc::c_void,
        )
    };
    nix::errno::Errno::result(res).map_err(PtraceError::SetRegs)?;
    Ok(())
}

#[inline]
pub fn checked_add(a: usize, b: usize) -> Result<usize, PtraceError> {
    a.checked_add(b).ok_or(PtraceError::IntOverflow(a, "+", b))
}

#[inline]
pub fn checked_sub(a: usize, b: usize) -> Result<usize, PtraceError> {
    a.checked_sub(b).ok_or(PtraceError::IntOverflow(a, "-", b))
}

#[inline]
pub fn checked_mul(a: usize, b: usize) -> Result<usize, PtraceError> {
    a.checked_mul(b).ok_or(PtraceError::IntOverflow(a, "*", b))
}

#[inline]
pub fn checked_div(a: usize, b: usize) -> Result<usize, PtraceError> {
    a.checked_div(b).ok_or(PtraceError::IntOverflow(a, "*", b))
}

pub fn bytes_to_usizes(bytes: &[u8]) -> Result<Vec<usize>, PtraceError> {
    let mut result: Vec<usize> = Vec::new();
    let iter = bytes.chunks_exact(USIZE_SIZE);
    for chunk in iter {
        result.push(usize::from_ne_bytes(chunk.try_into().unwrap()));
    }

    let remainder_pos = checked_mul(result.len(), USIZE_SIZE)?;
    let mut remainder_vec: Vec<u8> = Vec::new();
    remainder_vec.resize(USIZE_SIZE, 0);

    for (i, byte) in bytes.iter().skip(remainder_pos).enumerate() {
        remainder_vec[i] = *byte;
    }
    result.push(usize::from_ne_bytes(
        (&remainder_vec[..]).try_into().unwrap(),
    ));
    Ok(result)
}

pub fn aligned(val: usize) -> Result<usize, PtraceError> {
    let num_usizes = checked_div(checked_sub(checked_add(val, USIZE_SIZE)?, 1)?, USIZE_SIZE)?;
    checked_mul(num_usizes, USIZE_SIZE)
}

#[cfg(target_arch = "aarch64")]
#[cfg(test)]
mod tests {
    use crate::common;

    #[test]
    fn test_convert_bytes_to_usizes_exact() {
        let bytes: &[u8] = b"abcdefghijklmnop";
        let _expect: Vec<usize> = vec![7523094288207667809, 8101815670912281193];
        assert!(matches!(common::bytes_to_usizes(bytes), Ok(_expect)));
    }

    #[test]
    fn test_convert_bytes_to_usizes_remainder() {
        let bytes: &[u8] = b"abcdefghijklmnop9";
        let _expect: Vec<usize> = vec![7523094288207667809, 8101815670912281193, 57];
        assert!(matches!(common::bytes_to_usizes(bytes), Ok(_expect)));
    }
}
