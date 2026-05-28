use crate::winapi::CloseHandle;
use crate::winapi::GetThreadContext;
use crate::winapi::HANDLE;
use crate::winapi::OpenThread;
use crate::winapi::ResumeThread;
use crate::winapi::SetThreadContext;
use crate::winapi::SuspendThread;
use thiserror::Error;

pub const THREAD_SUSPEND_RESUME: u32 = 0x0002;
pub const THREAD_GET_CONTEXT: u32 = 0x0008;
pub const THREAD_SET_CONTEXT: u32 = 0x0010;
pub const THREAD_QUERY_INFORMATION: u32 = 0x0040;
pub const HARDWARE_BREAKPOINT_THREAD_ACCESS: u32 =
    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION;

#[cfg(target_arch = "x86_64")]
const CONTEXT_DEBUG_REGISTERS: u32 = 0x0010_0010;
#[cfg(target_arch = "x86")]
const CONTEXT_DEBUG_REGISTERS: u32 = 0x0001_0010;

#[derive(Error, Debug)]
pub enum HardwareBreakpointError {
    #[error("Invalid thread handle")]
    InvalidThreadHandle,

    #[error("Failed to open thread: {0}")]
    OpenThreadError(u32),

    #[error("Failed to suspend thread")]
    SuspendThreadError,

    #[error("Failed to get thread context")]
    GetThreadContextError,

    #[error("Failed to set thread context")]
    SetThreadContextError,

    #[error("Execution breakpoints must use one-byte length")]
    InvalidExecutionSize,

    #[error("Address is not aligned for breakpoint size")]
    UnalignedAddress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareBreakpointSlot {
    Dr0,
    Dr1,
    Dr2,
    Dr3,
}

impl HardwareBreakpointSlot {
    #[inline]
    pub const fn index(self) -> usize {
        match self {
            Self::Dr0 => 0,
            Self::Dr1 => 1,
            Self::Dr2 => 2,
            Self::Dr3 => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareBreakpointCondition {
    Execute,
    Write,
    ReadWrite,
}

impl HardwareBreakpointCondition {
    #[inline]
    const fn dr7_bits(self) -> u64 {
        match self {
            Self::Execute => 0b00,
            Self::Write => 0b01,
            Self::ReadWrite => 0b11,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareBreakpointSize {
    One,
    Two,
    Four,
    Eight,
}

impl HardwareBreakpointSize {
    #[inline]
    const fn bytes(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
            Self::Eight => 8,
        }
    }

    #[inline]
    const fn dr7_bits(self) -> u64 {
        match self {
            Self::One => 0b00,
            Self::Two => 0b01,
            Self::Four => 0b11,
            Self::Eight => 0b10,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HardwareBreakpointOptions {
    pub suspend_thread: bool,
}

impl Default for HardwareBreakpointOptions {
    fn default() -> Self {
        Self {
            suspend_thread: true,
        }
    }
}

pub struct HardwareBreakpointEntry {
    thread: HANDLE,
    owns_thread: bool,
    address: *mut u8,
    slot: HardwareBreakpointSlot,
    condition: HardwareBreakpointCondition,
    size: HardwareBreakpointSize,
    suspend_thread: bool,
    enabled: bool,
    original_address: u64,
    original_dr7_bits: u64,
}

impl HardwareBreakpointEntry {
    pub fn new(
        thread: HANDLE,
        address: *mut u8,
        slot: HardwareBreakpointSlot,
        condition: HardwareBreakpointCondition,
        size: HardwareBreakpointSize,
    ) -> Result<Self, HardwareBreakpointError> {
        Self::with_options(
            thread,
            address,
            slot,
            condition,
            size,
            HardwareBreakpointOptions::default(),
        )
    }

    pub fn with_options(
        thread: HANDLE,
        address: *mut u8,
        slot: HardwareBreakpointSlot,
        condition: HardwareBreakpointCondition,
        size: HardwareBreakpointSize,
        options: HardwareBreakpointOptions,
    ) -> Result<Self, HardwareBreakpointError> {
        validate_breakpoint(address, condition, size)?;

        if thread.is_null() {
            return Err(HardwareBreakpointError::InvalidThreadHandle);
        }

        let context = read_context(thread, options.suspend_thread)?;
        let original_address = context.debug_register(slot);
        let original_dr7_bits = dr7_slot_bits(context.dr7(), slot);

        Ok(Self {
            thread,
            owns_thread: false,
            address,
            slot,
            condition,
            size,
            suspend_thread: options.suspend_thread,
            enabled: false,
            original_address,
            original_dr7_bits,
        })
    }

    pub fn from_thread_id(
        thread_id: u32,
        address: *mut u8,
        slot: HardwareBreakpointSlot,
        condition: HardwareBreakpointCondition,
        size: HardwareBreakpointSize,
    ) -> Result<Self, HardwareBreakpointError> {
        let thread = unsafe { OpenThread(HARDWARE_BREAKPOINT_THREAD_ACCESS, 0, thread_id) };
        if thread.is_null() {
            return Err(HardwareBreakpointError::OpenThreadError(thread_id));
        }

        let mut entry = Self::new(thread, address, slot, condition, size)?;
        entry.owns_thread = true;
        Ok(entry)
    }

    pub unsafe fn toggle(&mut self) -> Result<(), HardwareBreakpointError> {
        if self.enabled {
            self.disable()
        } else {
            self.enable()
        }
    }

    pub unsafe fn enable(&mut self) -> Result<(), HardwareBreakpointError> {
        update_context(self.thread, self.suspend_thread, |context| {
            context.set_debug_register(self.slot, self.address as u64);
            context.set_dr7(encode_dr7_slot(
                context.dr7(),
                self.slot,
                self.condition.dr7_bits(),
                self.size.dr7_bits(),
            ));
            context.set_dr6(0);
        })?;

        self.enabled = true;
        Ok(())
    }

    pub unsafe fn disable(&mut self) -> Result<(), HardwareBreakpointError> {
        update_context(self.thread, self.suspend_thread, |context| {
            context.set_debug_register(self.slot, self.original_address);
            context.set_dr7(restore_dr7_slot(
                context.dr7(),
                self.slot,
                self.original_dr7_bits,
            ));
        })?;

        self.enabled = false;
        Ok(())
    }

    #[inline]
    pub fn is_enabled(&self) -> bool { self.enabled }

    #[inline]
    pub fn thread(&self) -> HANDLE { self.thread }

    #[inline]
    pub fn address(&self) -> *mut u8 { self.address }

    #[inline]
    pub fn slot(&self) -> HardwareBreakpointSlot { self.slot }
}

impl Drop for HardwareBreakpointEntry {
    fn drop(&mut self) {
        if self.enabled {
            let _ = unsafe { self.disable() };
        }

        if self.owns_thread && !self.thread.is_null() {
            unsafe {
                CloseHandle(self.thread);
            }
        }
    }
}

struct ThreadSuspendGuard {
    thread: HANDLE,
    active: bool,
}

impl ThreadSuspendGuard {
    fn new(thread: HANDLE, active: bool) -> Result<Self, HardwareBreakpointError> {
        if active && unsafe { SuspendThread(thread) } == u32::MAX {
            return Err(HardwareBreakpointError::SuspendThreadError);
        }

        Ok(Self { thread, active })
    }
}

impl Drop for ThreadSuspendGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                ResumeThread(self.thread);
            }
        }
    }
}

fn read_context(
    thread: HANDLE,
    suspend_thread: bool,
) -> Result<DebugRegisterContext, HardwareBreakpointError> {
    let _guard = ThreadSuspendGuard::new(thread, suspend_thread)?;
    let mut context = DebugRegisterContext::default();
    context.set_context_flags(CONTEXT_DEBUG_REGISTERS);

    if unsafe { GetThreadContext(thread, context.as_context_mut()) } == 0 {
        return Err(HardwareBreakpointError::GetThreadContextError);
    }

    Ok(context)
}

fn update_context(
    thread: HANDLE,
    suspend_thread: bool,
    update: impl FnOnce(&mut DebugRegisterContext),
) -> Result<(), HardwareBreakpointError> {
    let _guard = ThreadSuspendGuard::new(thread, suspend_thread)?;
    let mut context = DebugRegisterContext::default();
    context.set_context_flags(CONTEXT_DEBUG_REGISTERS);

    if unsafe { GetThreadContext(thread, context.as_context_mut()) } == 0 {
        return Err(HardwareBreakpointError::GetThreadContextError);
    }

    update(&mut context);
    context.set_context_flags(CONTEXT_DEBUG_REGISTERS);

    if unsafe { SetThreadContext(thread, context.as_context()) } == 0 {
        return Err(HardwareBreakpointError::SetThreadContextError);
    }

    Ok(())
}

fn validate_breakpoint(
    address: *mut u8,
    condition: HardwareBreakpointCondition,
    size: HardwareBreakpointSize,
) -> Result<(), HardwareBreakpointError> {
    if condition == HardwareBreakpointCondition::Execute && size != HardwareBreakpointSize::One {
        return Err(HardwareBreakpointError::InvalidExecutionSize);
    }

    if (address as usize) % size.bytes() != 0 {
        return Err(HardwareBreakpointError::UnalignedAddress);
    }

    Ok(())
}

fn encode_dr7_slot(
    dr7: u64,
    slot: HardwareBreakpointSlot,
    condition_bits: u64,
    size_bits: u64,
) -> u64 {
    let index = slot.index();
    let enable_shift = index * 2;
    let rw_shift = 16 + index * 4;
    let len_shift = rw_shift + 2;
    let mask = dr7_slot_mask(slot);

    (dr7 & !mask) | (1u64 << enable_shift) | (condition_bits << rw_shift) | (size_bits << len_shift)
}

fn restore_dr7_slot(dr7: u64, slot: HardwareBreakpointSlot, original_bits: u64) -> u64 {
    let mask = dr7_slot_mask(slot);
    (dr7 & !mask) | (original_bits & mask)
}

fn dr7_slot_bits(dr7: u64, slot: HardwareBreakpointSlot) -> u64 { dr7 & dr7_slot_mask(slot) }

fn dr7_slot_mask(slot: HardwareBreakpointSlot) -> u64 {
    let index = slot.index();
    let enable_shift = index * 2;
    let rw_shift = 16 + index * 4;
    let len_shift = rw_shift + 2;

    (0b11u64 << enable_shift) | (0b11u64 << rw_shift) | (0b11u64 << len_shift)
}

#[cfg(target_arch = "x86_64")]
#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct DebugRegisterContext {
    p1_home: u64,
    p2_home: u64,
    p3_home: u64,
    p4_home: u64,
    p5_home: u64,
    p6_home: u64,
    context_flags: u32,
    mx_csr: u32,
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    e_flags: u32,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
}

#[cfg(target_arch = "x86")]
#[repr(C)]
#[derive(Clone, Copy)]
struct DebugRegisterContext {
    context_flags: u32,
    dr0: u32,
    dr1: u32,
    dr2: u32,
    dr3: u32,
    dr6: u32,
    dr7: u32,
}

impl Default for DebugRegisterContext {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

impl DebugRegisterContext {
    fn as_context(&self) -> *const crate::winapi::CONTEXT {
        self as *const _ as *const crate::winapi::CONTEXT
    }

    fn as_context_mut(&mut self) -> crate::winapi::LPCONTEXT {
        self as *mut _ as crate::winapi::LPCONTEXT
    }

    fn set_context_flags(&mut self, flags: u32) { self.context_flags = flags; }

    fn dr7(&self) -> u64 { self.dr7 as u64 }

    fn set_dr6(&mut self, value: u64) { self.dr6 = value as _; }

    fn set_dr7(&mut self, value: u64) { self.dr7 = value as _; }

    fn debug_register(&self, slot: HardwareBreakpointSlot) -> u64 {
        match slot {
            HardwareBreakpointSlot::Dr0 => self.dr0 as u64,
            HardwareBreakpointSlot::Dr1 => self.dr1 as u64,
            HardwareBreakpointSlot::Dr2 => self.dr2 as u64,
            HardwareBreakpointSlot::Dr3 => self.dr3 as u64,
        }
    }

    fn set_debug_register(&mut self, slot: HardwareBreakpointSlot, address: u64) {
        match slot {
            HardwareBreakpointSlot::Dr0 => self.dr0 = address as _,
            HardwareBreakpointSlot::Dr1 => self.dr1 = address as _,
            HardwareBreakpointSlot::Dr2 => self.dr2 = address as _,
            HardwareBreakpointSlot::Dr3 => self.dr3 = address as _,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_dr7_slot_bits_without_touching_other_slots() {
        let dr7 = encode_dr7_slot(
            0,
            HardwareBreakpointSlot::Dr2,
            HardwareBreakpointCondition::ReadWrite.dr7_bits(),
            HardwareBreakpointSize::Four.dr7_bits(),
        );

        assert_eq!(dr7 & (1 << 4), 1 << 4);
        assert_eq!((dr7 >> 24) & 0b11, 0b11);
        assert_eq!((dr7 >> 26) & 0b11, 0b11);
        assert_eq!(dr7 & dr7_slot_mask(HardwareBreakpointSlot::Dr0), 0);
    }

    #[test]
    fn validates_execution_breakpoint_size() {
        assert!(
            validate_breakpoint(
                core::ptr::null_mut(),
                HardwareBreakpointCondition::Execute,
                HardwareBreakpointSize::Two,
            )
            .is_err()
        );
    }
}
