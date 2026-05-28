use crate::winapi::_EXCEPTION_POINTERS;
use crate::winapi::HANDLE;
use crate::winapi::raw::AddVectoredExceptionHandler;
use crate::winapi::raw::CloseHandle;
use crate::winapi::raw::GetThreadContext;
use crate::winapi::raw::OpenThread;
use crate::winapi::raw::RemoveVectoredExceptionHandler;
use crate::winapi::raw::ResumeThread;
use crate::winapi::raw::SetThreadContext;
use crate::winapi::raw::SuspendThread;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
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
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const EXCEPTION_SINGLE_STEP: u32 = 0x8000_0004;

static NEXT_HANDLER_ID: AtomicUsize = AtomicUsize::new(1);
static LOCAL_HANDLERS: Mutex<Vec<LocalHardwareBreakpointHandler>> = Mutex::new(Vec::new());
static VEH_HANDLE: Mutex<usize> = Mutex::new(0);

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

    #[error("Failed to install vectored exception handler")]
    VectoredHandlerError,
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

impl HardwareBreakpointOptions {
    pub const fn already_suspended() -> Self {
        Self {
            suspend_thread: false,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareBreakpointAction {
    ContinueExecution,
    ContinueSearch,
}

pub struct HardwareBreakpointEvent {
    address: *mut u8,
    slot: HardwareBreakpointSlot,
    exception_info: *mut _EXCEPTION_POINTERS,
}

impl HardwareBreakpointEvent {
    #[inline]
    pub fn address(&self) -> *mut u8 { self.address }

    #[inline]
    pub fn slot(&self) -> HardwareBreakpointSlot { self.slot }

    #[inline]
    pub fn exception_info(&self) -> *mut _EXCEPTION_POINTERS { self.exception_info }
}

type HardwareBreakpointCallback =
    Box<dyn FnMut(&mut HardwareBreakpointEvent) -> HardwareBreakpointAction + Send + 'static>;

struct LocalHardwareBreakpointHandler {
    id: usize,
    slot: HardwareBreakpointSlot,
    address: usize,
    callback: HardwareBreakpointCallback,
}

pub struct LocalHardwareBreakpoint {
    entry: HardwareBreakpointEntry,
    handler_id: usize,
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

    pub fn on_suspended_thread(
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
            HardwareBreakpointOptions::already_suspended(),
        )
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

        let mut entry = match Self::new(thread, address, slot, condition, size) {
            Ok(entry) => entry,
            Err(err) => {
                unsafe {
                    CloseHandle(thread);
                }
                return Err(err);
            }
        };
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

impl LocalHardwareBreakpoint {
    pub fn new(
        thread: HANDLE,
        address: *mut u8,
        slot: HardwareBreakpointSlot,
        condition: HardwareBreakpointCondition,
        size: HardwareBreakpointSize,
        callback: impl FnMut(&mut HardwareBreakpointEvent) -> HardwareBreakpointAction + Send + 'static,
    ) -> Result<Self, HardwareBreakpointError> {
        Self::with_options(
            thread,
            address,
            slot,
            condition,
            size,
            HardwareBreakpointOptions::default(),
            callback,
        )
    }

    pub fn with_options(
        thread: HANDLE,
        address: *mut u8,
        slot: HardwareBreakpointSlot,
        condition: HardwareBreakpointCondition,
        size: HardwareBreakpointSize,
        options: HardwareBreakpointOptions,
        callback: impl FnMut(&mut HardwareBreakpointEvent) -> HardwareBreakpointAction + Send + 'static,
    ) -> Result<Self, HardwareBreakpointError> {
        ensure_vectored_exception_handler()?;

        let mut entry =
            HardwareBreakpointEntry::with_options(thread, address, slot, condition, size, options)?;
        let handler_id = register_local_handler(slot, address, Box::new(callback));

        if let Err(err) = unsafe { entry.enable() } {
            unregister_local_handler(handler_id);
            return Err(err);
        }

        Ok(Self { entry, handler_id })
    }

    pub fn on_suspended_thread(
        thread: HANDLE,
        address: *mut u8,
        slot: HardwareBreakpointSlot,
        condition: HardwareBreakpointCondition,
        size: HardwareBreakpointSize,
        callback: impl FnMut(&mut HardwareBreakpointEvent) -> HardwareBreakpointAction + Send + 'static,
    ) -> Result<Self, HardwareBreakpointError> {
        let mut breakpoint = Self::with_options(
            thread,
            address,
            slot,
            condition,
            size,
            HardwareBreakpointOptions::already_suspended(),
            callback,
        )?;
        breakpoint.entry.suspend_thread = true;
        Ok(breakpoint)
    }

    pub fn from_thread_id(
        thread_id: u32,
        address: *mut u8,
        slot: HardwareBreakpointSlot,
        condition: HardwareBreakpointCondition,
        size: HardwareBreakpointSize,
        callback: impl FnMut(&mut HardwareBreakpointEvent) -> HardwareBreakpointAction + Send + 'static,
    ) -> Result<Self, HardwareBreakpointError> {
        let thread = unsafe { OpenThread(HARDWARE_BREAKPOINT_THREAD_ACCESS, 0, thread_id) };
        if thread.is_null() {
            return Err(HardwareBreakpointError::OpenThreadError(thread_id));
        }

        match Self::new(thread, address, slot, condition, size, callback) {
            Ok(mut breakpoint) => {
                breakpoint.entry.owns_thread = true;
                Ok(breakpoint)
            }
            Err(err) => {
                unsafe {
                    CloseHandle(thread);
                }
                Err(err)
            }
        }
    }

    #[inline]
    pub fn entry(&self) -> &HardwareBreakpointEntry { &self.entry }

    #[inline]
    pub fn entry_mut(&mut self) -> &mut HardwareBreakpointEntry { &mut self.entry }
}

impl Drop for LocalHardwareBreakpoint {
    fn drop(&mut self) {
        if self.entry.is_enabled() {
            let _ = unsafe { self.entry.disable() };
        }

        unregister_local_handler(self.handler_id);
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

fn ensure_vectored_exception_handler() -> Result<(), HardwareBreakpointError> {
    let Ok(mut handle) = VEH_HANDLE.lock() else {
        return Err(HardwareBreakpointError::VectoredHandlerError);
    };

    if *handle != 0 {
        return Ok(());
    }

    let new_handle = unsafe { AddVectoredExceptionHandler(1, Some(local_breakpoint_dispatcher)) };
    if new_handle.is_null() {
        return Err(HardwareBreakpointError::VectoredHandlerError);
    }

    *handle = new_handle as usize;
    Ok(())
}

fn register_local_handler(
    slot: HardwareBreakpointSlot,
    address: *mut u8,
    callback: HardwareBreakpointCallback,
) -> usize {
    let id = NEXT_HANDLER_ID.fetch_add(1, Ordering::Relaxed);
    let mut handlers = LOCAL_HANDLERS
        .lock()
        .expect("hardware breakpoint handler lock poisoned");
    handlers.push(LocalHardwareBreakpointHandler {
        id,
        slot,
        address: address as usize,
        callback,
    });
    id
}

fn unregister_local_handler(id: usize) {
    if let Ok(mut handlers) = LOCAL_HANDLERS.lock() {
        handlers.retain(|handler| handler.id != id);
        if handlers.is_empty() {
            if let Ok(mut handle) = VEH_HANDLE.lock()
                && *handle != 0
            {
                unsafe {
                    RemoveVectoredExceptionHandler(*handle as *mut _);
                }
                *handle = 0;
            }
        }
    }
}

unsafe extern "C" fn local_breakpoint_dispatcher(exception_info: *mut _EXCEPTION_POINTERS) -> i32 {
    let exception_info = exception_info as *mut ExceptionPointers;
    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let exception_record = unsafe { (*exception_info).exception_record };
    let context = unsafe { (*exception_info).context_record };
    if exception_record.is_null() || context.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if unsafe { (*exception_record).exception_code } != EXCEPTION_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let dr6 = unsafe { (*context).dr6() };
    for slot in [
        HardwareBreakpointSlot::Dr0,
        HardwareBreakpointSlot::Dr1,
        HardwareBreakpointSlot::Dr2,
        HardwareBreakpointSlot::Dr3,
    ] {
        if (dr6 & (1u64 << slot.index())) == 0 {
            continue;
        }

        let address = unsafe { (*context).debug_register(slot) };
        let Ok(mut handlers) = LOCAL_HANDLERS.lock() else {
            return EXCEPTION_CONTINUE_SEARCH;
        };

        if let Some(handler) = handlers
            .iter_mut()
            .find(|handler| handler.slot == slot && handler.address == address as usize)
        {
            let mut event = HardwareBreakpointEvent {
                address: address as *mut u8,
                slot,
                exception_info: exception_info as *mut _EXCEPTION_POINTERS,
            };

            let action = (handler.callback)(&mut event);
            match action {
                HardwareBreakpointAction::ContinueExecution => {
                    unsafe {
                        (*context).set_dr6(0);
                        (*context).set_resume_flag();
                    }
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                HardwareBreakpointAction::ContinueSearch => return EXCEPTION_CONTINUE_SEARCH,
            }
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

#[repr(C)]
struct ExceptionPointers {
    exception_record: *mut ExceptionRecord,
    context_record: *mut DebugRegisterContext,
}

#[repr(C)]
struct ExceptionRecord {
    exception_code: u32,
    exception_flags: u32,
    exception_record: *mut ExceptionRecord,
    exception_address: *mut core::ffi::c_void,
    number_parameters: u32,
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
    rest: [u8; 0x4d0 - 0x78],
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
    rest: [u8; 0x2cc - 0x1c],
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

    fn dr6(&self) -> u64 { self.dr6 as u64 }

    fn set_dr6(&mut self, value: u64) { self.dr6 = value as _; }

    fn set_dr7(&mut self, value: u64) { self.dr7 = value as _; }

    #[cfg(target_arch = "x86_64")]
    fn set_resume_flag(&mut self) {
        const EFLAGS_RESUME_FLAG: u32 = 0x0001_0000;
        self.e_flags |= EFLAGS_RESUME_FLAG;
    }

    #[cfg(target_arch = "x86")]
    fn set_resume_flag(&mut self) {
        const EFLAGS_RESUME_FLAG: u32 = 0x0001_0000;
        const EFLAGS_OFFSET: usize = 0xc0;
        unsafe {
            let eflags = (self as *mut Self as *mut u8).add(EFLAGS_OFFSET) as *mut u32;
            *eflags |= EFLAGS_RESUME_FLAG;
        }
    }

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
