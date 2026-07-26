use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use glazier::hardware_breakpoint::HardwareBreakpointAction;
use glazier::hardware_breakpoint::HardwareBreakpointCondition;
use glazier::hardware_breakpoint::HardwareBreakpointSize;
use glazier::hardware_breakpoint::HardwareBreakpointSlot;
use glazier::hardware_breakpoint::LocalHardwareBreakpoint;
use glazier::winapi::raw::CloseHandle;
use glazier::winapi::raw::CreateThread;
use glazier::winapi::raw::ResumeThread;
use glazier::winapi::raw::Sleep;
use glazier::winapi::raw::WaitForSingleObject;

const CREATE_SUSPENDED: u32 = 0x0000_0004;
const INFINITE: u32 = 0xffff_ffff;
const WAIT_OBJECT_0: u32 = 0;

static BREAKPOINT_HIT: AtomicBool = AtomicBool::new(false);
static THREAD_CAN_EXIT: AtomicBool = AtomicBool::new(false);

fn main() {
    unsafe {
        let mut thread_id = 0;
        let thread = CreateThread(
            null_mut(),
            0,
            Some(worker_thread),
            null_mut(),
            CREATE_SUSPENDED,
            &mut thread_id,
        );
        assert!(!thread.is_null(), "CreateThread failed");

        let breakpoint = LocalHardwareBreakpoint::on_suspended_thread(
            thread,
            breakpoint_target as *mut u8,
            HardwareBreakpointSlot::Dr0,
            HardwareBreakpointCondition::Execute,
            HardwareBreakpointSize::One,
            |event| {
                println!(
                    "hardware breakpoint fired at {:p} in {:?}",
                    event.address(),
                    event.slot()
                );
                BREAKPOINT_HIT.store(true, Ordering::Release);
                HardwareBreakpointAction::ContinueExecution
            },
        )
        .expect("failed to install hardware breakpoint");

        println!(
            "enabled DR0 read/write breakpoint at {:p} on thread {}",
            breakpoint.entry().address(),
            thread_id
        );

        ResumeThread(thread);

        while !BREAKPOINT_HIT.load(Ordering::Acquire) {
            Sleep(10);
        }

        drop(breakpoint);

        THREAD_CAN_EXIT.store(true, Ordering::Release);

        let wait = WaitForSingleObject(thread, INFINITE);
        assert_eq!(wait, WAIT_OBJECT_0, "WaitForSingleObject failed: {wait}");

        CloseHandle(thread);
    }
}

unsafe extern "C" fn worker_thread(_: *mut c_void) -> u32 { worker_thread_main() }

fn worker_thread_main() -> u32 {
    breakpoint_target();

    while !THREAD_CAN_EXIT.load(Ordering::Acquire) {
        unsafe {
            Sleep(10);
        }
    }

    0
}

#[inline(never)]
fn breakpoint_target() { core::hint::black_box(0x1337usize); }
