#![cfg(all(
    windows,
    target_arch = "x86_64",
    feature = "runtime",
    feature = "hardware_breakpoint"
))]

use glazier::hardware_breakpoint::HardwareBreakpointCondition;
use glazier::hardware_breakpoint::HardwareBreakpointSize;
use glazier::hardware_breakpoint::HardwareBreakpointSlot;
use glazier::hardware_breakpoint::NativeHardwareBreakpoint;
use glazier::runtime::NativePeRuntime;
use glazier::runtime::TargetArchitecture;
use glazier::winapi::THREADENTRY32;
use glazier::winapi::raw::CloseHandle;
use glazier::winapi::raw::CreateToolhelp32Snapshot;
use glazier::winapi::raw::OpenProcess;
use glazier::winapi::raw::Thread32First;
use glazier::winapi::raw::Thread32Next;
use std::os::windows::process::CommandExt;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_VM_READ: u32 = 0x0010;
const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn x64_host_parses_and_sets_breakpoint_on_wow64_target() {
    let system_root = std::env::var_os("WINDIR").expect("WINDIR is not set");
    let cmd = std::path::Path::new(&system_root)
        .join("SysWOW64")
        .join("cmd.exe");
    assert!(cmd.exists(), "32-bit cmd.exe is unavailable");

    let child = Command::new(cmd)
        .args(["/C", "ping -n 10 127.0.0.1"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start WOW64 test process");
    let child = ChildGuard(child);

    let process =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, child.0.id()) };
    assert!(!process.is_null(), "OpenProcess failed");

    let runtime = wait_for_runtime(process);
    assert_eq!(runtime.architecture(), TargetArchitecture::X86);
    assert!(runtime.module_base() <= u32::MAX as u64);
    assert!(!runtime.sections().is_empty());

    let kernel32 = wait_for_module(process, "KERNEL32.DLL");
    assert_eq!(kernel32.architecture(), TargetArchitecture::X86);
    assert!(kernel32.find_export("LoadLibraryW").is_ok());

    unsafe {
        CloseHandle(process);
    }

    let thread_id = first_thread_id(child.0.id()).expect("WOW64 process has no thread");
    let mut breakpoint = NativeHardwareBreakpoint::from_thread_id(
        thread_id,
        0x10000usize as *mut u8,
        HardwareBreakpointSlot::Dr0,
        HardwareBreakpointCondition::Execute,
        HardwareBreakpointSize::One,
    )
    .expect("failed to create WOW64 hardware breakpoint");

    assert_eq!(breakpoint.architecture(), TargetArchitecture::X86);
    unsafe {
        breakpoint
            .enable()
            .expect("failed to enable WOW64 breakpoint");
        breakpoint
            .disable()
            .expect("failed to disable WOW64 breakpoint");
    }
}

fn wait_for_runtime(
    process: glazier::winapi::HANDLE,
) -> NativePeRuntime<glazier::runtime::memory::RemoteMemory> {
    let mut last_error = String::new();
    for _ in 0..100 {
        match NativePeRuntime::from_handle(process) {
            Ok(runtime) => return runtime,
            Err(error) => last_error = error.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("failed to inspect WOW64 process: {last_error}");
}

fn wait_for_module(
    process: glazier::winapi::HANDLE,
    module: &str,
) -> NativePeRuntime<glazier::runtime::memory::RemoteMemory> {
    let mut last_error = String::new();
    for _ in 0..100 {
        match NativePeRuntime::from_module_remote(process, module) {
            Ok(runtime) => return runtime,
            Err(error) => last_error = error.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("failed to locate 32-bit {module}: {last_error}");
}

fn first_thread_id(process_id: u32) -> Option<u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot.is_null() || snapshot as isize == -1 {
        return None;
    }

    let mut entry: THREADENTRY32 = unsafe { core::mem::zeroed() };
    entry.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;

    let mut result = None;
    if unsafe { Thread32First(snapshot, &mut entry) } != 0 {
        loop {
            if entry.th32OwnerProcessID == process_id {
                result = Some(entry.th32ThreadID);
                break;
            }
            if unsafe { Thread32Next(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe {
        CloseHandle(snapshot);
    }
    result
}
