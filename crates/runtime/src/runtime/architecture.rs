use glazier_bindings::HANDLE;
use glazier_bindings::raw::CloseHandle;
use glazier_bindings::raw::GetProcessIdOfThread;
use glazier_bindings::raw::IsWow64Process2;
use glazier_bindings::raw::OpenProcess;
use thiserror::Error;

const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetArchitecture {
    X86,
    X64,
}

#[derive(Debug, Error)]
pub enum ArchitectureError {
    #[error("Invalid process handle")]
    InvalidProcessHandle,

    #[error("Failed to query process architecture")]
    QueryProcessArchitecture,

    #[error("Failed to resolve the process for a thread")]
    QueryThreadProcess,

    #[error(
        "Unsupported process machine: process={process_machine:#06x}, native={native_machine:#06x}"
    )]
    UnsupportedMachine {
        process_machine: u16,
        native_machine: u16,
    },
}

pub fn process_architecture(process: HANDLE) -> Result<TargetArchitecture, ArchitectureError> {
    if process.is_null() {
        return Err(ArchitectureError::InvalidProcessHandle);
    }

    let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    if unsafe { IsWow64Process2(process, &mut process_machine, &mut native_machine) } == 0 {
        return Err(ArchitectureError::QueryProcessArchitecture);
    }

    match (process_machine, native_machine) {
        (IMAGE_FILE_MACHINE_I386, _) => Ok(TargetArchitecture::X86),
        (IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_AMD64) => Ok(TargetArchitecture::X64),
        _ => Err(ArchitectureError::UnsupportedMachine {
            process_machine,
            native_machine,
        }),
    }
}

pub fn thread_architecture(thread: HANDLE) -> Result<TargetArchitecture, ArchitectureError> {
    let process_id = unsafe { GetProcessIdOfThread(thread) };
    if process_id == 0 {
        return Err(ArchitectureError::QueryThreadProcess);
    }

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(ArchitectureError::QueryThreadProcess);
    }

    let result = process_architecture(process);
    unsafe {
        CloseHandle(process);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use glazier_bindings::raw::GetCurrentProcess;

    #[test]
    fn detects_native_process_architecture() {
        let architecture = process_architecture(unsafe { GetCurrentProcess() }).unwrap();
        assert_eq!(architecture, TargetArchitecture::X64);
    }
}
