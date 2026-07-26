use crate::ExpError;
use crate::TH32CS_SNAPPROCESS;
use glazier_bindings::CloseHandle;
use glazier_bindings::CreateToolhelp32Snapshot;
use glazier_bindings::DWORD;
use glazier_bindings::GetWindowTextA;
use glazier_bindings::HANDLE;
use glazier_bindings::HWND;
use glazier_bindings::K32GetProcessImageFileNameA;
use glazier_bindings::OpenProcess;
use glazier_bindings::PROCESSENTRY32;
use glazier_bindings::Process32First;
use glazier_bindings::Process32Next;
use glazier_bindings::raw::GetWindowTextLengthA;

const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

#[derive(Debug)]
pub struct Process {
    pub handle: HANDLE,
    pub name: String,
    pub window_name: Option<String>,
    pub path: Option<String>,
    pub pid: u32,
}
impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

impl Process {
    pub fn from_pid(pid: u32, access: u32) -> Result<Self, ExpError> {
        let handle = unsafe { OpenProcess(access, 0, pid) };

        if handle.is_null() {
            return Err(ExpError::OpenProcessError(pid));
        }

        let mut buffer = vec![0u8; 260]; // MAX_PATH
        let len = unsafe {
            K32GetProcessImageFileNameA(
                handle,
                buffer.as_mut_ptr() as *mut i8, // Cast to *mut i8
                buffer.len() as u32,
            )
        };

        let name = if len > 0 {
            String::from_utf8_lossy(&buffer[..len as usize]).into_owned()
        } else {
            String::new()
        };

        let text_len = unsafe { GetWindowTextLengthA(handle as HWND) };

        let window_name = if text_len > 0 {
            let mut buffer: Vec<u8> = vec![0u8; (text_len + 1) as usize];

            let actual_len = unsafe {
                GetWindowTextA(
                    handle as HWND,
                    buffer.as_mut_ptr() as *mut i8,
                    buffer.len() as i32,
                )
            };

            if actual_len > 0 {
                // Use actual_len returned by GetWindowTextA, not text_len
                // This handles cases where GetWindowTextLengthA overestimates
                Some(String::from_utf8_lossy(&buffer[..actual_len as usize]).into_owned())
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            handle,
            name,
            window_name,
            path: None,
            pid,
        })
    }

    pub fn get_from_name(name: impl ToString, access: DWORD) -> Result<Vec<Process>, ExpError> {
        let mut pids: Vec<Process> = Vec::new();

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

        if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
            return Err(ExpError::CreateToolhelp32SnapshotError());
        }

        let mut pe32 = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..unsafe { std::mem::zeroed() }
        };

        if unsafe { Process32First(snapshot, &mut pe32) } == 0 {
            unsafe { CloseHandle(snapshot) };
            return Err(ExpError::OpenProcessError(0));
        }

        let target_name = name.to_string();

        loop {
            let exe_name = {
                let len = pe32
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(pe32.szExeFile.len());
                String::from_utf8_lossy(
                    &(pe32.szExeFile[..len])
                        .iter()
                        .map(|&c| c as u8)
                        .collect::<Vec<u8>>(),
                )
                .to_string()
            };

            if exe_name.eq_ignore_ascii_case(&target_name) {
                if let Ok(process) = Process::from_pid(pe32.th32ProcessID, access) {
                    pids.push(process);
                }
            }

            if unsafe { Process32Next(snapshot, &mut pe32) } == 0 {
                break;
            }
        }

        unsafe { CloseHandle(snapshot) };

        if pids.is_empty() {
            Err(ExpError::ProcessNotFoundError(target_name))
        } else {
            Ok(pids)
        }
    }
}
