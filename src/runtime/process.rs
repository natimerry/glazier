use crate::ExpError;
use crate::winapi::*;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS;

pub struct Process {
    pub handle: HANDLE,
    pub name: String,
    pub window_name: Option<String>,
    pub path: Option<String>,
}

impl Process {
    pub fn from_pid(pid: u32, access: u32) -> Result<Self, ExpError> {
        let handle = unsafe { OpenProcess(access, 0, pid) };

        if handle.is_null() {
            return Err(ExpError::OpenProcessError(pid));
        }

        let mut buffer = vec![0u8; 260]; // MAX_PATH
        let len = unsafe {
            GetProcessImageFileNameA(
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
            let mut text_buffer = vec![0u8; (text_len + 1) as usize];
            let actual_len = unsafe {
                GetWindowTextA(
                    handle as HWND,
                    text_buffer.as_mut_ptr() as *mut i8, // Cast to *mut i8
                    text_buffer.len() as i32,
                )
            };

            if actual_len > 0 {
                Some(String::from_utf8_lossy(&text_buffer[..actual_len as usize]).into_owned())
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
        })
    }

    pub fn get_pid_by_names(name: impl ToString) -> Result<Vec<u32>, ExpError> {
        let mut pids: Vec<u32> = Vec::new();

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
                pids.push(pe32.th32ProcessID);
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
