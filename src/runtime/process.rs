use crate::ExpError;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows_sys::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32;
use windows_sys::Win32::System::Diagnostics::ToolHelp::Process32First;
use windows_sys::Win32::System::Diagnostics::ToolHelp::Process32Next;
use windows_sys::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS;

pub struct Process {
    pub handle: HWND,
    pub name: String,
    pub window_name: Option<String>,
    pub path: Option<String>,
}

impl Process {
    pub fn from_pid(pid: u32, access: u32) -> Result<Self, ExpError> {
        let handle = unsafe { windows_sys::Win32::System::Threading::OpenProcess(access, 0, pid) };

        if handle.is_null() {
            return Err(ExpError::OpenProcessError(pid));
        }

        let mut buffer = vec![0u8; 260]; // MAX_PATH
        let len = unsafe {
            windows_sys::Win32::System::ProcessStatus::GetProcessImageFileNameA(
                handle,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        };

        let name = if len > 0 {
            String::from_utf8_lossy(&buffer[..len as usize]).into_owned()
        } else {
            String::new()
        };

        let text_len =
            unsafe { windows_sys::Win32::UI::WindowsAndMessaging::GetWindowTextLengthA(handle) };

        let window_name = if text_len > 0 {
            let mut text_buffer = vec![0u8; (text_len + 1) as usize];
            let actual_len = unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::GetWindowTextA(
                    handle,
                    text_buffer.as_mut_ptr(),
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
        if snapshot == INVALID_HANDLE_VALUE {
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

        loop {
            let exe_name = unsafe {
                let len = pe32
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(pe32.szExeFile.len());
                String::from_utf8_lossy(
                    &(pe32.szExeFile[..len])
                        .iter()
                        .map(|x| *x as u8)
                        .collect::<Vec<u8>>(),
                )
                .to_string()
            };

            if exe_name.eq_ignore_ascii_case(&name.to_string()) {
                pids.push(pe32.th32ProcessID);
            }

            if unsafe { Process32Next(snapshot, &mut pe32) } == 0 {
                break;
            }
        }

        unsafe { CloseHandle(snapshot) };

        if pids.is_empty() {
            Err(ExpError::ProcessNotFoundError(name.to_string()))
        } else {
            Ok(pids)
        }
    }
}
