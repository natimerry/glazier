use glazier::hooking::winapi as hooks;
use glazier::utils::to_wide;
use glazier::winapi::CloseHandle;
use glazier::winapi::CreateFileW;
use std::ptr::null_mut;

const GENERIC_READ: u32 = 0x8000_0000;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let mut hook = hooks::CreateFileW(
        |original,
         file_name,
         desired_access,
         share_mode,
         security_attributes,
         creation_disposition,
         flags_and_attributes,
         template_file| {
            println!("CreateFileW intercepted (share mode: {share_mode})");
            unsafe {
                original(
                    file_name,
                    desired_access,
                    share_mode,
                    security_attributes,
                    creation_disposition,
                    flags_and_attributes,
                    template_file,
                )
            }
        },
    )?;
    hook.enable()?;

    let path = to_wide("NUL");
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            0,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };

    if handle as isize != -1 {
        unsafe {
            CloseHandle(handle);
        }
    }

    hook.disable()?;
    Ok(())
}
