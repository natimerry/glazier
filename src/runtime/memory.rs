use crate::ExpError;
use crate::winapi::BOOL;
use crate::winapi::DWORD;
use crate::winapi::HANDLE;
use crate::winapi::LPVOID;
use crate::winapi::MEMORY_BASIC_INFORMATION;
#[cfg(not(feature = "hells_gate"))]
use crate::winapi::NtReadVirtualMemory;
#[cfg(feature = "hells_gate")]
use crate::winapi::NtReadVirtualMemoryHellsGate;
#[cfg(not(feature = "hells_gate"))]
use crate::winapi::NtWriteVirtualMemory;
#[cfg(feature = "hells_gate")]
use crate::winapi::NtWriteVirtualMemoryHellsGate;
use crate::winapi::PDWORD;
use crate::winapi::ReadProcessMemory;
use crate::winapi::SIZE_T;
use crate::winapi::VirtualProtect;
use crate::winapi::VirtualProtectEx;
use crate::winapi::VirtualQuery;
use crate::winapi::VirtualQueryEx;

pub trait MemoryView {
    fn read<T: Copy>(&self, address: u64) -> Result<T, ExpError>;
    fn write<T: Copy>(&self, address: u64, value: T) -> Result<(), ExpError>;

    fn read_bytes(&self, address: u64, size: usize) -> Result<Vec<u8>, ExpError> {
        (0..size)
            .map(|i| self.read::<u8>(address + i as u64))
            .collect()
    }

    fn write_bytes(&self, address: u64, bytes: &[u8]) -> Result<(), ExpError> {
        bytes
            .iter()
            .enumerate()
            .try_for_each(|(i, &b)| self.write::<u8>(address + i as u64, b))
    }

    fn get_handle(&self) -> Option<HANDLE>;

    fn virtual_query(&self, addr: LPVOID, mbi: &mut MEMORY_BASIC_INFORMATION) -> u64 {
        unsafe {
            let size = if let Some(handle) = self.get_handle() {
                VirtualQueryEx(
                    handle,
                    addr as LPVOID,
                    mbi,
                    size_of::<MEMORY_BASIC_INFORMATION>() as SIZE_T,
                )
            } else {
                VirtualQuery(
                    addr as LPVOID,
                    mbi,
                    size_of::<MEMORY_BASIC_INFORMATION>() as SIZE_T,
                )
            };
            size as u64
        }
    }

    fn copy_non_overlapping(
        &self,
        copysrc: u64,
        copydest: u64,
        copysize: usize,
    ) -> Result<(), ExpError> {
        let bytes = self.read_bytes(copysrc, copysize)?;
        self.write_bytes(copydest, &bytes)?;
        Ok(())
    }

    fn virtual_protect(
        &self,
        address: *mut u8,
        size: usize,
        new_protect: DWORD,
        p_old_protect: PDWORD,
    ) -> BOOL {
        unsafe {
            let res = if let Some(handle) = self.get_handle() {
                VirtualProtectEx(
                    handle,
                    address as *mut _,
                    size as SIZE_T,
                    new_protect,
                    p_old_protect,
                )
            } else {
                VirtualProtect(
                    address as *mut _,
                    size as SIZE_T,
                    new_protect,
                    p_old_protect,
                )
            };
            res
        }
    }

    fn read_bytes_into(&self, addr: u64, buf: &mut [u8]) -> usize;
}

pub struct LocalMemory;

pub struct RemoteMemory {
    pub handle: HANDLE,
}
impl RemoteMemory {
    pub fn from_handle(handle: HANDLE) -> Self { Self { handle } }
}

impl MemoryView for LocalMemory {
    fn read<T: Copy>(&self, address: u64) -> Result<T, ExpError> {
        unsafe {
            let ptr = address as *const T;
            Ok(std::ptr::read_unaligned(ptr))
        }
    }

    fn write<T: Copy>(&self, address: u64, value: T) -> Result<(), ExpError> {
        unsafe {
            let ptr = address as *mut T;
            if ptr.is_null() {
                return Err(ExpError::RuntimeError(
                    "Attempt to write to null pointer".to_string(),
                ));
            }
            std::ptr::write_unaligned(ptr, value);
            Ok(())
        }
    }

    fn get_handle(&self) -> Option<HANDLE> { None }

    fn read_bytes_into(&self, addr: u64, buf: &mut [u8]) -> usize {
        unsafe {
            std::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), buf.len());
        }
        buf.len()
    }
}

impl MemoryView for RemoteMemory {
    fn read<T: Copy>(&self, address: u64) -> Result<T, ExpError> {
        unsafe {
            let mut buffer: T = std::mem::zeroed();
            let mut bytes_read: SIZE_T = 0;
            #[cfg(feature = "hells_gate")]
            let status = NtReadVirtualMemoryHellsGate(
                self.handle,
                address as *mut _,
                &mut buffer as *mut _ as *mut _,
                size_of::<T>() as SIZE_T,
                &mut bytes_read,
            );

            #[cfg(not(feature = "hells_gate"))]
            let status = NtReadVirtualMemory(
                self.handle,
                address as *mut _,
                &mut buffer as *mut _ as *mut _,
                size_of::<T>() as SIZE_T,
                &mut bytes_read,
            );

            if status < 0 {
                return Err(ExpError::RuntimeError("NT READ FAIL".to_string()));
            }
            if bytes_read != size_of::<T>() as SIZE_T {
                return Err(ExpError::RuntimeError("Partial Read".to_string()));
            }
            Ok(buffer)
        }
    }

    fn write<T: Copy>(&self, address: u64, value: T) -> Result<(), ExpError> {
        unsafe {
            let mut bytes_written: SIZE_T = 0;
            #[cfg(feature = "hells_gate")]
            let status = NtWriteVirtualMemoryHellsGate(
                self.handle,
                address as *mut _,
                &value as *const _ as *mut _,
                size_of::<T>() as SIZE_T,
                &mut bytes_written,
            );

            #[cfg(not(feature = "hells_gate"))]
            let status = NtWriteVirtualMemory(
                self.handle,
                address as *mut _,
                &value as *const _ as *mut _,
                size_of::<T>() as SIZE_T,
                &mut bytes_written,
            );
            if status < 0 {
                return Err(ExpError::RuntimeError("NT Write FAIL".to_string()));
            }
            if bytes_written != size_of::<T>() as SIZE_T {
                return Err(ExpError::RuntimeError("Partial Write".to_string()));
            }
            Ok(())
        }
    }

    fn get_handle(&self) -> Option<HANDLE> { return Some(self.handle); }

    fn read_bytes_into(&self, addr: u64, buf: &mut [u8]) -> usize {
        let mut got: SIZE_T = 0;
        // TODO USE NT
        unsafe {
            ReadProcessMemory(
                self.handle,
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                buf.len() as SIZE_T,
                &mut got,
            );
        }
        got as usize
    }
}
