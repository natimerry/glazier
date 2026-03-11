use crate::ExpError;
use crate::winapi::HANDLE;
use crate::winapi::NtReadVirtualMemoryHellsGate;
use crate::winapi::NtWriteVirtualMemoryHellsGate;

pub trait MemoryView {
    fn read<T: Copy>(&self, address: u64) -> Result<T, ExpError>;
    fn write<T: Copy>(&self, address: u64, value: T) -> Result<(), ExpError>;

    fn read_bytes(&self, address: u64, size: usize) -> Result<Vec<u8>, ExpError> {
        (0..size)
            .map(|i| self.read::<u8>(address + i as u64))
            .collect()
    }
}

pub struct LocalMemory;

pub struct RemoteMemory {
    pub handle: HANDLE,
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
}

impl MemoryView for RemoteMemory {
    fn read<T: Copy>(&self, address: u64) -> Result<T, ExpError> {
        unsafe {
            let mut buffer: T = std::mem::zeroed();
            let mut bytes_read: u64 = 0;
            let status = NtReadVirtualMemoryHellsGate(
                self.handle,
                address as *mut _,
                &mut buffer as *mut _ as *mut _,
                size_of::<T>() as u64,
                &mut bytes_read,
            );
            if status < 0 {
                return Err(ExpError::RuntimeError("NT READ FAIL".to_string()));
            }
            if bytes_read != size_of::<T>() as u64 {
                return Err(ExpError::RuntimeError("Partial Read".to_string()));
            }
            Ok(buffer)
        }
    }

    fn write<T: Copy>(&self, address: u64, value: T) -> Result<(), ExpError> {
        unsafe {
            let mut bytes_written: u64 = 0;
            let status = NtWriteVirtualMemoryHellsGate(
                self.handle,
                address as *mut _,
                &value as *const _ as *mut _,
                size_of::<T>() as u64,
                &mut bytes_written,
            );
            if status < 0 {
                return Err(ExpError::RuntimeError("NT Write FAIL".to_string()));
            }
            if bytes_written != size_of::<T>() as u64 {
                return Err(ExpError::RuntimeError("Partial Write".to_string()));
            }
            Ok(())
        }
    }
}
