use crate::ExpError;
use crate::architecture::TargetArchitecture;
use crate::architecture::process_architecture;
use crate::memory::LocalMemory;
use crate::memory::MemoryView;
use crate::memory::RemoteMemory;
use crate::pe::export_address_table::ParsedExportFunction;
use crate::pe::image_section_header::ImageSectionHeader;
use crate::pe32_runtime::PE32Runtime;
use crate::pe64_runtime::PE64Runtime;
use glazier_bindings::HANDLE;

pub enum NativePeRuntime<M: MemoryView> {
    Pe32(PE32Runtime<M>),
    Pe64(PE64Runtime<M>),
}

impl NativePeRuntime<LocalMemory> {
    pub fn from_current_module() -> Result<Self, ExpError> {
        PE64Runtime::from_current_module().map(Self::Pe64)
    }

    pub fn from_module(dll_name: impl ToString) -> Result<Self, ExpError> {
        PE64Runtime::from_module(dll_name).map(Self::Pe64)
    }

    pub fn get_syscall_num(&self, export: ParsedExportFunction) -> Result<u16, ExpError> {
        match self {
            Self::Pe64(runtime) => runtime.get_syscall_num(export),
            Self::Pe32(_) => Err(ExpError::RuntimeError(
                "Syscall extraction is only supported for PE64 modules".to_string(),
            )),
        }
    }
}

impl NativePeRuntime<RemoteMemory> {
    pub fn from_handle(handle: HANDLE) -> Result<Self, ExpError> {
        match process_architecture(handle).map_err(|err| ExpError::RuntimeError(err.to_string()))? {
            TargetArchitecture::X86 => PE32Runtime::from_handle(handle).map(Self::Pe32),
            TargetArchitecture::X64 => PE64Runtime::from_handle(handle).map(Self::Pe64),
        }
    }

    pub fn from_module_remote(handle: HANDLE, dll_name: impl ToString) -> Result<Self, ExpError> {
        let dll_name = dll_name.to_string();
        match process_architecture(handle).map_err(|err| ExpError::RuntimeError(err.to_string()))? {
            TargetArchitecture::X86 => {
                PE32Runtime::from_module_remote(handle, dll_name).map(Self::Pe32)
            }
            TargetArchitecture::X64 => {
                PE64Runtime::from_module_remote(handle, dll_name).map(Self::Pe64)
            }
        }
    }
}

impl<M: MemoryView> NativePeRuntime<M> {
    pub const fn architecture(&self) -> TargetArchitecture {
        match self {
            Self::Pe32(_) => TargetArchitecture::X86,
            Self::Pe64(_) => TargetArchitecture::X64,
        }
    }

    pub fn find_export(
        &self,
        export_name: impl ToString,
    ) -> Result<ParsedExportFunction, ExpError> {
        let export_name = export_name.to_string();
        match self {
            Self::Pe32(runtime) => runtime.find_export(export_name),
            Self::Pe64(runtime) => runtime.find_export(export_name),
        }
    }

    pub fn module_base(&self) -> u64 {
        match self {
            Self::Pe32(runtime) => runtime.module_base as u64,
            Self::Pe64(runtime) => runtime.module_base,
        }
    }

    pub fn image_size(&self) -> u32 {
        match self {
            Self::Pe32(runtime) => runtime.image_size,
            Self::Pe64(runtime) => runtime.image_size,
        }
    }

    pub fn has_exports(&self) -> bool {
        match self {
            Self::Pe32(runtime) => runtime.has_exports(),
            Self::Pe64(runtime) => runtime.has_exports(),
        }
    }

    pub fn sections(&self) -> &[ImageSectionHeader] {
        match self {
            Self::Pe32(runtime) => runtime.sections(),
            Self::Pe64(runtime) => runtime.sections(),
        }
    }

    pub fn as_pe32(&self) -> Option<&PE32Runtime<M>> {
        match self {
            Self::Pe32(runtime) => Some(runtime),
            Self::Pe64(_) => None,
        }
    }

    pub fn as_pe64(&self) -> Option<&PE64Runtime<M>> {
        match self {
            Self::Pe32(_) => None,
            Self::Pe64(runtime) => Some(runtime),
        }
    }

    pub fn into_memory(self) -> M {
        match self {
            Self::Pe32(runtime) => runtime.memory,
            Self::Pe64(runtime) => runtime.memory,
        }
    }
}

pub type NativePERuntime<M> = NativePeRuntime<M>;
