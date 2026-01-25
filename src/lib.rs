use thiserror::Error;

pub mod pe;
#[cfg(feature = "runtime")]
pub mod runtime;
pub mod utils;
pub use pe::pe64_static::*;

#[derive(Error, Debug)]
pub enum ExpError {
    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Export Error: {0}")]
    ExportError(String),

    #[cfg(feature = "runtime")]
    #[error("Failed to open process: {0}")]
    OpenProcessError(u32),

    #[cfg(feature = "runtime")]
    #[error("Runtime error: {0}")]
    RuntimeError(String),

    #[cfg(feature = "runtime")]
    #[error("CreateToolhelp32Snapshot error")]
    CreateToolhelp32SnapshotError(),

    #[cfg(feature = "runtime")]
    #[error("Process not found error")]
    ProcessNotFoundError(String),

    #[cfg(feature = "runtime")]
    #[error("Process32Next error")]
    Process32NextError(),
}

pub trait ByteReader {
    fn read_u8(&mut self) -> Result<u8, ExpError>;
    fn read_u32(&mut self) -> Result<u32, ExpError>;
    fn read_u64(&mut self) -> Result<u64, ExpError>;
    fn read_i8(&mut self) -> Result<i8, ExpError>;
    fn read_i16(&mut self) -> Result<i16, ExpError>;
    fn read_i32(&mut self) -> Result<i32, ExpError>;
    fn read_i64(&mut self) -> Result<i64, ExpError>;
    fn read_f32(&mut self) -> Result<f32, ExpError>;
    fn read_f64(&mut self) -> Result<f64, ExpError>;

    fn read_c_string(&mut self) -> Result<String, ExpError>;

    fn read_string_at_offset(&mut self, offset: usize) -> Result<String, ExpError>;

    fn seek(&mut self, offset: usize) -> Result<u64, ExpError>;

    fn current_offset(&mut self) -> Result<usize, ExpError>;
}
