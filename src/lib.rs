use thiserror::Error;

pub mod pe;

#[derive(Error, Debug)]
pub enum ExpError{
    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),
    
    
    #[error("Parse error: {0}")]
    ParseError(String),
}