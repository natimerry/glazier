#![allow(
    warnings,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    unnecessary_transmutes,
    unsafe_op_in_unsafe_fn
)]

pub mod raw {
    include!(concat!(env!("OUT_DIR"), "/raw_bindings.rs"));
}

pub use raw::*;
