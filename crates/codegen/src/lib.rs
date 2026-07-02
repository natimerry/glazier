use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::fs::{self};
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

macro_rules! log {
    ($($tokens: tt)*) => {
        let _ = format_args!($($tokens)*);
    }
}

#[cfg(windows)]
fn windows_kits_root10(_workspace: &Path) -> PathBuf {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // Common locations for KitsRoot10. KitsRoot10 value typically includes trailing
    // backslash. [web:7][web:17]
    let candidates = [
        r"SOFTWARE\Microsoft\Windows Kits\Installed Roots",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots",
    ];

    for key_path in candidates {
        if let Ok(key) = hklm.open_subkey(key_path) {
            if let Ok(dir) = key.get_value::<String, _>("KitsRoot10") {
                return PathBuf::from(dir);
            }
        }
    }

    panic!(
        r#"Windows SDK not found: registry value KitsRoot10 missing.
Looked in HKLM\SOFTWARE\Microsoft\Windows Kits\Installed Roots (and WOW6432Node)."#
    );
}

#[cfg(not(windows))]
fn windows_kits_root10(workspace: &Path) -> PathBuf { workspace.join("windows-kit") }

#[cfg(windows)]
fn newest_windows_sdk_include_dir(kits_root10: &Path) -> PathBuf {
    let include_root = kits_root10.join("Include");
    let rd = fs::read_dir(&include_root).unwrap_or_else(|e| {
        panic!(
            "Windows SDK include root not found: {:?} ({})",
            include_root, e
        )
    });

    // Pick the newest version folder by lexicographic sort
    let mut versions: Vec<OsString> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().ok().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name())
        .collect();

    versions.sort();
    versions.reverse();

    for ver in versions {
        let base = include_root.join(&ver);
        let um = base.join("um");
        let shared = base.join("shared");
        let ucrt = base.join("ucrt");

        if um.is_dir() && shared.is_dir() && ucrt.is_dir() {
            return base;
        }
    }

    panic!(
        "No Windows SDK Include/<version> directory contained um/shared/ucrt under {:?}",
        include_root
    );
}

#[cfg(not(windows))]
fn newest_windows_sdk_include_dir(kits_root10: &Path) -> PathBuf {
    let include_root = kits_root10.join("sdk").join("include");
    log!("Using local xwin include dir: {:?}", include_root);

    if !include_root.exists() {
        panic!("Windows SDK include root not found: {:?}", include_root);
    }

    include_root
}

pub fn generate_winapi_bindings(out_dir: &str, phnt_dir: &Path) -> PathBuf {
    log!("Starting WinAPI bindings generation...");

    let workspace = phnt_dir.parent().unwrap_or_else(|| Path::new("."));
    let kits = windows_kits_root10(workspace);
    let include_ver = newest_windows_sdk_include_dir(&kits);

    log!("Found WINAPI version: {:?}", &include_ver);

    let target = env::var("TARGET").unwrap_or_else(|_| "x86_64-pc-windows-msvc".to_string());
    let is_64_bit = target.contains("x86_64") || target.contains("aarch64");

    let mut bindings_builder = bindgen::Builder::default()
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .header_contents(
            "wrapper.h",
            r#"
#define PHNT_MODE PHNT_MODE_USER
#define PHNT_VERSION PHNT_WINDOWS_11
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define WINNT_NO_DEPRECATE

#include <phnt_windows.h>
#include <phnt.h>
#include <ntpsapi.h>
#include <ntpebteb.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winuser.h>
"#,
        )
        .clang_arg("-fms-compatibility")
        .clang_arg("-fms-extensions")
        .clang_arg(format!("--target={}", target))
        .allowlist_recursively(true)
        .allowlist_type(".*")
        .allowlist_function(".*")
        .blocklist_type("winternl.*")
        .layout_tests(false)
        .generate_comments(false);

    if is_64_bit {
        bindings_builder = bindings_builder.clang_arg("-D_WIN64");
    }

    #[cfg(not(windows))]
    {
        // IMPORTANT: phnt must come FIRST to override incomplete Windows SDK
        // definitions
        bindings_builder = bindings_builder
            .clang_arg(format!("-I{}", phnt_dir.display()))
            .clang_arg(format!("-I{}", kits.join("crt").join("include").display()))
            .clang_arg(format!("-I{}", include_ver.join("ucrt").display()))
            .clang_arg(format!("-I{}", include_ver.join("shared").display()))
            .clang_arg(format!("-I{}", include_ver.join("um").display()));
    }

    #[cfg(windows)]
    {
        bindings_builder = bindings_builder.clang_arg(format!("-I{}", phnt_dir.display()));
    }

    let bindings = bindings_builder
        .generate()
        .expect("Unable to generate bindings");

    let raw_bindings_path = PathBuf::from(out_dir).join("raw_bindings.rs");
    bindings
        .write_to_file(&raw_bindings_path)
        .expect("Couldn't write raw bindings!");

    log!("Post-processing raw bindings...");

    // Fix extern blocks to be unsafe
    let content = std::fs::read_to_string(&raw_bindings_path).unwrap();
    let fixed_content = content
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("extern \"") && trimmed.ends_with('{') {
                let indent = &line[..line.len() - trimmed.len()];
                format!("{indent}unsafe {trimmed}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    std::fs::write(&raw_bindings_path, fixed_content).unwrap();

    log!("Raw bindings written and fixed");

    raw_bindings_path
}

pub fn generate_wrapped_bindings(raw_path: &Path, out_dir: &str) {
    let limit: Option<usize> = None;
    use syn::ForeignItem;
    use syn::Item;

    log!("Parsing generated bindings...");

    let content = std::fs::read_to_string(raw_path).unwrap();
    let file = syn::parse_file(&content).unwrap();

    let wrapped_path = PathBuf::from(out_dir).join("winapi_bindings.rs");
    let mut output = File::create(&wrapped_path).unwrap();

    writeln!(output, "// Auto-generated wrapped Windows API bindings").unwrap();
    writeln!(output).unwrap();

    writeln!(output, "pub mod raw {{").unwrap();
    writeln!(output, "    pub use libwinexploit_bindings::raw::*;").unwrap();
    writeln!(output, "}}").unwrap();
    writeln!(output).unwrap();

    // todo: figure out a way to only reexport types
    writeln!(output, "pub use raw::*;").unwrap();

    writeln!(output).unwrap();

    writeln!(output, "#[cfg(feature = \"hells_gate\")]").unwrap();
    writeln!(
        output,
        "use libwinexploit_runtime::NativePeRuntime as NativePERuntime;"
    )
    .unwrap();

    writeln!(output).unwrap();

    // Count functions
    let total_functions: usize = file
        .items
        .iter()
        .filter_map(|item| {
            if let Item::ForeignMod(fm) = item {
                Some(
                    fm.items
                        .iter()
                        .filter(|i| matches!(i, ForeignItem::Fn(_)))
                        .count(),
                )
            } else {
                None
            }
        })
        .sum();

    let target_count = limit.unwrap_or(total_functions);
    log!("Found {} total functions", total_functions);
    if let Some(n) = limit {
        log!("Generating wrappers for first {} functions", n);
    }

    // Only generate function wrappers
    let mut processed = 0;
    let mut succeeded = 0;
    let mut failed_funcs = Vec::new();

    'outer: for item in file.items {
        if let Item::ForeignMod(foreign_mod) = item {
            for foreign_item in foreign_mod.items {
                if let ForeignItem::Fn(func) = foreign_item {
                    if let Some(max) = limit
                        && processed >= max
                    {
                        break 'outer;
                    }

                    processed += 1;
                    let func_name = func.sig.ident.to_string();

                    if processed % 10 == 0 {
                        let percentage = (processed as f32 / target_count as f32 * 100.0) as usize;
                        log!(
                            "[{}/{}] {}% - {}",
                            processed,
                            target_count,
                            percentage,
                            func_name
                        );
                    }

                    match generate_wrapper(&mut output, &func) {
                        Ok(_) => succeeded += 1,
                        Err(e) => failed_funcs.push((func_name.clone(), e.to_string())),
                    }
                }
            }
        }
    }

    log!("========================================");
    log!("Binding generation complete!");
    log!("  Functions wrapped: {}", succeeded);
    log!("  Functions failed:  {}", failed_funcs.len());
    log!("========================================");

    log!("Now we wait for rustc to compile thew few thousand function and structs...");
    if !failed_funcs.is_empty() {
        log!("Failed functions:");
        for (name, err) in failed_funcs.iter().take(5) {
            log!("  - {}: {}", name, err);
        }
        if failed_funcs.len() > 5 {
            log!("  ... and {} more", failed_funcs.len() - 5);
        }
    }
}

pub fn generate_winapi_hook_bindings(raw_path: &Path, out_dir: &str) {
    use syn::ForeignItem;
    use syn::Item;

    let content = fs::read_to_string(raw_path).expect("Couldn't read raw WinAPI bindings");
    let file = syn::parse_file(&content).expect("Couldn't parse raw WinAPI bindings");

    let path = PathBuf::from(out_dir).join("winapi_hook_bindings.rs");
    let mut output = File::create(path).expect("Couldn't create WinAPI hook bindings");

    writeln!(output, "// Auto-generated typed WinAPI hook installers").unwrap();

    for item in &file.items {
        let Item::ForeignMod(foreign_mod) = item else {
            continue;
        };

        for foreign_item in &foreign_mod.items {
            let ForeignItem::Fn(function) = foreign_item else {
                continue;
            };

            if function.sig.variadic.is_some() {
                continue;
            }

            generate_winapi_hook_binding(&mut output, function)
                .expect("Couldn't generate a WinAPI hook binding");
        }
    }
}

fn generate_winapi_hook_binding<W: Write>(
    output: &mut W,
    function: &syn::ForeignItemFn,
) -> std::io::Result<()> {
    let name = &function.sig.ident;
    let function_name = name.to_string();
    let original_type = format!("{function_name}Original");
    let dll = guess_dll(&function_name);
    let arguments = function
        .sig
        .inputs
        .iter()
        .enumerate()
        .filter_map(|(index, input)| {
            let syn::FnArg::Typed(argument) = input else {
                return None;
            };
            let argument_name = match &*argument.pat {
                syn::Pat::Ident(ident) => ident.ident.to_string(),
                _ => format!("arg{index}"),
            };
            Some((
                argument_name,
                hook_type_to_string(&argument.ty),
                type_to_string(&argument.ty),
            ))
        })
        .collect::<Vec<_>>();
    let return_type = match &function.sig.output {
        syn::ReturnType::Default => "()".to_string(),
        syn::ReturnType::Type(_, ty) => hook_type_to_string(ty),
    };
    let display_return_type = match &function.sig.output {
        syn::ReturnType::Default => "()".to_string(),
        syn::ReturnType::Type(_, ty) => type_to_string(ty),
    };
    let callback_return_type = if return_type == "!" {
        "::std::convert::Infallible".to_string()
    } else {
        return_type.clone()
    };
    let display_callback_return_type = if return_type == "!" {
        "Infallible".to_string()
    } else {
        display_return_type.clone()
    };
    let argument_declarations = arguments
        .iter()
        .map(|(name, ty, _)| format!("{name}: {ty}"))
        .collect::<Vec<_>>()
        .join(", ");
    let callback_types = std::iter::once(original_type.clone())
        .chain(arguments.iter().map(|(_, ty, _)| ty.clone()))
        .collect::<Vec<_>>()
        .join(", ");
    let installer_types = std::iter::once(format!("__{function_name}Slot"))
        .chain(std::iter::once("_".to_string()))
        .chain(std::iter::once(original_type.clone()))
        .chain(arguments.iter().map(|(_, ty, _)| ty.clone()))
        .chain((return_type != "!").then_some(return_type.clone()))
        .collect::<Vec<_>>()
        .join(", ");
    let installer = if return_type == "!" {
        format!("install_never_{}", arguments.len())
    } else {
        format!("install_{}", arguments.len())
    };
    let display_parameters = std::iter::once(format!("original: {original_type}"))
        .chain(
            arguments
                .iter()
                .map(|(name, _, display_type)| format!("{name}: {display_type}")),
        )
        .collect::<Vec<_>>()
        .join(", ");
    let documentation = format!(
        "Installs a callback hook for `{function_name}`.\n\nCallback signature: `|{display_parameters}| -> {display_callback_return_type}`."
    );

    writeln!(output, "#[allow(non_camel_case_types, non_snake_case)]")?;
    writeln!(
        output,
        "pub type {original_type} = unsafe extern \"system\" fn({argument_declarations}) -> {return_type};"
    )?;
    writeln!(output, "#[allow(non_snake_case)]")?;
    writeln!(output, "struct __{function_name}Slot;")?;
    writeln!(
        output,
        "impl super::callback::CallbackSlot for __{function_name}Slot {{"
    )?;
    writeln!(
        output,
        "    fn state() -> &'static ::std::sync::atomic::AtomicPtr<()> {{"
    )?;
    writeln!(
        output,
        "        static STATE: ::std::sync::atomic::AtomicPtr<()> = ::std::sync::atomic::AtomicPtr::new(::std::ptr::null_mut());"
    )?;
    writeln!(output, "        &STATE")?;
    writeln!(output, "    }}")?;
    writeln!(output, "}}")?;
    writeln!(output, "#[doc = {documentation:?}]")?;
    writeln!(output, "#[allow(non_snake_case)]")?;
    writeln!(
        output,
        "pub fn {function_name}(callback: impl Fn({callback_types}) -> {callback_return_type} + Send + Sync + 'static) -> Result<super::CallbackHook, super::HookError> {{"
    )?;
    writeln!(
        output,
        "    super::callback::{installer}::<{installer_types}>(callback, \"{function_name}\", \"{dll}\")"
    )?;
    writeln!(output, "}}")?;
    writeln!(output)?;

    Ok(())
}

fn generate_wrapper(output: &mut File, func: &syn::ForeignItemFn) -> std::io::Result<()> {
    let name = &func.sig.ident;
    let func_name = name.to_string();

    let inputs = &func.sig.inputs;
    let ret = &func.sig.output;

    let dll = guess_dll(&func_name);

    let mut arg_names = Vec::new();
    let mut arg_decls = Vec::new();
    let mut arg_types = Vec::new();

    for (i, input) in inputs.iter().enumerate() {
        if let syn::FnArg::Typed(pat_type) = input {
            let arg_name = if let syn::Pat::Ident(ident) = &*pat_type.pat {
                ident.ident.to_string()
            } else {
                format!("arg{}", i)
            };

            let arg_type = &pat_type.ty;

            arg_names.push(arg_name.clone());
            arg_decls.push(format!("{}: {}", arg_name, type_to_string(arg_type)));
            arg_types.push(type_to_string(arg_type));
        }
    }

    let arg_names_str = arg_names.join(", ");
    let args_decl_str = arg_decls.join(", ");
    let fn_type_args_str = arg_types.join(", ");

    let return_type_str = match ret {
        syn::ReturnType::Default => "()".to_string(),
        syn::ReturnType::Type(_, ty) => type_to_string(ty),
    };

    let return_annotation = if return_type_str == "()" {
        String::new()
    } else {
        format!("-> {}", return_type_str)
    };

    // Generate the main function wrapper
    generate_single_wrapper(
        output,
        &func_name,
        None, // No alias, use func_name
        &args_decl_str,
        &return_annotation,
        &arg_names_str,
        &fn_type_args_str,
        &return_type_str,
        dll,
    )?;

    // If function starts with K32, also generate non-K32 alias
    if func_name.starts_with("K32") {
        let alias_name = func_name.strip_prefix("K32").unwrap();
        writeln!(output, "// Compatibility alias for {}", alias_name)?;
        generate_single_wrapper(
            output,
            alias_name,
            Some(&func_name), // Use K32 name as the real function
            &args_decl_str,
            &return_annotation,
            &arg_names_str,
            &fn_type_args_str,
            &return_type_str,
            dll,
        )?;
    }

    if func_name.starts_with("Nt") || func_name.starts_with("Zw") {
        let alias_name = format!("{}HellsGate", &func_name);
        generate_single_wrapper_hells_gate(
            output,
            &alias_name,
            Some(&func_name), // Use K32 name as the real function
            &args_decl_str,
            &return_annotation,
            &arg_names_str,
            &fn_type_args_str,
            &return_type_str,
            dll,
        )?;
    }

    Ok(())
}
fn generate_single_wrapper_hells_gate(
    output: &mut File,
    name: &str,
    real_func_name: Option<&str>,
    args_decl_str: &str,
    return_annotation: &str,
    arg_names_str: &str,
    _fn_type_args_str: &str, // Unused in Hell's Gate but kept for API compatibility
    return_type_str: &str,
    dll: &str,
) -> std::io::Result<()> {
    let target_func = real_func_name.unwrap_or(name);

    writeln!(output, "#[cfg_attr(not(feature = \"hells_gate\"), inline)]")?;
    writeln!(
        output,
        "pub unsafe fn {}({}) {} {{",
        name, args_decl_str, return_annotation
    )?;
    writeln!(output, "    #[cfg(not(feature = \"hells_gate\"))]")?;
    writeln!(output, "    {{")?;
    writeln!(
        output,
        "        unsafe {{ raw::{}({}) }}",
        target_func, arg_names_str
    )?;
    writeln!(output, "    }}")?;
    writeln!(output, "    #[cfg(feature = \"hells_gate\")]")?;
    writeln!(output, "    {{")?;
    writeln!(output, "        static mut SSN: u16 = 0;")?;
    writeln!(
        output,
        "        static INIT: std::sync::Once = std::sync::Once::new();"
    )?;
    writeln!(output, "        INIT.call_once(|| {{")?;

    // Only works for NTDLL, but we keep 'dll' variable for flexibility if needed
    // In practice, Hell's Gate is strictly for "NTDLL.DLL"
    writeln!(
        output,
        "            if let Ok(module) = NativePERuntime::from_module(\"{}\") {{",
        dll
    )?;
    writeln!(
        output,
        "                if let Ok(export) = module.find_export(\"{}\") {{",
        target_func
    )?;
    writeln!(
        output,
        "                    if let Ok(s) = module.get_syscall_num(export) {{"
    )?;
    writeln!(output, "                        unsafe {{ SSN = s; }}")?;
    writeln!(output, "                    }}")?;
    writeln!(output, "                }}")?;
    writeln!(output, "            }}")?;
    writeln!(output, "        }});")?;

    // Invocation via the syscall! macro
    // We explicitly cast the result to the expected return type
    let invocation_args = if arg_names_str.trim().is_empty() {
        String::new()
    } else {
        format!(", {}", arg_names_str) // format args as: arg1, arg2
    };

    writeln!(
        output,
        // Remove the hardcoded comma after SSN used in the template
        "        crate::syscall!(unsafe {{ SSN }}{}) as {}",
        invocation_args, return_type_str
    )?;
    writeln!(output, "    }}")?;
    writeln!(output, "}}")?;
    writeln!(output)?;

    Ok(())
}

fn generate_single_wrapper(
    output: &mut File,
    name: &str,
    real_func_name: Option<&str>, // Added parameter
    args_decl_str: &str,
    return_annotation: &str,
    arg_names_str: &str,
    fn_type_args_str: &str,
    return_type_str: &str,
    dll: &str,
) -> std::io::Result<()> {
    let target_func = real_func_name.unwrap_or(name);

    // Keep one public item per API. Only the implementation changes by feature,
    // which avoids parsing and type-checking duplicate signatures.
    writeln!(
        output,
        "#[cfg_attr(not(feature = \"obfuscation\"), inline)]"
    )?;
    writeln!(
        output,
        "pub unsafe fn {}({}) {} {{",
        name, args_decl_str, return_annotation
    )?;
    writeln!(output, "    #[cfg(not(feature = \"obfuscation\"))]")?;
    writeln!(output, "    {{")?;
    writeln!(
        output,
        "        unsafe {{ raw::{}({}) }}",
        target_func, arg_names_str
    )?;
    writeln!(output, "    }}")?;
    writeln!(output, "    #[cfg(feature = \"obfuscation\")]")?;
    writeln!(output, "    {{")?;
    writeln!(
        output,
        "        type FnType = unsafe extern \"system\" fn({}) -> {};",
        fn_type_args_str, return_type_str
    )?;
    writeln!(
        output,
        "        static FN_PTR: ::std::sync::atomic::AtomicPtr<()> = ::std::sync::atomic::AtomicPtr::new(::std::ptr::null_mut());"
    )?;
    writeln!(
        output,
        "        let resolved_fn: FnType = unsafe {{ ::std::mem::transmute(resolver::resolve(&FN_PTR, \"{}\", \"{}\")) }};",
        target_func, dll
    )?;
    writeln!(
        output,
        "        unsafe {{ resolved_fn({}) }}",
        arg_names_str
    )?;
    writeln!(output, "    }}")?;
    writeln!(output, "}}")?;
    writeln!(output)?;

    Ok(())
}

fn type_to_string(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(type_path) => {
            // Handle full path with generics
            let segments = &type_path.path.segments;
            segments
                .iter()
                .map(|seg| {
                    let ident = seg.ident.to_string();

                    // Handle generic arguments
                    match &seg.arguments {
                        syn::PathArguments::None => ident,
                        syn::PathArguments::AngleBracketed(args) => {
                            let generic_args = args
                                .args
                                .iter()
                                .map(|arg| match arg {
                                    syn::GenericArgument::Type(ty) => type_to_string(ty),
                                    syn::GenericArgument::Lifetime(lt) => format!("'{}", lt.ident),
                                    syn::GenericArgument::Const(expr) => {
                                        quote::quote!(#expr).to_string()
                                    }
                                    _ => String::new(),
                                })
                                .filter(|s| !s.is_empty())
                                .collect::<Vec<_>>()
                                .join(", ");
                            format!("{}<{}>", ident, generic_args)
                        }
                        syn::PathArguments::Parenthesized(args) => {
                            let inputs = args
                                .inputs
                                .iter()
                                .map(type_to_string)
                                .collect::<Vec<_>>()
                                .join(", ");
                            let output = match &args.output {
                                syn::ReturnType::Default => String::new(),
                                syn::ReturnType::Type(_, ty) => {
                                    format!(" -> {}", type_to_string(ty))
                                }
                            };
                            format!("{}({}){}", ident, inputs, output)
                        }
                    }
                })
                .collect::<Vec<_>>()
                .join("::")
        }
        syn::Type::Ptr(type_ptr) => {
            let mutability = if type_ptr.mutability.is_some() {
                "mut "
            } else {
                "const "
            };
            format!("*{}{}", mutability, type_to_string(&type_ptr.elem))
        }
        syn::Type::Reference(type_ref) => {
            let mutability = if type_ref.mutability.is_some() {
                "mut "
            } else {
                ""
            };
            let lifetime = type_ref
                .lifetime
                .as_ref()
                .map(|lt| format!("'{} ", lt.ident))
                .unwrap_or_default();
            format!(
                "&{}{}{}",
                lifetime,
                mutability,
                type_to_string(&type_ref.elem)
            )
        }
        syn::Type::Array(type_array) => {
            format!(
                "[{}; {}]",
                type_to_string(&type_array.elem),
                quote::quote!(#type_array.len)
            )
        }
        syn::Type::Tuple(type_tuple) => {
            if type_tuple.elems.is_empty() {
                "()".to_string()
            } else {
                let elems = type_tuple
                    .elems
                    .iter()
                    .map(type_to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("({})", elems)
            }
        }
        syn::Type::BareFn(bare_fn) => {
            // Function pointer type
            let unsafety = if bare_fn.unsafety.is_some() {
                "unsafe "
            } else {
                ""
            };
            let abi = bare_fn
                .abi
                .as_ref()
                .map(|abi| format!("extern \"{}\" ", abi.name.as_ref().unwrap().value()))
                .unwrap_or_default();

            let inputs = bare_fn
                .inputs
                .iter()
                .map(|arg| {
                    let name = arg
                        .name
                        .as_ref()
                        .map(|(ident, _)| format!("{}: ", ident))
                        .unwrap_or_default();
                    format!("{}{}", name, type_to_string(&arg.ty))
                })
                .collect::<Vec<_>>()
                .join(", ");

            let output = match &bare_fn.output {
                syn::ReturnType::Default => String::new(),
                syn::ReturnType::Type(_, ty) => format!(" -> {}", type_to_string(ty)),
            };

            format!("{}{}fn({}){}", unsafety, abi, inputs, output)
        }
        _ => {
            // Fallback: use quote
            quote::quote!(#ty).to_string()
        }
    }
}

fn hook_type_to_string(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(type_path) if type_path.qself.is_none() => {
            let mut rendered = String::new();
            let first = type_path
                .path
                .segments
                .first()
                .map(|segment| segment.ident.to_string());

            if type_path.path.leading_colon.is_some() {
                rendered.push_str("::");
            } else if first.as_deref().is_some_and(should_qualify_winapi_type) {
                rendered.push_str("crate::winapi::");
            }

            rendered.push_str(
                &type_path
                    .path
                    .segments
                    .iter()
                    .map(|segment| {
                        let ident = segment.ident.to_string();
                        match &segment.arguments {
                            syn::PathArguments::None => ident,
                            syn::PathArguments::AngleBracketed(arguments) => {
                                let arguments = arguments
                                    .args
                                    .iter()
                                    .map(|argument| match argument {
                                        syn::GenericArgument::Type(ty) => hook_type_to_string(ty),
                                        syn::GenericArgument::Lifetime(lifetime) => {
                                            quote::quote!(#lifetime).to_string()
                                        }
                                        syn::GenericArgument::Const(expression) => {
                                            quote::quote!(#expression).to_string()
                                        }
                                        _ => quote::quote!(#argument).to_string(),
                                    })
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                format!("{ident}<{arguments}>")
                            }
                            syn::PathArguments::Parenthesized(arguments) => {
                                let inputs = arguments
                                    .inputs
                                    .iter()
                                    .map(hook_type_to_string)
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                let output = match &arguments.output {
                                    syn::ReturnType::Default => String::new(),
                                    syn::ReturnType::Type(_, ty) => {
                                        format!(" -> {}", hook_type_to_string(ty))
                                    }
                                };
                                format!("{ident}({inputs}){output}")
                            }
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("::"),
            );
            rendered
        }
        syn::Type::Ptr(pointer) => {
            let mutability = if pointer.mutability.is_some() {
                "mut "
            } else {
                "const "
            };
            format!("*{mutability}{}", hook_type_to_string(&pointer.elem))
        }
        syn::Type::Reference(reference) => {
            let lifetime = reference
                .lifetime
                .as_ref()
                .map(|lifetime| format!("{} ", quote::quote!(#lifetime)))
                .unwrap_or_default();
            let mutability = if reference.mutability.is_some() {
                "mut "
            } else {
                ""
            };
            format!(
                "&{lifetime}{mutability}{}",
                hook_type_to_string(&reference.elem)
            )
        }
        syn::Type::Array(array) => {
            let length = &array.len;
            format!(
                "[{}; {}]",
                hook_type_to_string(&array.elem),
                quote::quote!(#length)
            )
        }
        syn::Type::Slice(slice) => format!("[{}]", hook_type_to_string(&slice.elem)),
        syn::Type::Tuple(tuple) => {
            if tuple.elems.is_empty() {
                return "()".to_string();
            }
            let elements = tuple
                .elems
                .iter()
                .map(hook_type_to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let trailing_comma = if tuple.elems.len() == 1 { "," } else { "" };
            format!("({elements}{trailing_comma})")
        }
        syn::Type::BareFn(function) => {
            let unsafety = if function.unsafety.is_some() {
                "unsafe "
            } else {
                ""
            };
            let abi = function
                .abi
                .as_ref()
                .map(|abi| {
                    let name = abi
                        .name
                        .as_ref()
                        .map(|name| name.value())
                        .unwrap_or_else(|| "C".to_string());
                    format!("extern \"{name}\" ")
                })
                .unwrap_or_default();
            let mut inputs = function
                .inputs
                .iter()
                .map(|argument| {
                    let name = argument
                        .name
                        .as_ref()
                        .map(|(name, _)| format!("{name}: "))
                        .unwrap_or_default();
                    format!("{name}{}", hook_type_to_string(&argument.ty))
                })
                .collect::<Vec<_>>();
            if function.variadic.is_some() {
                inputs.push("...".to_string());
            }
            let output = match &function.output {
                syn::ReturnType::Default => String::new(),
                syn::ReturnType::Type(_, ty) => format!(" -> {}", hook_type_to_string(ty)),
            };
            format!("{unsafety}{abi}fn({}){output}", inputs.join(", "))
        }
        syn::Type::Paren(paren) => format!("({})", hook_type_to_string(&paren.elem)),
        syn::Type::Group(group) => hook_type_to_string(&group.elem),
        syn::Type::Never(_) => "!".to_string(),
        _ => type_to_string(ty),
    }
}

fn should_qualify_winapi_type(first_segment: &str) -> bool {
    !matches!(
        first_segment,
        "std"
            | "core"
            | "alloc"
            | "crate"
            | "self"
            | "super"
            | "Option"
            | "Result"
            | "Box"
            | "String"
            | "Vec"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
            | "f32"
            | "f64"
            | "bool"
            | "char"
            | "str"
    )
}

fn guess_dll(func_name: &str) -> &'static str {
    let name_lower = func_name.to_lowercase();

    // Check prefixes first
    if name_lower.starts_with("zw") || name_lower.starts_with("nt") {
        return "NTDLL.DLL";
    }

    // Match based on keywords
    match () {
        _ if name_lower.contains("process")
            || name_lower.contains("thread")
            || name_lower.contains("library")
            || name_lower.contains("module")
            || name_lower.contains("toolhelp")
            || name_lower.contains("heap")
            || name_lower.contains("virtual")
            || name_lower.contains("createfile") =>
        {
            "KERNEL32.DLL"
        }

        _ if name_lower.contains("window")
            || name_lower.contains("message")
            || name_lower.contains("dialog")
            || name_lower.contains("menu")
            || name_lower.contains("input")
            || name_lower.contains("foreground")
            || name_lower.contains("hook") =>
        {
            "USER32.DLL"
        }

        _ if name_lower.contains("reg")
            || name_lower.contains("security")
            || name_lower.contains("service") =>
        {
            "ADVAPI32.DLL"
        }

        _ if name_lower.contains("gdi")
            || name_lower.contains("bitmap")
            || name_lower.contains("brush") =>
        {
            "GDI32.DLL"
        }

        _ if name_lower.contains("shell") || name_lower.contains("shget") => "SHELL32.DLL",

        _ => "KERNEL32.DLL",
    }
}
