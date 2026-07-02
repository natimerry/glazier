#![allow(dead_code)]

use super::CallbackHook;
use super::HookEntry;
use super::HookError;
use std::convert::Infallible;
use std::ptr::null_mut;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;

const INSTALLING: *mut () = 1usize as *mut ();

pub(super) trait CallbackSlot {
    fn state() -> &'static AtomicPtr<()>;
}

struct CallbackState<F, O> {
    callback: F,
    original: O,
}

fn install<S, F, O>(
    callback: F,
    function_name: &str,
    dll: &str,
    detour: *mut u8,
) -> Result<CallbackHook, HookError>
where
    S: CallbackSlot,
    F: Send + Sync + 'static,
    O: Copy + 'static,
{
    let slot = S::state();
    slot.compare_exchange(null_mut(), INSTALLING, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| HookError::CallbackAlreadyInstalled)?;

    let result = (|| {
        let entry = HookEntry::from_winapi_function(function_name, Some(dll), detour)?;
        assert_eq!(std::mem::size_of::<O>(), std::mem::size_of::<*mut u8>());

        // Generated O types are native function pointers with the exact target
        // signature.
        let original = unsafe { std::mem::transmute_copy::<*mut u8, O>(&entry.original()) };
        let state = Box::new(CallbackState { callback, original });
        slot.store(Box::into_raw(state).cast(), Ordering::Release);

        Ok(CallbackHook::__new(entry))
    })();

    if result.is_err() {
        slot.store(null_mut(), Ordering::Release);
    }

    result
}

#[inline(always)]
fn state<S, F, O>() -> &'static CallbackState<F, O>
where
    S: CallbackSlot,
    F: 'static,
    O: 'static,
{
    let state = S::state().load(Ordering::Acquire);
    if state.is_null() || state == INSTALLING {
        std::process::abort();
    }

    unsafe { &*state.cast::<CallbackState<F, O>>() }
}

macro_rules! define_callback_arity {
    (
        $install:ident,
        $detour:ident,
        $install_never:ident,
        $detour_never:ident
        $(, $argument_type:ident $argument:ident)*
    ) => {
        #[allow(improper_ctypes_definitions)]
        unsafe extern "system" fn $detour<S, F, O, $($argument_type,)* R>(
            $($argument: $argument_type),*
        ) -> R
        where
            S: CallbackSlot,
            F: Fn(O $(, $argument_type)*) -> R + Send + Sync + 'static,
            O: Copy + 'static,
        {
            let state = state::<S, F, O>();
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                (state.callback)(state.original $(, $argument)*)
            })) {
                Ok(value) => value,
                Err(_) => std::process::abort(),
            }
        }

        pub(super) fn $install<S, F, O, $($argument_type,)* R>(
            callback: F,
            function_name: &str,
            dll: &str,
        ) -> Result<CallbackHook, HookError>
        where
            S: CallbackSlot,
            F: Fn(O $(, $argument_type)*) -> R + Send + Sync + 'static,
            O: Copy + 'static,
        {
            install::<S, F, O>(
                callback,
                function_name,
                dll,
                $detour::<S, F, O, $($argument_type,)* R> as *const () as *mut u8,
            )
        }

        #[allow(improper_ctypes_definitions)]
        unsafe extern "system" fn $detour_never<S, F, O, $($argument_type,)*>(
            $($argument: $argument_type),*
        ) -> !
        where
            S: CallbackSlot,
            F: Fn(O $(, $argument_type)*) -> Infallible + Send + Sync + 'static,
            O: Copy + 'static,
        {
            let state = state::<S, F, O>();
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                (state.callback)(state.original $(, $argument)*)
            })) {
                Ok(value) => match value {},
                Err(_) => std::process::abort(),
            }
        }

        pub(super) fn $install_never<S, F, O, $($argument_type,)*>(
            callback: F,
            function_name: &str,
            dll: &str,
        ) -> Result<CallbackHook, HookError>
        where
            S: CallbackSlot,
            F: Fn(O $(, $argument_type)*) -> Infallible + Send + Sync + 'static,
            O: Copy + 'static,
        {
            install::<S, F, O>(
                callback,
                function_name,
                dll,
                $detour_never::<S, F, O, $($argument_type,)*> as *const () as *mut u8,
            )
        }
    };
}

define_callback_arity!(install_0, detour_0, install_never_0, detour_never_0);
define_callback_arity!(install_1, detour_1, install_never_1, detour_never_1, A0 a0);
define_callback_arity!(install_2, detour_2, install_never_2, detour_never_2, A0 a0, A1 a1);
define_callback_arity!(install_3, detour_3, install_never_3, detour_never_3, A0 a0, A1 a1, A2 a2);
define_callback_arity!(install_4, detour_4, install_never_4, detour_never_4, A0 a0, A1 a1, A2 a2, A3 a3);
define_callback_arity!(install_5, detour_5, install_never_5, detour_never_5, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4);
define_callback_arity!(install_6, detour_6, install_never_6, detour_never_6, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5);
define_callback_arity!(install_7, detour_7, install_never_7, detour_never_7, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6);
define_callback_arity!(install_8, detour_8, install_never_8, detour_never_8, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7);
define_callback_arity!(install_9, detour_9, install_never_9, detour_never_9, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8);
define_callback_arity!(install_10, detour_10, install_never_10, detour_never_10, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9);
define_callback_arity!(install_11, detour_11, install_never_11, detour_never_11, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10);
define_callback_arity!(install_12, detour_12, install_never_12, detour_never_12, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11);
define_callback_arity!(install_13, detour_13, install_never_13, detour_never_13, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12);
define_callback_arity!(install_14, detour_14, install_never_14, detour_never_14, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13);
define_callback_arity!(install_15, detour_15, install_never_15, detour_never_15, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14);
define_callback_arity!(install_16, detour_16, install_never_16, detour_never_16, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15);
define_callback_arity!(install_17, detour_17, install_never_17, detour_never_17, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16);
define_callback_arity!(install_18, detour_18, install_never_18, detour_never_18, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17);
define_callback_arity!(install_19, detour_19, install_never_19, detour_never_19, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17, A18 a18);
define_callback_arity!(install_20, detour_20, install_never_20, detour_never_20, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17, A18 a18, A19 a19);
define_callback_arity!(install_21, detour_21, install_never_21, detour_never_21, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17, A18 a18, A19 a19, A20 a20);
define_callback_arity!(install_22, detour_22, install_never_22, detour_never_22, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17, A18 a18, A19 a19, A20 a20, A21 a21);
define_callback_arity!(install_23, detour_23, install_never_23, detour_never_23, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17, A18 a18, A19 a19, A20 a20, A21 a21, A22 a22);
define_callback_arity!(install_24, detour_24, install_never_24, detour_never_24, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17, A18 a18, A19 a19, A20 a20, A21 a21, A22 a22, A23 a23);
define_callback_arity!(install_25, detour_25, install_never_25, detour_never_25, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17, A18 a18, A19 a19, A20 a20, A21 a21, A22 a22, A23 a23, A24 a24);
define_callback_arity!(install_26, detour_26, install_never_26, detour_never_26, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17, A18 a18, A19 a19, A20 a20, A21 a21, A22 a22, A23 a23, A24 a24, A25 a25);
define_callback_arity!(install_27, detour_27, install_never_27, detour_never_27, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17, A18 a18, A19 a19, A20 a20, A21 a21, A22 a22, A23 a23, A24 a24, A25 a25, A26 a26);
define_callback_arity!(install_28, detour_28, install_never_28, detour_never_28, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17, A18 a18, A19 a19, A20 a20, A21 a21, A22 a22, A23 a23, A24 a24, A25 a25, A26 a26, A27 a27);
define_callback_arity!(install_29, detour_29, install_never_29, detour_never_29, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17, A18 a18, A19 a19, A20 a20, A21 a21, A22 a22, A23 a23, A24 a24, A25 a25, A26 a26, A27 a27, A28 a28);
define_callback_arity!(install_30, detour_30, install_never_30, detour_never_30, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17, A18 a18, A19 a19, A20 a20, A21 a21, A22 a22, A23 a23, A24 a24, A25 a25, A26 a26, A27 a27, A28 a28, A29 a29);
define_callback_arity!(install_31, detour_31, install_never_31, detour_never_31, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17, A18 a18, A19 a19, A20 a20, A21 a21, A22 a22, A23 a23, A24 a24, A25 a25, A26 a26, A27 a27, A28 a28, A29 a29, A30 a30);
define_callback_arity!(install_32, detour_32, install_never_32, detour_never_32, A0 a0, A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15, A16 a16, A17 a17, A18 a18, A19 a19, A20 a20, A21 a21, A22 a22, A23 a23, A24 a24, A25 a25, A26 a26, A27 a27, A28 a28, A29 a29, A30 a30, A31 a31);
