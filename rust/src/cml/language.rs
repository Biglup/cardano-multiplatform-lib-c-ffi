extern crate cardano_multiplatform_lib;
extern crate libc;

use cardano_multiplatform_lib::plutus::Language;

use crate::utils::CResult;
use crate::utils::CBuffer;
use crate::utils::to_c_str;

#[no_mangle]
pub extern "C" fn language_free(ptr: *mut Language) {
    assert!(!ptr.is_null());

    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn language_to_bytes(ptr: *mut Language) -> *mut CBuffer {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    let     result = val.to_bytes();
    let mut buf    = result.into_boxed_slice();
    let     data   = buf.as_mut_ptr();
    let     len    = buf.len() as i32;

    std::mem::forget(buf);

    return Box::into_raw(Box::new(CBuffer { len, data }));
}

#[no_mangle]
pub extern "C" fn language_from_bytes(ptr: *mut u8, size: usize) -> *mut CResult  {
    assert!(!ptr.is_null());
    assert!(size > 0);

    let v = unsafe { core::slice::from_raw_parts(ptr, size as usize).to_vec() };

    let ret = match Language::from_bytes(v) {
        Ok(int) => CResult {
            result:    Box::into_raw(Box::new(int)) as *mut u8,
            has_error: 0,
            error_msg: std::ptr::null_mut()
        },
        Err(message) => CResult {
            result:    std::ptr::null_mut(),
            has_error: 1,
            error_msg: to_c_str(message.to_string())
        }
    };

    return Box::into_raw(Box::new(ret));
}

#[no_mangle]
pub extern "C" fn language_new_plutus_v1() -> *mut Language {
    Box::into_raw(Box::new(Language::new_plutus_v1()))
}

#[no_mangle]
pub extern "C" fn language_new_plutus_v2() -> *mut Language {
    Box::into_raw(Box::new(Language::new_plutus_v2()))
}

#[no_mangle]
pub extern "C" fn language_kind(ptr: *mut Language) -> u8 {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    return val.kind() as u8;
}