extern crate libc;

use libc::c_char;
use std::ffi::CString;
use cardano_multiplatform_lib::error::JsError;

pub struct CBuffer {
    pub len: i32,
    pub data: *mut u8,
}

#[no_mangle]
pub extern "C" fn buffer_free(ptr: *mut CBuffer) {
    assert!(!ptr.is_null());

    let s = unsafe { std::slice::from_raw_parts_mut((*ptr).data, (*ptr).len as usize) };
    let s = s.as_mut_ptr();

    unsafe {
        Box::from_raw(s);
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn buffer_get_len(ptr: *mut CBuffer) -> i32 {
    let buffer = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return buffer.len;
}


#[no_mangle]
pub extern "C" fn buffer_get_data(ptr: *mut CBuffer) -> *mut u8 {
    let buffer = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return buffer.data;
}

pub struct CResult {
    pub result: *mut u8,
    pub has_error: u8,
    pub error_msg: *const c_char
}

#[no_mangle]
pub extern "C" fn result_free(ptr: *mut CResult) {
    assert!(!ptr.is_null());

    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn result_get(ptr: *mut CResult) -> *mut u8 {
    let res = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return res.result;
}

#[no_mangle]
pub extern "C" fn result_get_has_error(ptr: *mut CResult) -> u8 {
    let res = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return res.has_error;
}


#[no_mangle]
pub extern "C" fn result_get_error_message(ptr: *mut CResult) -> *const c_char {
    let res = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return res.error_msg;
}

pub struct COption {
    pub some: *mut u8,
    pub is_none: u8,
}

#[no_mangle]
pub extern "C" fn option_free(ptr: *mut COption) {
    assert!(!ptr.is_null());

    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn option_get_is_none(ptr: *mut COption) -> u8 {
    let res = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return res.is_none;
}

#[no_mangle]
pub extern "C" fn option_get_some(ptr: *mut COption) -> *mut u8 {
    let res = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return res.some;
}

#[no_mangle]
pub extern "C" fn free_c_str(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(ptr));
    }
}

#[no_mangle]
pub extern "C" fn free_int32(ptr: *mut i32) {
    assert!(!ptr.is_null());

    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
/// This is intended for the C code to call for deallocating the
/// Rust-allocated i32 array.
pub unsafe extern "C" fn deallocate_rust_buffer(ptr: *mut i32, len: u32) {
    let len = len as usize;
    drop(Vec::from_raw_parts(ptr, len, len));
}

pub fn get_error_message(error: JsError) -> *const c_char {
    let error_message = error.as_string();

    match error_message {
        Some(v) => {
            let s = CString::new(v).unwrap();
            let p = s.as_ptr();
            std::mem::forget(s);
            return p;
        },
        None => {
            return std::ptr::null_mut();
        }
    };
}

pub fn to_c_str(message: String) -> *const c_char {
    let s = CString::new(message).unwrap();
    let p = s.as_ptr();
    std::mem::forget(s);
    return p;
}

