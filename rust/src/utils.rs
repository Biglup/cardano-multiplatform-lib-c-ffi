extern crate libc;

use libc::c_char;
use std::ffi::CString;
use cardano_multiplatform_lib::error::JsError;

#[repr(C)]
pub struct Buffer {
    pub len: i32,
    pub data: *mut u8,
}

#[repr(C)]
pub struct CResult {
    pub result: *mut u8,
    pub has_error: u8,
    pub error_msg: *const c_char
}

#[no_mangle]
pub extern "C" fn free_buffer(buf: Buffer) {
    let s = unsafe { std::slice::from_raw_parts_mut(buf.data, buf.len as usize) };
    let s = s.as_mut_ptr();
    unsafe {
        Box::from_raw(s);
    }
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