extern crate libc;

use libc::c_char;
use std::ffi::CString;

#[repr(C)]
pub struct Buffer {
    pub len: i32,
    pub data: *mut u8,
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