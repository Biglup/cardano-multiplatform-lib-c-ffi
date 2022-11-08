extern crate cardano_multiplatform_lib;
extern crate libc;
use libc::c_char;
use std::ffi::CString;
use std::ffi::CStr;
use std::mem;

use cardano_multiplatform_lib::ledger::common::value::Int;
use cardano_multiplatform_lib::ledger::common::value::BigNum;
use crate::utils::CResult;
use crate::utils::CBuffer;
use crate::utils::COption;
use crate::utils::get_error_message;
use crate::utils::to_c_str;

#[no_mangle]
pub extern "C" fn int_new(ptr: *mut BigNum) -> *mut Int {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    Box::into_raw(Box::new(Int::new(big_num)))
}

#[no_mangle]
pub extern "C" fn int_new_negative(ptr: *mut BigNum) -> *mut Int {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    Box::into_raw(Box::new(Int::new_negative(big_num)))
}

#[no_mangle]
pub extern "C" fn int_new_i32(x: i32) -> *mut Int {
    Box::into_raw(Box::new(Int::from(x)))
}

#[no_mangle]
pub extern "C" fn int_free(ptr: *mut Int) {
    assert!(!ptr.is_null());

    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn int_as_positive(ptr: *mut Int) -> *mut COption {
    assert!(!ptr.is_null());

    let int = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let result = int.as_positive();

    let ret = match result {
        Some(v) => COption {
            some:    Box::into_raw(Box::new(v)) as *mut u8,
            is_none: 0
        },
        None => COption {
            some:    std::ptr::null_mut(),
            is_none: 1,
        }
    };

    return Box::into_raw(Box::new(ret));
}

#[no_mangle]
pub extern "C" fn int_as_negative(ptr: *mut Int) -> *mut COption {
    assert!(!ptr.is_null());

    let int = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let result = int.as_negative();

    let ret = match result {
        Some(v) => COption {
            some:    Box::into_raw(Box::new(v)) as *mut u8,
            is_none: 0
        },
        None => COption {
            some:    std::ptr::null_mut(),
            is_none: 1,
        }
    };

    return Box::into_raw(Box::new(ret));
}

#[no_mangle]
pub extern "C" fn int_is_positive(ptr: *mut Int) -> u8  {
    let int = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    return unsafe{ mem::transmute(int.is_positive()) };
}

#[no_mangle]
pub extern "C" fn int_as_i32_or_nothing(ptr: *mut Int) -> *mut COption {
    assert!(!ptr.is_null());

    let int = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let result = int.as_i32_or_nothing();

    let ret = match result {
        Some(v) => COption {
            some:    Box::into_raw(Box::new(v)) as *mut u8,
            is_none: 0
        },
        None => COption {
            some:    std::ptr::null_mut(),
            is_none: 1,
        }
    };

    return Box::into_raw(Box::new(ret));
}

#[no_mangle]
pub extern "C" fn int_as_i32_or_fail(ptr: *mut Int) -> *mut CResult {
    let int = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let result = int.as_i32_or_fail();

    let ret = match result {
        Ok(v) => CResult {
            result: Box::into_raw(Box::new(v)) as *mut u8,
            has_error: 0,
            error_msg: std::ptr::null_mut()
        },
        Err(js_value) => CResult {
            result: std::ptr::null_mut(),
            has_error: 1,
            error_msg: get_error_message(js_value)
        }
    };

    return Box::into_raw(Box::new(ret));
}

#[no_mangle]
pub extern "C" fn int_to_bytes(ptr: *mut Int) -> *mut CBuffer {
    let int = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    let     result = int.to_bytes();
    let mut buf    = result.into_boxed_slice();
    let     data   = buf.as_mut_ptr();
    let     len    = buf.len() as i32;

    std::mem::forget(buf);

    return Box::into_raw(Box::new(CBuffer { len, data }));
}

#[no_mangle]
pub extern "C" fn int_from_bytes(ptr: *mut u8, size: usize) -> *mut CResult  {
    assert!(!ptr.is_null());
    assert!(size > 0);

    let v = unsafe { core::slice::from_raw_parts(ptr, size as usize).to_vec() };

    let ret = match Int::from_bytes(v) {
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
pub extern "C" fn int_from_string(int_str: *const c_char) -> *mut CResult {
    assert!(!int_str.is_null());

    let data_c_str: &CStr = unsafe { CStr::from_ptr(int_str) };
    let data_str_slice: &str = data_c_str.to_str().unwrap();

    let result = Int::from_str(data_str_slice);

    let ret = match result {
        Ok(v) => CResult {
            result:    Box::into_raw(Box::new(v)) as *mut u8,
            has_error: 0,
            error_msg: std::ptr::null_mut()
        },
        Err(js_value) => CResult {
            result:    std::ptr::null_mut(),
            has_error: 1,
            error_msg: get_error_message(js_value)
        }
    };

    return Box::into_raw(Box::new(ret));
}

#[no_mangle]
pub extern "C" fn int_to_string(ptr: *mut Int) -> *const c_char {
    let int = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let result = int.to_str();

    let s = CString::new(result).unwrap();
    let p = s.as_ptr();
    std::mem::forget(s);
    return p;
}