
extern crate cardano_multiplatform_lib;
extern crate libc;
use libc::c_char;
use std::ffi::CString;
use std::ffi::CStr;
use std::mem;

use cardano_multiplatform_lib::ledger::common::value::BigNum;
use crate::utils::CResult;
use crate::utils::CBuffer;
use crate::utils::get_error_message;
use crate::utils::to_c_str;

#[no_mangle]
pub extern "C" fn big_num_free(ptr: *mut BigNum) {
    assert!(!ptr.is_null());

    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn big_num_to_bytes(ptr: *mut BigNum) -> *mut CBuffer {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    let     result = big_num.to_bytes();
    let mut buf    = result.into_boxed_slice();
    let     data   = buf.as_mut_ptr();
    let     len    = buf.len() as i32;

    std::mem::forget(buf);

    return Box::into_raw(Box::new(CBuffer { len, data }));
}

#[no_mangle]
pub extern "C" fn big_num_from_bytes(ptr: *mut u8, size: usize) -> *mut CResult  {
    assert!(!ptr.is_null());
    assert!(size > 0);

    let v = unsafe { core::slice::from_raw_parts(ptr, size as usize).to_vec() };

    let ret = match BigNum::from_bytes(v) {
        Ok(big_num) => CResult {
            result:    Box::into_raw(Box::new(big_num)) as *mut u8,
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
pub extern "C" fn big_num_from_string(big_num_str: *const c_char) -> *mut CResult {
    assert!(!big_num_str.is_null());

    let data_c_str: &CStr = unsafe { CStr::from_ptr(big_num_str) };
    let data_str_slice: &str = data_c_str.to_str().unwrap();

    let result = BigNum::from_str(data_str_slice);

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
pub extern "C" fn big_num_to_string(ptr: *mut BigNum) -> *const c_char {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let result = big_num.to_str();

    let s = CString::new(result).unwrap();
    let p = s.as_ptr();
    std::mem::forget(s);
    return p;
}

#[no_mangle]
pub extern "C" fn big_num_zero() -> *mut BigNum  {
    Box::into_raw(Box::new(BigNum::zero()))
}

#[no_mangle]
pub extern "C" fn big_num_is_zero(ptr: *mut BigNum) -> u8  {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    return unsafe{ mem::transmute(big_num.is_zero()) };
}

#[no_mangle]
pub extern "C" fn big_num_checked_mul(ptr: *mut BigNum, other: *mut BigNum) -> *mut CResult {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_big_num = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    let result = big_num.checked_mul(other_big_num);

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
pub extern "C" fn big_num_checked_add(ptr: *mut BigNum, other: *mut BigNum) -> *mut CResult {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_big_num = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    let result = big_num.checked_add(other_big_num);

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
pub extern "C" fn big_num_checked_sub(ptr: *mut BigNum, other: *mut BigNum) -> *mut CResult {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_big_num = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    let result = big_num.checked_sub(other_big_num);

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
pub extern "C" fn big_num_clamped_sub(ptr: *mut BigNum, other: *mut BigNum) -> *mut BigNum {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_big_num = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    return Box::into_raw(Box::new(big_num.clamped_sub(other_big_num)))
}

#[no_mangle]
pub extern "C" fn big_num_checked_div(ptr: *mut BigNum, other: *mut BigNum) -> *mut CResult {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_big_num = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    let result = big_num.checked_div(other_big_num);

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
pub extern "C" fn big_num_checked_div_ceil(ptr: *mut BigNum, other: *mut BigNum) -> *mut CResult {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_big_num = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    let result = big_num.checked_div_ceil(other_big_num);

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
pub extern "C" fn big_num_compare(ptr: *mut BigNum, other: *mut BigNum) -> i8 {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_big_num = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    return big_num.compare(other_big_num);
}
