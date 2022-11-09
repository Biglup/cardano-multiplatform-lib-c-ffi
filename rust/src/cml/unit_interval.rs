extern crate cardano_multiplatform_lib;
extern crate libc;
use libc::c_char;
use std::ffi::CStr;

use cardano_multiplatform_lib::UnitInterval;
use cardano_multiplatform_lib::ledger::common::value::BigNum;

use crate::utils::CResult;
use crate::utils::CBuffer;
use crate::utils::get_error_message;
use crate::utils::to_c_str;

#[no_mangle]
pub extern "C" fn unit_interval_new(numerator: *mut BigNum, denominator: *mut BigNum) -> *mut UnitInterval {
    let big_num_numerator = unsafe {
        assert!(!numerator.is_null());
        &mut* numerator
    };

    let big_num_denominator = unsafe {
        assert!(!denominator.is_null());
        &mut* denominator
    };

    Box::into_raw(Box::new(UnitInterval::new(big_num_numerator, big_num_denominator)))
}

#[no_mangle]
pub extern "C" fn unit_interval_free(ptr: *mut UnitInterval) {
    assert!(!ptr.is_null());

    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn unit_interval_numerator(ptr: *mut UnitInterval) -> *mut BigNum {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return Box::into_raw(Box::new(val.numerator()));
}

#[no_mangle]
pub extern "C" fn unit_interval_denominator(ptr: *mut UnitInterval) -> *mut BigNum {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return Box::into_raw(Box::new(val.denominator()));
}

#[no_mangle]
pub extern "C" fn unit_interval_to_bytes(ptr: *mut UnitInterval) -> *mut CBuffer {
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
pub extern "C" fn unit_interval_from_bytes(ptr: *mut u8, size: usize) -> *mut CResult  {
    assert!(!ptr.is_null());
    assert!(size > 0);

    let v = unsafe { core::slice::from_raw_parts(ptr, size as usize).to_vec() };

    let ret = match UnitInterval::from_bytes(v) {
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
pub extern "C" fn unit_interval_from_json(int_str: *const c_char) -> *mut CResult {
    assert!(!int_str.is_null());

    let data_c_str: &CStr = unsafe { CStr::from_ptr(int_str) };
    let data_str_slice: &str = data_c_str.to_str().unwrap();

    let result = UnitInterval::from_json(data_str_slice);

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
pub extern "C" fn unit_interval_to_json(ptr: *mut UnitInterval) -> *mut CResult {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let result = val.to_json();

    let ret = match result {
        Ok(v) => CResult {
            result:    to_c_str(v) as *mut u8,
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