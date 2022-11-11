extern crate cardano_multiplatform_lib;
extern crate libc;
use libc::c_char;
use std::ffi::CStr;

use cardano_multiplatform_lib::ledger::common::value::Int;
use cardano_multiplatform_lib::plutus::Language;
use cardano_multiplatform_lib::plutus::CostModel;


use crate::utils::CResult;
use crate::utils::CBuffer;
use crate::utils::get_error_message;
use crate::utils::to_c_str;

#[no_mangle]
pub extern "C" fn cost_model_free(ptr: *mut CostModel) {
    assert!(!ptr.is_null());

    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn cost_model_set(ptr: *mut CostModel, operation: usize, cost: *mut Int) -> *mut CResult {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    let val2 = unsafe {
        assert!(!cost.is_null());
        &mut *cost
    };

    let result = val.set(operation, val2);

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
pub extern "C" fn cost_model_get(ptr: *mut CostModel, operation: usize) -> *mut CResult {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    let result = val.get(operation);

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
pub extern "C" fn cost_model_language(ptr: *mut CostModel) -> *mut Language {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    return Box::into_raw(Box::new(val.language()));
}

#[no_mangle]
pub extern "C" fn cost_model_empty_model(ptr: *mut Language) -> *mut CostModel {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return Box::into_raw(Box::new(CostModel::empty_model(val)));
}

#[no_mangle]
pub extern "C" fn cost_model_to_bytes(ptr: *mut CostModel) -> *mut CBuffer {
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
pub extern "C" fn cost_model_from_bytes(ptr: *mut u8, size: usize) -> *mut CResult  {
    assert!(!ptr.is_null());
    assert!(size > 0);

    let v = unsafe { core::slice::from_raw_parts(ptr, size as usize).to_vec() };

    let ret = match CostModel::from_bytes(v) {
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
pub extern "C" fn cost_model_from_json(ptr: *const c_char) -> *mut CResult {
    assert!(!ptr.is_null());

    let data_c_str: &CStr = unsafe { CStr::from_ptr(ptr) };
    let data_str_slice: &str = data_c_str.to_str().unwrap();

    let result = CostModel::from_json(data_str_slice);

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
pub extern "C" fn cost_model_to_json(ptr: *mut CostModel) -> *mut CResult {
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

