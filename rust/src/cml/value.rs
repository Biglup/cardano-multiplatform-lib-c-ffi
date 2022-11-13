
extern crate cardano_multiplatform_lib;
extern crate libc;
use libc::c_char;
use std::ffi::CStr;
use std::mem;

use cardano_multiplatform_lib::ledger::common::value::Value;
use cardano_multiplatform_lib::ledger::common::value::BigNum;
use cardano_multiplatform_lib::MultiAsset;

use crate::utils::CResult;
use crate::utils::CBuffer;
use crate::utils::COption;
use crate::utils::get_error_message;
use crate::utils::to_c_str;

#[no_mangle]
pub extern "C" fn value_free(ptr: *mut Value) {
    assert!(!ptr.is_null());

    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn value_new(coin: *mut BigNum) -> *mut Value {
    let big_num_coin = unsafe {
        assert!(!coin.is_null());
        &mut* coin
    };

    Box::into_raw(Box::new(Value::new(big_num_coin)))
}

#[no_mangle]
pub extern "C" fn value_from_multi_asset(multi_asset: *mut MultiAsset) -> *mut Value {
    let val1 = unsafe {
        assert!(!multi_asset.is_null());
        &mut* multi_asset
    };

    Box::into_raw(Box::new(Value::new_from_assets(val1)))
}

#[no_mangle]
pub extern "C" fn value_zero() -> *mut Value {
    Box::into_raw(Box::new(Value::zero()))
}


#[no_mangle]
pub extern "C" fn value_is_zero(ptr: *mut Value) -> u8  {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    return unsafe{ mem::transmute(val.is_zero()) };
}

#[no_mangle]
pub extern "C" fn value_coin(ptr: *mut Value) -> *mut BigNum {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    Box::into_raw(Box::new(val.coin()))
}

#[no_mangle]
pub extern "C" fn value_set_coin(ptr: *mut Value, coin: *mut BigNum){
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let val2 = unsafe {
        assert!(!coin.is_null());
        &mut* coin
    };

    val.set_coin(val2);
}

#[no_mangle]
pub extern "C" fn value_multi_asset(ptr: *mut Value) -> *mut COption {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let result = val.multiasset();

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
pub extern "C" fn value_set_multi_asset(ptr: *mut Value, multi_asset: *mut MultiAsset) {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let val2 = unsafe {
        assert!(!multi_asset.is_null());
        &mut* multi_asset
    };

    val.set_multiasset(val2);
}

#[no_mangle]
pub extern "C" fn value_to_bytes(ptr: *mut Value) -> *mut CBuffer {
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
pub extern "C" fn value_from_bytes(ptr: *mut u8, size: usize) -> *mut CResult  {
    assert!(!ptr.is_null());
    assert!(size > 0);

    let v = unsafe { core::slice::from_raw_parts(ptr, size as usize).to_vec() };

    let ret = match Value::from_bytes(v) {
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
pub extern "C" fn value_from_json(int_str: *const c_char) -> *mut CResult {
    assert!(!int_str.is_null());

    let data_c_str: &CStr = unsafe { CStr::from_ptr(int_str) };
    let data_str_slice: &str = data_c_str.to_str().unwrap();

    let result = Value::from_json(data_str_slice);

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
pub extern "C" fn value_to_json(ptr: *mut Value) -> *mut CResult {
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

#[no_mangle]
pub extern "C" fn value_checked_add(ptr: *mut Value, other: *mut Value) -> *mut CResult {
    let value = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_value = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    let result = value.checked_add(other_value);

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
pub extern "C" fn value_checked_sub(ptr: *mut Value, other: *mut Value) -> *mut CResult {
    let value = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_value = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    let result = value.checked_sub(other_value);

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
pub extern "C" fn value_clamped_sub(ptr: *mut Value, other: *mut Value) -> *mut Value
 {
    let value = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_value = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    return Box::into_raw(Box::new(value.clamped_sub(other_value)))
}

#[no_mangle]
pub extern "C" fn value_compare(ptr: *mut Value, other: *mut Value) -> *mut COption {
    let value = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_value = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    let result = value.compare(other_value);

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
