extern crate cardano_multiplatform_lib;
extern crate libc;
use libc::c_char;
use std::ffi::CStr;

use cardano_multiplatform_lib::plutus::ExUnitPrices;
use cardano_multiplatform_lib::UnitInterval;

use crate::utils::CResult;
use crate::utils::CBuffer;
use crate::utils::get_error_message;
use crate::utils::to_c_str;

#[no_mangle]
pub extern "C" fn ex_unit_prices_new(mem_price: *mut UnitInterval, step_price: *mut UnitInterval) -> *mut ExUnitPrices {
    let val1 = unsafe {
        assert!(!mem_price.is_null());
        &mut* mem_price
    };

    let val2 = unsafe {
        assert!(!step_price.is_null());
        &mut* step_price
    };

    Box::into_raw(Box::new(ExUnitPrices::new(val1, val2)))
}

#[no_mangle]
pub extern "C" fn ex_unit_prices_free(ptr: *mut ExUnitPrices) {
    assert!(!ptr.is_null());

    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn ex_unit_prices_mem_price(ptr: *mut ExUnitPrices) -> *mut UnitInterval {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return Box::into_raw(Box::new(val.mem_price()));
}

#[no_mangle]
pub extern "C" fn ex_unit_prices_step_price(ptr: *mut ExUnitPrices) -> *mut UnitInterval {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return Box::into_raw(Box::new(val.step_price()));
}

#[no_mangle]
pub extern "C" fn ex_unit_prices_to_bytes(ptr: *mut ExUnitPrices) -> *mut CBuffer {
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
pub extern "C" fn ex_unit_prices_from_bytes(ptr: *mut u8, size: usize) -> *mut CResult  {
    assert!(!ptr.is_null());
    assert!(size > 0);

    let v = unsafe { core::slice::from_raw_parts(ptr, size as usize).to_vec() };

    let ret = match ExUnitPrices::from_bytes(v) {
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
pub extern "C" fn ex_unit_prices_from_json(int_str: *const c_char) -> *mut CResult {
    assert!(!int_str.is_null());

    let data_c_str: &CStr = unsafe { CStr::from_ptr(int_str) };
    let data_str_slice: &str = data_c_str.to_str().unwrap();

    let result = ExUnitPrices::from_json(data_str_slice);

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
pub extern "C" fn ex_unit_prices_to_json(ptr: *mut ExUnitPrices) -> *mut CResult {
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
