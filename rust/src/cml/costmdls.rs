extern crate cardano_multiplatform_lib;
extern crate libc;
use libc::c_char;
use std::ffi::CStr;

use cardano_multiplatform_lib::plutus::Language;
use cardano_multiplatform_lib::plutus::Languages;
use cardano_multiplatform_lib::plutus::CostModel;
use cardano_multiplatform_lib::plutus::Costmdls;

use crate::utils::CResult;
use crate::utils::CBuffer;
use crate::utils::COption;
use crate::utils::get_error_message;
use crate::utils::to_c_str;

#[no_mangle]
pub extern "C" fn costmdls_new() -> *mut Costmdls {
    return Box::into_raw(Box::new(Costmdls::new()));
}

#[no_mangle]
pub extern "C" fn costmdls_free(ptr: *mut Costmdls) {
    assert!(!ptr.is_null());

    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn costmdls_len(ptr: *mut Costmdls) -> usize {
    assert!(!ptr.is_null());

    let val = unsafe {
        assert!(!ptr.is_null());
        &*ptr
    };

    return val.len();
}


#[no_mangle]
pub extern "C" fn costmdls_insert(ptr: *mut Costmdls, value: *mut CostModel) -> *mut COption {
    assert!(!ptr.is_null());
    assert!(!value.is_null());

    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let val2 = unsafe {
        assert!(!value.is_null());
        &mut* value
    };

    let result = val1.insert(val2);

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
pub extern "C" fn costmdls_get(ptr: *mut Costmdls, key: *mut Language) -> *mut COption {
    assert!(!ptr.is_null());
    assert!(!key.is_null());

    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let val2 = unsafe {
        assert!(!key.is_null());
        &mut* key
    };

    let result = val1.get(val2);

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
pub extern "C" fn costmdls_keys(ptr: *mut Costmdls) -> *mut Languages {
    assert!(!ptr.is_null());

    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    return Box::into_raw(Box::new(val1.keys()));
}

#[no_mangle]
pub extern "C" fn costmdls_to_bytes(ptr: *mut Costmdls) -> *mut CBuffer {
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
pub extern "C" fn costmdls_from_bytes(ptr: *mut u8, size: usize) -> *mut CResult  {
    assert!(!ptr.is_null());
    assert!(size > 0);

    let v = unsafe { core::slice::from_raw_parts(ptr, size as usize).to_vec() };

    let ret = match Costmdls::from_bytes(v) {
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
pub extern "C" fn costmdls_from_json(int_str: *const c_char) -> *mut CResult {
    assert!(!int_str.is_null());

    let data_c_str: &CStr = unsafe { CStr::from_ptr(int_str) };
    let data_str_slice: &str = data_c_str.to_str().unwrap();

    let result = Costmdls::from_json(data_str_slice);

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
pub extern "C" fn costmdls_to_json(ptr: *mut Costmdls) -> *mut CResult {
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