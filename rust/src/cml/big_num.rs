
mod utils;

extern crate cardano_multiplatform_lib;
extern crate libc;

use cardano_multiplatform_lib::ledger::common::value::BigNum;
use crate::utils::CResult;
use crate::utils::CBuffer;sdasd

#[no_mangle]
pub extern "C" fn big_num_free(ptr: *mut BigNum) {
    assert!(!ptr.is_null());

    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn big_num_to_bytes(ptr: *mut BigNum) -> CBuffer {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    let     result = big_num.to_bytes();
    let mut buf    = result.into_boxed_slice();
    let     data   = buf.as_mut_ptr();
    let     len    = buf.len() as i32;

    std::mem::forget(buf);
    Buffer { len, data }
}

#[no_mangle]
pub extern "C" fn big_num_from_bytes(ptr: *mut u8, size: usize) -> CResult  {
    assert!(!ptr.is_null());
    assert!(size >= 0);

    unsafe {
        let v = slice::from_raw_parts(ptr, size as usize).to_vec();
        return Box::into_raw(Box::new(BigNum::from_bytes(v)));
    }

    match BigNum::from_bytes(v) {
        Ok(bigNum) => CResult {
            result:    Box::into_raw(Box::new(bigNum)),
            has_error: 0,
            error_msg: std::ptr::null_mut()
        },
        Err(message) => CResult {
            result:    std::ptr::null_mut(),
            has_error: 1,
            error_msg: message.to_string()
        }
}

#[no_mangle]
pub extern "C" fn big_num_from_string(big_num_str: *const c_char) -> CResult {
    assert!(!big_num_str.is_null());

    let c_str:     &CStr  = unsafe { CStr::from_ptr(big_num_str) };
    let str_slice: &str   = c_str.to_str().unwrap();
    let str_buf:   String = str_slice.to_owned(); 
   
    let result = BigNum::from_str(str_buf);

    match result {
        Ok(v) => CResult {
            result:    Box::into_raw(Box::new(v)),
            has_error: 0,
            error_msg: std::ptr::null_mut()
        },
        Err(jsValue) => CResult {
            result:    std::ptr::null_mut(),
            has_error: 1,
            error_msg: get_error_message(jsValue)
        }
    };
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
pub extern "C" fn big_num_is_zero(ptr: *mut BigNum) -> boolean  {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    big_num.is_zero();
}


#[no_mangle]
pub extern "C" fn big_num_checked_mul(ptr: *mut BigNum, other: *mut BigNum) -> CResult {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_big_num = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    let result = big_num.checked_mul(other_big_num);

    match result {
        Ok(v) => CResult {
            result: Box::into_raw(Box::new(v)),
            has_error: 0,
            error_msg: std::ptr::null_mut()
        },
        Err(jsValue) => CResult {
            result: std::ptr::null_mut(),
            has_error: 1,
            error_msg: get_error_message(jsValue)
        }
    };
}

#[no_mangle]
pub extern "C" fn big_num_checked_add(ptr: *mut BigNum, other: *mut BigNum) -> CResult {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_big_num = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    let result = big_num.checked_add(other_big_num);

    match result {
        Ok(v) => CResult {
            result: Box::into_raw(Box::new(v)),
            has_error: 0,
            error_msg: std::ptr::null_mut()
        },
        Err(jsValue) => CResult {
            result: std::ptr::null_mut(),
            has_error: 1,
            error_msg: get_error_message(jsValue)
        }
    };
}

#[no_mangle]
pub extern "C" fn big_num_checked_sub(ptr: *mut BigNum, other: *mut BigNum) -> CResult {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_big_num = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    let result = big_num.checked_sub(other_big_num);

    match result {
        Ok(v) => CResult {
            result: Box::into_raw(Box::new(v)),
            has_error: 0,
            error_msg: std::ptr::null_mut()
        },
        Err(jsValue) => CResult {
            result: std::ptr::null_mut(),
            has_error: 1,
            error_msg: get_error_message(jsValue)
        }
    };
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

    Box::into_raw(Box::new(big_num.clamped_sub(other_big_num)))
}

#[no_mangle]
pub extern "C" fn big_num_checked_div(ptr: *mut BigNum, other: *mut BigNum) -> CResult {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_big_num = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    let result = big_num.checked_div(other_big_num);

    match result {
        Ok(v) => CResult {
            result: Box::into_raw(Box::new(v)),
            has_error: 0,
            error_msg: std::ptr::null_mut()
        },
        Err(jsValue) => CResult {
            result: std::ptr::null_mut(),
            has_error: 1,
            error_msg: get_error_message(jsValue)
        }
    };
}

#[no_mangle]
pub extern "C" fn big_num_checked_div_ceil(ptr: *mut BigNum, other: *mut BigNum) -> CResult {
    let big_num = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let other_big_num = unsafe {
        assert!(!other.is_null());
        &mut* other
    };

    let result = big_num.checked_div_ceil(other_big_num);

    match result {
        Ok(v) => CResult {
            result: Box::into_raw(Box::new(v)),
            has_error: 0,
            error_msg: std::ptr::null_mut()
        },
        Err(jsValue) => CResult {
            result: std::ptr::null_mut(),
            has_error: 1,
            error_msg: get_error_message(jsValue)
        }
    };
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

    big_num.compare(other_big_num);
}