extern crate cardano_multiplatform_lib;
extern crate libc;

use cardano_multiplatform_lib::ledger::alonzo::fees::LinearFee;
use cardano_multiplatform_lib::ledger::common::value::BigNum;

#[no_mangle]
pub extern "C" fn linear_fee_free(ptr: *mut LinearFee) {
    assert!(!ptr.is_null());

    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn linear_fee_new(coefficient: *mut BigNum, constant: *mut BigNum) -> *mut LinearFee {
    let val = unsafe {
        assert!(!coefficient.is_null());
        &mut *coefficient
    };

    let val2 = unsafe {
        assert!(!constant.is_null());
        &mut *constant
    };

    return Box::into_raw(Box::new(LinearFee::new(val, val2)));
}

#[no_mangle]
pub extern "C" fn linear_fee_coefficient(ptr: *mut LinearFee) -> *mut BigNum {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    Box::into_raw(Box::new(val.coefficient()))
}

#[no_mangle]
pub extern "C" fn linear_fee_constant(ptr: *mut LinearFee) -> *mut BigNum {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    Box::into_raw(Box::new(val.constant()))

}