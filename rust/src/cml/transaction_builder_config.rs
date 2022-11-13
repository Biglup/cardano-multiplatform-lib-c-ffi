extern crate cardano_multiplatform_lib;
extern crate libc;
use libc::c_char;
use std::ffi::CString;

use cardano_multiplatform_lib::builders::tx_builder::TransactionBuilderConfig;

#[no_mangle]
pub extern "C" fn transaction_builder_config_free(ptr: *mut TransactionBuilderConfig) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn transaction_builder_config_to_string(ptr: *mut TransactionBuilderConfig) -> *const c_char {
    let config = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let result = format!("{:?}", config);

    let s = CString::new(result).unwrap();
    let p = s.as_ptr();
    std::mem::forget(s);
    return p;
}