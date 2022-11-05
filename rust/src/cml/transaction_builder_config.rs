mod utils;

extern crate cardano_multiplatform_lib;
extern crate libc;

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