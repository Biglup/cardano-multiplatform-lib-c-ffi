extern crate cardano_multiplatform_lib;
extern crate libc;

use cardano_multiplatform_lib::ledger::common::value::BigNum;
use cardano_multiplatform_lib::builders::tx_builder::TransactionBuilderConfigBuilder;
use cardano_multiplatform_lib::ledger::alonzo::fees::LinearFee;
use cardano_multiplatform_lib::plutus::ExUnitPrices;
use cardano_multiplatform_lib::plutus::Costmdls;

use crate::utils::CResult;
use crate::utils::get_error_message;

#[no_mangle]
pub extern "C" fn transaction_builder_config_builder_new() -> *mut TransactionBuilderConfigBuilder {
    Box::into_raw(Box::new(TransactionBuilderConfigBuilder::new()))
}

#[no_mangle]
pub extern "C" fn transaction_builder_config_builder_free(ptr: *mut TransactionBuilderConfigBuilder) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn transaction_builder_config_builder_fee_algo(ptr: *mut TransactionBuilderConfigBuilder, param1: *mut LinearFee)  -> *mut TransactionBuilderConfigBuilder {
    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let val2 = unsafe {
        assert!(!param1.is_null());
        &mut* param1
    };

    Box::into_raw(Box::new(val1.fee_algo(val2)))
}

#[no_mangle]
pub extern "C" fn transaction_builder_config_builder_coins_per_utxo_byte(ptr: *mut TransactionBuilderConfigBuilder, param1: *mut BigNum)  -> *mut TransactionBuilderConfigBuilder {
    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let val2 = unsafe {
        assert!(!param1.is_null());
        &mut* param1
    };

    Box::into_raw(Box::new(val1.coins_per_utxo_byte(val2)))
}

#[no_mangle]
pub extern "C" fn transaction_builder_config_builder_pool_deposit(ptr: *mut TransactionBuilderConfigBuilder, param1: *mut BigNum)  -> *mut TransactionBuilderConfigBuilder {
    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let val2 = unsafe {
        assert!(!param1.is_null());
        &mut* param1
    };

    Box::into_raw(Box::new(val1.pool_deposit(val2)))
}

#[no_mangle]
pub extern "C" fn transaction_builder_config_builder_key_deposit(ptr: *mut TransactionBuilderConfigBuilder, param1: *mut BigNum)  -> *mut TransactionBuilderConfigBuilder {
    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let val2 = unsafe {
        assert!(!param1.is_null());
        &mut* param1
    };

    Box::into_raw(Box::new(val1.key_deposit(val2)))
}

#[no_mangle]
pub extern "C" fn transaction_builder_config_builder_max_value_size(ptr: *mut TransactionBuilderConfigBuilder, param1: u32)  -> *mut TransactionBuilderConfigBuilder {
    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    Box::into_raw(Box::new(val1.max_value_size(param1)))
}

#[no_mangle]
pub extern "C" fn transaction_builder_config_builder_max_tx_size(ptr: *mut TransactionBuilderConfigBuilder, param1: u32)  -> *mut TransactionBuilderConfigBuilder {
    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    Box::into_raw(Box::new(val1.max_tx_size(param1)))
}

#[no_mangle]
pub extern "C" fn transaction_builder_config_builder_prefer_pure_change(ptr: *mut TransactionBuilderConfigBuilder, param1: u32)  -> *mut TransactionBuilderConfigBuilder {
    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    Box::into_raw(Box::new(val1.prefer_pure_change(param1 != 0)))
}

#[no_mangle]
pub extern "C" fn transaction_builder_config_builder_ex_unit_prices(ptr: *mut TransactionBuilderConfigBuilder, param1: *mut ExUnitPrices)  -> *mut TransactionBuilderConfigBuilder {
    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let val2 = unsafe {
        assert!(!param1.is_null());
        &mut* param1
    };

    Box::into_raw(Box::new(val1.ex_unit_prices(val2)))
}

#[no_mangle]
pub extern "C" fn transaction_builder_config_builder_costmdls(ptr: *mut TransactionBuilderConfigBuilder, param1: *mut Costmdls)  -> *mut TransactionBuilderConfigBuilder {
    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let val2 = unsafe {
        assert!(!param1.is_null());
        &mut* param1
    };

    Box::into_raw(Box::new(val1.costmdls(val2)))
}

#[no_mangle]
pub extern "C" fn transaction_builder_config_builder_collateral_percentage(ptr: *mut TransactionBuilderConfigBuilder, param1: u32)  -> *mut TransactionBuilderConfigBuilder {
    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    Box::into_raw(Box::new(val1.collateral_percentage(param1)))
}

#[no_mangle]
pub extern "C" fn transaction_builder_config_builder_max_collateral_inputs(ptr: *mut TransactionBuilderConfigBuilder, param1: u32)  -> *mut TransactionBuilderConfigBuilder {
    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    Box::into_raw(Box::new(val1.max_collateral_inputs(param1)))
}

#[no_mangle]
pub extern "C" fn transaction_builder_config_builder_build(ptr: *mut TransactionBuilderConfigBuilder)  -> *mut CResult {
    let val1 = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let result = val1.build();

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
