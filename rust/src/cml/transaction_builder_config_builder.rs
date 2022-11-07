mod utils;

extern crate cardano_multiplatform_lib;
extern crate libc;

use cardano_multiplatform_lib::builders::tx_builder::TransactionBuilderConfig;
use cardano_multiplatform_lib::builders::tx_builder::TransactionBuilderConfigBuilder;

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
pub extern "C" fn network_info_network_id(ptr: *mut NetworkInfo) -> u8 {
    let network_info = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return network_info.network_id();
}

#[no_mangle]
pub extern "C" fn network_info_protocol_magic(ptr: *mut NetworkInfo) -> u32 {
    let network_info = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return network_info.protocol_magic();
}

#[no_mangle]
pub extern "C" fn network_info_testnet() -> *mut NetworkInfo {
    Box::into_raw(Box::new(NetworkInfo::testnet()))
}

#[no_mangle]
pub extern "C" fn network_info_mainnet() -> *mut NetworkInfo {
    Box::into_raw(Box::new(NetworkInfo::mainnet()))
}

/**
export class TransactionBuilderConfigBuilder {

    static __wrap(ptr) {
        const obj = Object.create(TransactionBuilderConfigBuilder.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_transactionbuilderconfigbuilder_free(ptr);
    }
    /**
    * @returns {TransactionBuilderConfigBuilder}
    */
    static new() {
        const ret = wasm.transactionbuilderconfigbuilder_new();
        return TransactionBuilderConfigBuilder.__wrap(ret);
    }
    /**
    * @param {LinearFee} fee_algo
    * @returns {TransactionBuilderConfigBuilder}
    */
    fee_algo(fee_algo) {
        _assertClass(fee_algo, LinearFee);
        const ret = wasm.transactionbuilderconfigbuilder_fee_algo(this.ptr, fee_algo.ptr);
        return TransactionBuilderConfigBuilder.__wrap(ret);
    }
    /**
    * @param {BigNum} coins_per_utxo_byte
    * @returns {TransactionBuilderConfigBuilder}
    */
    coins_per_utxo_byte(coins_per_utxo_byte) {
        _assertClass(coins_per_utxo_byte, BigNum);
        const ret = wasm.transactionbuilderconfigbuilder_coins_per_utxo_byte(this.ptr, coins_per_utxo_byte.ptr);
        return TransactionBuilderConfigBuilder.__wrap(ret);
    }
    /**
    * TODO: remove once Babbage is on mainnet
    * @param {BigNum} coins_per_utxo_word
    * @returns {TransactionBuilderConfigBuilder}
    */
    coins_per_utxo_word(coins_per_utxo_word) {
        _assertClass(coins_per_utxo_word, BigNum);
        const ret = wasm.transactionbuilderconfigbuilder_coins_per_utxo_word(this.ptr, coins_per_utxo_word.ptr);
        return TransactionBuilderConfigBuilder.__wrap(ret);
    }
    /**
    * @param {BigNum} pool_deposit
    * @returns {TransactionBuilderConfigBuilder}
    */
    pool_deposit(pool_deposit) {
        _assertClass(pool_deposit, BigNum);
        const ret = wasm.transactionbuilderconfigbuilder_pool_deposit(this.ptr, pool_deposit.ptr);
        return TransactionBuilderConfigBuilder.__wrap(ret);
    }
    /**
    * @param {BigNum} key_deposit
    * @returns {TransactionBuilderConfigBuilder}
    */
    key_deposit(key_deposit) {
        _assertClass(key_deposit, BigNum);
        const ret = wasm.transactionbuilderconfigbuilder_key_deposit(this.ptr, key_deposit.ptr);
        return TransactionBuilderConfigBuilder.__wrap(ret);
    }
    /**
    * @param {number} max_value_size
    * @returns {TransactionBuilderConfigBuilder}
    */
    max_value_size(max_value_size) {
        const ret = wasm.transactionbuilderconfigbuilder_max_value_size(this.ptr, max_value_size);
        return TransactionBuilderConfigBuilder.__wrap(ret);
    }
    /**
    * @param {number} max_tx_size
    * @returns {TransactionBuilderConfigBuilder}
    */
    max_tx_size(max_tx_size) {
        const ret = wasm.transactionbuilderconfigbuilder_max_tx_size(this.ptr, max_tx_size);
        return TransactionBuilderConfigBuilder.__wrap(ret);
    }
    /**
    * @param {boolean} prefer_pure_change
    * @returns {TransactionBuilderConfigBuilder}
    */
    prefer_pure_change(prefer_pure_change) {
        const ret = wasm.transactionbuilderconfigbuilder_prefer_pure_change(this.ptr, prefer_pure_change);
        return TransactionBuilderConfigBuilder.__wrap(ret);
    }
    /**
    * @param {ExUnitPrices} ex_unit_prices
    * @returns {TransactionBuilderConfigBuilder}
    */
    ex_unit_prices(ex_unit_prices) {
        _assertClass(ex_unit_prices, ExUnitPrices);
        const ret = wasm.transactionbuilderconfigbuilder_ex_unit_prices(this.ptr, ex_unit_prices.ptr);
        return TransactionBuilderConfigBuilder.__wrap(ret);
    }
    /**
    * @param {Costmdls} costmdls
    * @returns {TransactionBuilderConfigBuilder}
    */
    costmdls(costmdls) {
        _assertClass(costmdls, Costmdls);
        const ret = wasm.transactionbuilderconfigbuilder_costmdls(this.ptr, costmdls.ptr);
        return TransactionBuilderConfigBuilder.__wrap(ret);
    }
    /**
    * @param {number} collateral_percentage
    * @returns {TransactionBuilderConfigBuilder}
    */
    collateral_percentage(collateral_percentage) {
        const ret = wasm.transactionbuilderconfigbuilder_collateral_percentage(this.ptr, collateral_percentage);
        return TransactionBuilderConfigBuilder.__wrap(ret);
    }
    /**
    * @param {number} max_collateral_inputs
    * @returns {TransactionBuilderConfigBuilder}
    */
    max_collateral_inputs(max_collateral_inputs) {
        const ret = wasm.transactionbuilderconfigbuilder_max_collateral_inputs(this.ptr, max_collateral_inputs);
        return TransactionBuilderConfigBuilder.__wrap(ret);
    }
    /**
    * @returns {TransactionBuilderConfig}
    */
    build() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilderconfigbuilder_build(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionBuilderConfig.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}


