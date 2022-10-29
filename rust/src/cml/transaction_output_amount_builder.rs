/**
export class TransactionOutputAmountBuilder {

    static __wrap(ptr) {
        const obj = Object.create(TransactionOutputAmountBuilder.prototype);
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
        wasm.__wbg_transactionoutputamountbuilder_free(ptr);
    }
    /**
    * @param {Value} amount
    * @returns {TransactionOutputAmountBuilder}
    */
    with_value(amount) {
        _assertClass(amount, Value);
        const ret = wasm.transactionoutputamountbuilder_with_value(this.ptr, amount.ptr);
        return TransactionOutputAmountBuilder.__wrap(ret);
    }
    /**
    * @param {BigNum} coin
    * @returns {TransactionOutputAmountBuilder}
    */
    with_coin(coin) {
        _assertClass(coin, BigNum);
        const ret = wasm.transactionoutputamountbuilder_with_coin(this.ptr, coin.ptr);
        return TransactionOutputAmountBuilder.__wrap(ret);
    }
    /**
    * @param {BigNum} coin
    * @param {MultiAsset} multiasset
    * @returns {TransactionOutputAmountBuilder}
    */
    with_coin_and_asset(coin, multiasset) {
        _assertClass(coin, BigNum);
        _assertClass(multiasset, MultiAsset);
        const ret = wasm.transactionoutputamountbuilder_with_coin_and_asset(this.ptr, coin.ptr, multiasset.ptr);
        return TransactionOutputAmountBuilder.__wrap(ret);
    }
    /**
    * @param {MultiAsset} multiasset
    * @param {BigNum} coins_per_utxo_byte
    * @param {BigNum | undefined} coins_per_utxo_word
    * @returns {TransactionOutputAmountBuilder}
    */
    with_asset_and_min_required_coin(multiasset, coins_per_utxo_byte, coins_per_utxo_word) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(multiasset, MultiAsset);
            _assertClass(coins_per_utxo_byte, BigNum);
            let ptr0 = 0;
            if (!isLikeNone(coins_per_utxo_word)) {
                _assertClass(coins_per_utxo_word, BigNum);
                ptr0 = coins_per_utxo_word.ptr;
                coins_per_utxo_word.ptr = 0;
            }
            wasm.transactionoutputamountbuilder_with_asset_and_min_required_coin(retptr, this.ptr, multiasset.ptr, coins_per_utxo_byte.ptr, ptr0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionOutputAmountBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {SingleOutputBuilderResult}
    */
    build() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionoutputamountbuilder_build(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return SingleOutputBuilderResult.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}