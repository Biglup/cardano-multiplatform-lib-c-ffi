/**
* We introduce a builder-pattern format for creating transaction outputs
* This is because:
* 1. Some fields (i.e. data hash) are optional, and we can't easily expose Option<> in WASM
* 2. Some fields like amounts have many ways it could be set (some depending on other field values being known)
* 3. Easier to adapt as the output format gets more complicated in future Cardano releases
export class TransactionOutputBuilder {

    static __wrap(ptr) {
        const obj = Object.create(TransactionOutputBuilder.prototype);
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
        wasm.__wbg_transactionoutputbuilder_free(ptr);
    }
    /**
    * @returns {TransactionOutputBuilder}
    */
    static new() {
        const ret = wasm.transactionoutputbuilder_new();
        return TransactionOutputBuilder.__wrap(ret);
    }
    /**
    * @param {Address} address
    * @returns {TransactionOutputBuilder}
    */
    with_address(address) {
        _assertClass(address, Address);
        const ret = wasm.transactionoutputbuilder_with_address(this.ptr, address.ptr);
        return TransactionOutputBuilder.__wrap(ret);
    }
    /**
    * A communication datum is one where the data hash is used in the tx output
    * Yet the full datum is included in the witness of the same transaction
    * @param {PlutusData} datum
    * @returns {TransactionOutputBuilder}
    */
    with_communication_data(datum) {
        _assertClass(datum, PlutusData);
        const ret = wasm.transactionoutputbuilder_with_communication_data(this.ptr, datum.ptr);
        return TransactionOutputBuilder.__wrap(ret);
    }
    /**
    * @param {Datum} datum
    * @returns {TransactionOutputBuilder}
    */
    with_data(datum) {
        _assertClass(datum, Datum);
        const ret = wasm.transactionoutputbuilder_with_data(this.ptr, datum.ptr);
        return TransactionOutputBuilder.__wrap(ret);
    }
    /**
    * @param {ScriptRef} script_ref
    * @returns {TransactionOutputBuilder}
    */
    with_reference_script(script_ref) {
        _assertClass(script_ref, ScriptRef);
        const ret = wasm.transactionoutputbuilder_with_reference_script(this.ptr, script_ref.ptr);
        return TransactionOutputBuilder.__wrap(ret);
    }
    /**
    * @returns {TransactionOutputAmountBuilder}
    */
    next() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionoutputbuilder_next(retptr, this.ptr);
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
}