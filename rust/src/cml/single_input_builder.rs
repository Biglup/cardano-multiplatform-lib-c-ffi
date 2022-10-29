/**
export class SingleInputBuilder {

    static __wrap(ptr) {
        const obj = Object.create(SingleInputBuilder.prototype);
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
        wasm.__wbg_singleinputbuilder_free(ptr);
    }
    /**
    * @param {TransactionInput} input
    * @param {TransactionOutput} utxo_info
    * @returns {SingleInputBuilder}
    */
    static new(input, utxo_info) {
        _assertClass(input, TransactionInput);
        _assertClass(utxo_info, TransactionOutput);
        const ret = wasm.singleinputbuilder_new(input.ptr, utxo_info.ptr);
        return SingleInputBuilder.__wrap(ret);
    }
    /**
    * @returns {InputBuilderResult}
    */
    payment_key() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.singleinputbuilder_payment_key(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return InputBuilderResult.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {NativeScript} native_script
    * @param {NativeScriptWitnessInfo} witness_info
    * @returns {InputBuilderResult}
    */
    native_script(native_script, witness_info) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(native_script, NativeScript);
            _assertClass(witness_info, NativeScriptWitnessInfo);
            wasm.singleinputbuilder_native_script(retptr, this.ptr, native_script.ptr, witness_info.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return InputBuilderResult.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {PartialPlutusWitness} partial_witness
    * @param {Ed25519KeyHashes} required_signers
    * @param {PlutusData} datum
    * @returns {InputBuilderResult}
    */
    plutus_script(partial_witness, required_signers, datum) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(partial_witness, PartialPlutusWitness);
            _assertClass(required_signers, Ed25519KeyHashes);
            _assertClass(datum, PlutusData);
            wasm.singleinputbuilder_plutus_script(retptr, this.ptr, partial_witness.ptr, required_signers.ptr, datum.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return InputBuilderResult.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}