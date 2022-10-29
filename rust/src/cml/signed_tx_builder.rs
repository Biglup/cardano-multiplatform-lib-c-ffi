/**
export class SignedTxBuilder {

    static __wrap(ptr) {
        const obj = Object.create(SignedTxBuilder.prototype);
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
        wasm.__wbg_signedtxbuilder_free(ptr);
    }
    /**
    * @param {TransactionBody} body
    * @param {TransactionWitnessSetBuilder} witness_set
    * @param {boolean} is_valid
    * @param {AuxiliaryData} auxiliary_data
    * @returns {SignedTxBuilder}
    */
    static new_with_data(body, witness_set, is_valid, auxiliary_data) {
        _assertClass(body, TransactionBody);
        _assertClass(witness_set, TransactionWitnessSetBuilder);
        _assertClass(auxiliary_data, AuxiliaryData);
        const ret = wasm.signedtxbuilder_new_with_data(body.ptr, witness_set.ptr, is_valid, auxiliary_data.ptr);
        return SignedTxBuilder.__wrap(ret);
    }
    /**
    * @param {TransactionBody} body
    * @param {TransactionWitnessSetBuilder} witness_set
    * @param {boolean} is_valid
    * @returns {SignedTxBuilder}
    */
    static new_without_data(body, witness_set, is_valid) {
        _assertClass(body, TransactionBody);
        _assertClass(witness_set, TransactionWitnessSetBuilder);
        const ret = wasm.signedtxbuilder_new_without_data(body.ptr, witness_set.ptr, is_valid);
        return SignedTxBuilder.__wrap(ret);
    }
    /**
    * @returns {Transaction}
    */
    build_checked() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.signedtxbuilder_build_checked(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return Transaction.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {Transaction}
    */
    build_unchecked() {
        const ret = wasm.signedtxbuilder_build_unchecked(this.ptr);
        return Transaction.__wrap(ret);
    }
    /**
    * @param {Vkeywitness} vkey
    */
    add_vkey(vkey) {
        _assertClass(vkey, Vkeywitness);
        wasm.signedtxbuilder_add_vkey(this.ptr, vkey.ptr);
    }
    /**
    * @param {BootstrapWitness} bootstrap
    */
    add_bootstrap(bootstrap) {
        _assertClass(bootstrap, BootstrapWitness);
        wasm.signedtxbuilder_add_bootstrap(this.ptr, bootstrap.ptr);
    }
    /**
    * @returns {TransactionBody}
    */
    body() {
        const ret = wasm.signedtxbuilder_body(this.ptr);
        return TransactionBody.__wrap(ret);
    }
    /**
    * @returns {TransactionWitnessSetBuilder}
    */
    witness_set() {
        const ret = wasm.signedtxbuilder_witness_set(this.ptr);
        return TransactionWitnessSetBuilder.__wrap(ret);
    }
    /**
    * @returns {boolean}
    */
    is_valid() {
        const ret = wasm.signedtxbuilder_is_valid(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {AuxiliaryData | undefined}
    */
    auxiliary_data() {
        const ret = wasm.signedtxbuilder_auxiliary_data(this.ptr);
        return ret === 0 ? undefined : AuxiliaryData.__wrap(ret);
    }
}