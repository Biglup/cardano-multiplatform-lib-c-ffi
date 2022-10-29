/**
export class SingleWithdrawalBuilder {

    static __wrap(ptr) {
        const obj = Object.create(SingleWithdrawalBuilder.prototype);
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
        wasm.__wbg_singlewithdrawalbuilder_free(ptr);
    }
    /**
    * @param {RewardAddress} address
    * @param {BigNum} amount
    * @returns {SingleWithdrawalBuilder}
    */
    static new(address, amount) {
        _assertClass(address, RewardAddress);
        _assertClass(amount, BigNum);
        const ret = wasm.singlewithdrawalbuilder_new(address.ptr, amount.ptr);
        return SingleWithdrawalBuilder.__wrap(ret);
    }
    /**
    * @returns {WithdrawalBuilderResult}
    */
    payment_key() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.singlewithdrawalbuilder_payment_key(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return WithdrawalBuilderResult.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {NativeScript} native_script
    * @param {NativeScriptWitnessInfo} witness_info
    * @returns {WithdrawalBuilderResult}
    */
    native_script(native_script, witness_info) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(native_script, NativeScript);
            _assertClass(witness_info, NativeScriptWitnessInfo);
            wasm.singlewithdrawalbuilder_native_script(retptr, this.ptr, native_script.ptr, witness_info.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return WithdrawalBuilderResult.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {PartialPlutusWitness} partial_witness
    * @param {Ed25519KeyHashes} required_signers
    * @returns {WithdrawalBuilderResult}
    */
    plutus_script(partial_witness, required_signers) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(partial_witness, PartialPlutusWitness);
            _assertClass(required_signers, Ed25519KeyHashes);
            wasm.singlewithdrawalbuilder_plutus_script(retptr, this.ptr, partial_witness.ptr, required_signers.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return WithdrawalBuilderResult.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}