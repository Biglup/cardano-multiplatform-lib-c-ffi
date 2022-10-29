/**
export class SingleCertificateBuilder {

    static __wrap(ptr) {
        const obj = Object.create(SingleCertificateBuilder.prototype);
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
        wasm.__wbg_singlecertificatebuilder_free(ptr);
    }
    /**
    * @param {Certificate} cert
    * @returns {SingleCertificateBuilder}
    */
    static new(cert) {
        _assertClass(cert, Certificate);
        const ret = wasm.singlecertificatebuilder_new(cert.ptr);
        return SingleCertificateBuilder.__wrap(ret);
    }
    /**
    * note: particularly useful for StakeRegistration which doesn't require witnessing
    * @returns {CertificateBuilderResult}
    */
    skip_witness() {
        const ret = wasm.singlecertificatebuilder_skip_witness(this.ptr);
        return CertificateBuilderResult.__wrap(ret);
    }
    /**
    * @returns {CertificateBuilderResult}
    */
    payment_key() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.singlecertificatebuilder_payment_key(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return CertificateBuilderResult.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Signer keys don't have to be set. You can leave it empty and then add the required witnesses later
    * @param {NativeScript} native_script
    * @param {NativeScriptWitnessInfo} witness_info
    * @returns {CertificateBuilderResult}
    */
    native_script(native_script, witness_info) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(native_script, NativeScript);
            _assertClass(witness_info, NativeScriptWitnessInfo);
            wasm.singlecertificatebuilder_native_script(retptr, this.ptr, native_script.ptr, witness_info.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return CertificateBuilderResult.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {PartialPlutusWitness} partial_witness
    * @param {Ed25519KeyHashes} required_signers
    * @returns {CertificateBuilderResult}
    */
    plutus_script(partial_witness, required_signers) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(partial_witness, PartialPlutusWitness);
            _assertClass(required_signers, Ed25519KeyHashes);
            wasm.singlecertificatebuilder_plutus_script(retptr, this.ptr, partial_witness.ptr, required_signers.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return CertificateBuilderResult.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}