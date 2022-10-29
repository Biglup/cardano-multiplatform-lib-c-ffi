/**
export class SpendingData {

    static __wrap(ptr) {
        const obj = Object.create(SpendingData.prototype);
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
        wasm.__wbg_spendingdata_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.spendingdata_to_bytes(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var v0 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1);
            return v0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {SpendingData}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.spendingdata_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return SpendingData.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {string}
    */
    to_json() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.spendingdata_to_json(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            var r3 = getInt32Memory0()[retptr / 4 + 3];
            var ptr0 = r0;
            var len0 = r1;
            if (r3) {
                ptr0 = 0; len0 = 0;
                throw takeObject(r2);
            }
            return getStringFromWasm0(ptr0, len0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(ptr0, len0);
        }
    }
    /**
    * @returns {any}
    */
    to_js_value() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.spendingdata_to_js_value(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {string} json
    * @returns {SpendingData}
    */
    static from_json(json) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.spendingdata_from_json(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return SpendingData.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Bip32PublicKey} public_ed25519_bip32
    * @returns {SpendingData}
    */
    static new_spending_data_pub_key(public_ed25519_bip32) {
        _assertClass(public_ed25519_bip32, Bip32PublicKey);
        const ret = wasm.spendingdata_new_spending_data_pub_key(public_ed25519_bip32.ptr);
        return SpendingData.__wrap(ret);
    }
    /**
    * @param {ByronScript} script
    * @returns {SpendingData}
    */
    static new_spending_data_script(script) {
        _assertClass(script, ByronScript);
        const ret = wasm.spendingdata_new_spending_data_script(script.ptr);
        return SpendingData.__wrap(ret);
    }
    /**
    * @param {PublicKey} public_ed25519
    * @returns {SpendingData}
    */
    static new_spending_data_redeem(public_ed25519) {
        _assertClass(public_ed25519, PublicKey);
        const ret = wasm.spendingdata_new_spending_data_redeem(public_ed25519.ptr);
        return SpendingData.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    kind() {
        const ret = wasm.spendingdata_kind(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {SpendingDataPubKeyASD | undefined}
    */
    as_spending_data_pub_key() {
        const ret = wasm.spendingdata_as_spending_data_pub_key(this.ptr);
        return ret === 0 ? undefined : SpendingDataPubKeyASD.__wrap(ret);
    }
    /**
    * @returns {SpendingDataScriptASD | undefined}
    */
    as_spending_data_script() {
        const ret = wasm.spendingdata_as_spending_data_script(this.ptr);
        return ret === 0 ? undefined : SpendingDataScriptASD.__wrap(ret);
    }
    /**
    * @returns {SpendingDataRedeemASD | undefined}
    */
    as_spending_data_redeem() {
        const ret = wasm.spendingdata_as_spending_data_redeem(this.ptr);
        return ret === 0 ? undefined : SpendingDataRedeemASD.__wrap(ret);
    }
}