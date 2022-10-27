/**
export class Mint {

    static __wrap(ptr) {
        const obj = Object.create(Mint.prototype);
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
        wasm.__wbg_mint_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.mint_to_bytes(retptr, this.ptr);
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
    * @returns {Mint}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.mint_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return Mint.__wrap(r0);
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
            wasm.mint_to_json(retptr, this.ptr);
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
            wasm.mint_to_js_value(retptr, this.ptr);
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
    * @returns {Mint}
    */
    static from_json(json) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.mint_from_json(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return Mint.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {Mint}
    */
    static new() {
        const ret = wasm.mint_new();
        return Mint.__wrap(ret);
    }
    /**
    * @param {ScriptHash} key
    * @param {MintAssets} value
    * @returns {Mint}
    */
    static new_from_entry(key, value) {
        _assertClass(key, ScriptHash);
        _assertClass(value, MintAssets);
        const ret = wasm.mint_new_from_entry(key.ptr, value.ptr);
        return Mint.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    len() {
        const ret = wasm.mint_len(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {ScriptHash} key
    * @param {MintAssets} value
    * @returns {MintAssets | undefined}
    */
    insert(key, value) {
        _assertClass(key, ScriptHash);
        _assertClass(value, MintAssets);
        const ret = wasm.mint_insert(this.ptr, key.ptr, value.ptr);
        return ret === 0 ? undefined : MintAssets.__wrap(ret);
    }
    /**
    * @param {ScriptHash} key
    * @returns {MintAssets | undefined}
    */
    get(key) {
        _assertClass(key, ScriptHash);
        const ret = wasm.mint_get(this.ptr, key.ptr);
        return ret === 0 ? undefined : MintAssets.__wrap(ret);
    }
    /**
    * @returns {ScriptHashes}
    */
    keys() {
        const ret = wasm.mint_keys(this.ptr);
        return ScriptHashes.__wrap(ret);
    }
    /**
    * Returns the multiasset where only positive (minting) entries are present
    * @returns {MultiAsset}
    */
    as_positive_multiasset() {
        const ret = wasm.mint_as_positive_multiasset(this.ptr);
        return MultiAsset.__wrap(ret);
    }
    /**
    * Returns the multiasset where only negative (burning) entries are present
    * @returns {MultiAsset}
    */
    as_negative_multiasset() {
        const ret = wasm.mint_as_negative_multiasset(this.ptr);
        return MultiAsset.__wrap(ret);
    }
}