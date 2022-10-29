/**
export class Script {

    static __wrap(ptr) {
        const obj = Object.create(Script.prototype);
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
        wasm.__wbg_script_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.script_to_bytes(retptr, this.ptr);
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
    * @returns {Script}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.script_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return Script.__wrap(r0);
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
            wasm.script_to_json(retptr, this.ptr);
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
            wasm.script_to_js_value(retptr, this.ptr);
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
    * @returns {Script}
    */
    static from_json(json) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.script_from_json(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return Script.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {NativeScript} native_script
    * @returns {Script}
    */
    static new_native(native_script) {
        _assertClass(native_script, NativeScript);
        const ret = wasm.script_new_native(native_script.ptr);
        return Script.__wrap(ret);
    }
    /**
    * @param {PlutusV1Script} plutus_script
    * @returns {Script}
    */
    static new_plutus_v1(plutus_script) {
        _assertClass(plutus_script, PlutusV1Script);
        const ret = wasm.script_new_plutus_v1(plutus_script.ptr);
        return Script.__wrap(ret);
    }
    /**
    * @param {PlutusV2Script} plutus_script
    * @returns {Script}
    */
    static new_plutus_v2(plutus_script) {
        _assertClass(plutus_script, PlutusV2Script);
        const ret = wasm.script_new_plutus_v2(plutus_script.ptr);
        return Script.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    kind() {
        const ret = wasm.script_kind(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {NativeScript | undefined}
    */
    as_native() {
        const ret = wasm.script_as_native(this.ptr);
        return ret === 0 ? undefined : NativeScript.__wrap(ret);
    }
    /**
    * @returns {PlutusV1Script | undefined}
    */
    as_plutus_v1() {
        const ret = wasm.script_as_plutus_v1(this.ptr);
        return ret === 0 ? undefined : PlutusV1Script.__wrap(ret);
    }
    /**
    * @returns {PlutusV2Script | undefined}
    */
    as_plutus_v2() {
        const ret = wasm.script_as_plutus_v2(this.ptr);
        return ret === 0 ? undefined : PlutusV2Script.__wrap(ret);
    }
    /**
    * @returns {ScriptHash}
    */
    hash() {
        const ret = wasm.script_hash(this.ptr);
        return ScriptHash.__wrap(ret);
    }
}