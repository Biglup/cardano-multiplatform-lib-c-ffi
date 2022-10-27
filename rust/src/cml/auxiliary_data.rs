/**
export class AuxiliaryData {

    static __wrap(ptr) {
        const obj = Object.create(AuxiliaryData.prototype);
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
        wasm.__wbg_auxiliarydata_free(ptr);
    }
    /**
    * Add a single metadatum using TransactionMetadatum object under `key` TranscactionMetadatumLabel
    * @param {BigNum} key
    * @param {TransactionMetadatum} value
    */
    add_metadatum(key, value) {
        _assertClass(key, BigNum);
        _assertClass(value, TransactionMetadatum);
        wasm.auxiliarydata_add_metadatum(this.ptr, key.ptr, value.ptr);
    }
    /**
    * Add a single JSON metadatum using a MetadataJsonSchema object and MetadataJsonScehma object.
    * @param {BigNum} key
    * @param {string} val
    * @param {number} schema
    */
    add_json_metadatum_with_schema(key, val, schema) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(key, BigNum);
            const ptr0 = passStringToWasm0(val, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.auxiliarydata_add_json_metadatum_with_schema(retptr, this.ptr, key.ptr, ptr0, len0, schema);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {AuxiliaryData} other
    */
    add(other) {
        _assertClass(other, AuxiliaryData);
        wasm.auxiliarydata_add(this.ptr, other.ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.auxiliarydata_to_bytes(retptr, this.ptr);
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
    * @returns {AuxiliaryData}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.auxiliarydata_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return AuxiliaryData.__wrap(r0);
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
            wasm.auxiliarydata_to_json(retptr, this.ptr);
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
            wasm.auxiliarydata_to_js_value(retptr, this.ptr);
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
    * @returns {AuxiliaryData}
    */
    static from_json(json) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.auxiliarydata_from_json(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return AuxiliaryData.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {AuxiliaryData}
    */
    static new() {
        const ret = wasm.auxiliarydata_new();
        return AuxiliaryData.__wrap(ret);
    }
    /**
    * @returns {GeneralTransactionMetadata | undefined}
    */
    metadata() {
        const ret = wasm.auxiliarydata_metadata(this.ptr);
        return ret === 0 ? undefined : GeneralTransactionMetadata.__wrap(ret);
    }
    /**
    * @param {GeneralTransactionMetadata} metadata
    */
    set_metadata(metadata) {
        _assertClass(metadata, GeneralTransactionMetadata);
        wasm.auxiliarydata_set_metadata(this.ptr, metadata.ptr);
    }
    /**
    * @returns {NativeScripts | undefined}
    */
    native_scripts() {
        const ret = wasm.auxiliarydata_native_scripts(this.ptr);
        return ret === 0 ? undefined : NativeScripts.__wrap(ret);
    }
    /**
    * @param {NativeScripts} native_scripts
    */
    set_native_scripts(native_scripts) {
        _assertClass(native_scripts, NativeScripts);
        wasm.auxiliarydata_set_native_scripts(this.ptr, native_scripts.ptr);
    }
    /**
    * @returns {PlutusV1Scripts | undefined}
    */
    plutus_v1_scripts() {
        const ret = wasm.auxiliarydata_plutus_v1_scripts(this.ptr);
        return ret === 0 ? undefined : PlutusV1Scripts.__wrap(ret);
    }
    /**
    * @param {PlutusV1Scripts} plutus_v1_scripts
    */
    set_plutus_v1_scripts(plutus_v1_scripts) {
        _assertClass(plutus_v1_scripts, PlutusV1Scripts);
        wasm.auxiliarydata_set_plutus_v1_scripts(this.ptr, plutus_v1_scripts.ptr);
    }
    /**
    * @returns {PlutusV2Scripts | undefined}
    */
    plutus_v2_scripts() {
        const ret = wasm.auxiliarydata_plutus_v2_scripts(this.ptr);
        return ret === 0 ? undefined : PlutusV2Scripts.__wrap(ret);
    }
    /**
    * @param {PlutusV2Scripts} plutus_v2_scripts
    */
    set_plutus_v2_scripts(plutus_v2_scripts) {
        _assertClass(plutus_v2_scripts, PlutusV2Scripts);
        wasm.auxiliarydata_set_plutus_v2_scripts(this.ptr, plutus_v2_scripts.ptr);
    }
}