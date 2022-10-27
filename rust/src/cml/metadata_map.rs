/**
export class MetadataMap {

    static __wrap(ptr) {
        const obj = Object.create(MetadataMap.prototype);
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
        wasm.__wbg_metadatamap_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.metadatamap_to_bytes(retptr, this.ptr);
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
    * @returns {MetadataMap}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.metadatamap_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return MetadataMap.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {MetadataMap}
    */
    static new() {
        const ret = wasm.metadatamap_new();
        return MetadataMap.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    len() {
        const ret = wasm.metadatamap_len(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {TransactionMetadatum} key
    * @param {TransactionMetadatum} value
    * @returns {TransactionMetadatum | undefined}
    */
    insert(key, value) {
        _assertClass(key, TransactionMetadatum);
        _assertClass(value, TransactionMetadatum);
        const ret = wasm.metadatamap_insert(this.ptr, key.ptr, value.ptr);
        return ret === 0 ? undefined : TransactionMetadatum.__wrap(ret);
    }
    /**
    * @param {string} key
    * @param {TransactionMetadatum} value
    * @returns {TransactionMetadatum | undefined}
    */
    insert_str(key, value) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            _assertClass(value, TransactionMetadatum);
            wasm.metadatamap_insert_str(retptr, this.ptr, ptr0, len0, value.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return r0 === 0 ? undefined : TransactionMetadatum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {number} key
    * @param {TransactionMetadatum} value
    * @returns {TransactionMetadatum | undefined}
    */
    insert_i32(key, value) {
        _assertClass(value, TransactionMetadatum);
        const ret = wasm.metadatamap_insert_i32(this.ptr, key, value.ptr);
        return ret === 0 ? undefined : TransactionMetadatum.__wrap(ret);
    }
    /**
    * @param {TransactionMetadatum} key
    * @returns {TransactionMetadatum}
    */
    get(key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(key, TransactionMetadatum);
            wasm.metadatamap_get(retptr, this.ptr, key.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionMetadatum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {string} key
    * @returns {TransactionMetadatum}
    */
    get_str(key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.metadatamap_get_str(retptr, this.ptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionMetadatum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {number} key
    * @returns {TransactionMetadatum}
    */
    get_i32(key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.metadatamap_get_i32(retptr, this.ptr, key);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionMetadatum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {TransactionMetadatum} key
    * @returns {boolean}
    */
    has(key) {
        _assertClass(key, TransactionMetadatum);
        const ret = wasm.metadatamap_has(this.ptr, key.ptr);
        return ret !== 0;
    }
    /**
    * @returns {MetadataList}
    */
    keys() {
        const ret = wasm.metadatamap_keys(this.ptr);
        return MetadataList.__wrap(ret);
    }
}