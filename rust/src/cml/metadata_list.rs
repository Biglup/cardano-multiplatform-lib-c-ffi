/**
export class MetadataList {

    static __wrap(ptr) {
        const obj = Object.create(MetadataList.prototype);
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
        wasm.__wbg_metadatalist_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.metadatalist_to_bytes(retptr, this.ptr);
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
    * @returns {MetadataList}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.metadatalist_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return MetadataList.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {MetadataList}
    */
    static new() {
        const ret = wasm.metadatalist_new();
        return MetadataList.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    len() {
        const ret = wasm.metadatalist_len(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} index
    * @returns {TransactionMetadatum}
    */
    get(index) {
        const ret = wasm.metadatalist_get(this.ptr, index);
        return TransactionMetadatum.__wrap(ret);
    }
    /**
    * @param {TransactionMetadatum} elem
    */
    add(elem) {
        _assertClass(elem, TransactionMetadatum);
        wasm.metadatalist_add(this.ptr, elem.ptr);
    }
}