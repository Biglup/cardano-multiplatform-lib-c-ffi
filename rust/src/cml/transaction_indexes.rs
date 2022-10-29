/**
export class TransactionIndexes {

    static __wrap(ptr) {
        const obj = Object.create(TransactionIndexes.prototype);
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
        wasm.__wbg_transactionindexes_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionindexes_to_bytes(retptr, this.ptr);
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
    * @returns {TransactionIndexes}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.transactionindexes_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionIndexes.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {TransactionIndexes}
    */
    static new() {
        const ret = wasm.transactionindexes_new();
        return TransactionIndexes.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    len() {
        const ret = wasm.transactionindexes_len(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} index
    * @returns {BigNum}
    */
    get(index) {
        const ret = wasm.transactionindexes_get(this.ptr, index);
        return BigNum.__wrap(ret);
    }
    /**
    * @param {BigNum} elem
    */
    add(elem) {
        _assertClass(elem, BigNum);
        wasm.transactionindexes_add(this.ptr, elem.ptr);
    }
}