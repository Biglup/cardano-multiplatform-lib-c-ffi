/**
export class ConstrPlutusData {

    static __wrap(ptr) {
        const obj = Object.create(ConstrPlutusData.prototype);
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
        wasm.__wbg_constrplutusdata_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.constrplutusdata_to_bytes(retptr, this.ptr);
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
    * @returns {ConstrPlutusData}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.constrplutusdata_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return ConstrPlutusData.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {BigNum}
    */
    alternative() {
        const ret = wasm.constrplutusdata_alternative(this.ptr);
        return BigNum.__wrap(ret);
    }
    /**
    * @returns {PlutusList}
    */
    data() {
        const ret = wasm.constrplutusdata_data(this.ptr);
        return PlutusList.__wrap(ret);
    }
    /**
    * @param {BigNum} alternative
    * @param {PlutusList} data
    * @returns {ConstrPlutusData}
    */
    static new(alternative, data) {
        _assertClass(alternative, BigNum);
        _assertClass(data, PlutusList);
        const ret = wasm.constrplutusdata_new(alternative.ptr, data.ptr);
        return ConstrPlutusData.__wrap(ret);
    }
}