/**
export class BigNum {

    static __wrap(ptr) {
        const obj = Object.create(BigNum.prototype);
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
        wasm.__wbg_bignum_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bignum_to_bytes(retptr, this.ptr);
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
    * @returns {BigNum}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.bignum_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return BigNum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {string} string
    * @returns {BigNum}
    */
    static from_str(string) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(string, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.bignum_from_str(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return BigNum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {string}
    */
    to_str() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bignum_to_str(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(r0, r1);
        }
    }
    /**
    * @returns {BigNum}
    */
    static zero() {
        const ret = wasm.bignum_zero();
        return BigNum.__wrap(ret);
    }
    /**
    * @returns {boolean}
    */
    is_zero() {
        const ret = wasm.bignum_is_zero(this.ptr);
        return ret !== 0;
    }
    /**
    * @param {BigNum} other
    * @returns {BigNum}
    */
    checked_mul(other) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(other, BigNum);
            wasm.bignum_checked_mul(retptr, this.ptr, other.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return BigNum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {BigNum} other
    * @returns {BigNum}
    */
    checked_add(other) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(other, BigNum);
            wasm.bignum_checked_add(retptr, this.ptr, other.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return BigNum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {BigNum} other
    * @returns {BigNum}
    */
    checked_sub(other) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(other, BigNum);
            wasm.bignum_checked_sub(retptr, this.ptr, other.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return BigNum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * returns 0 if it would otherwise underflow
    * @param {BigNum} other
    * @returns {BigNum}
    */
    clamped_sub(other) {
        _assertClass(other, BigNum);
        const ret = wasm.bignum_clamped_sub(this.ptr, other.ptr);
        return BigNum.__wrap(ret);
    }
    /**
    * @param {BigNum} other
    * @returns {BigNum}
    */
    checked_div(other) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(other, BigNum);
            wasm.bignum_checked_div(retptr, this.ptr, other.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return BigNum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {BigNum} other
    * @returns {BigNum}
    */
    checked_div_ceil(other) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(other, BigNum);
            wasm.bignum_checked_div_ceil(retptr, this.ptr, other.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return BigNum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {BigNum} rhs_value
    * @returns {number}
    */
    compare(rhs_value) {
        _assertClass(rhs_value, BigNum);
        const ret = wasm.bignum_compare(this.ptr, rhs_value.ptr);
        return ret;
    }
}