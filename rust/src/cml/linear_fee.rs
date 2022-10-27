/**
* Careful: although the linear fee is the same for Byron & Shelley
* The value of the parameters and how fees are computed is not the same
export class LinearFee {

    static __wrap(ptr) {
        const obj = Object.create(LinearFee.prototype);
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
        wasm.__wbg_linearfee_free(ptr);
    }
    /**
    * @returns {BigNum}
    */
    constant() {
        const ret = wasm.linearfee_constant(this.ptr);
        return BigNum.__wrap(ret);
    }
    /**
    * @returns {BigNum}
    */
    coefficient() {
        const ret = wasm.linearfee_coefficient(this.ptr);
        return BigNum.__wrap(ret);
    }
    /**
    * @param {BigNum} coefficient
    * @param {BigNum} constant
    * @returns {LinearFee}
    */
    static new(coefficient, constant) {
        _assertClass(coefficient, BigNum);
        _assertClass(constant, BigNum);
        const ret = wasm.linearfee_new(coefficient.ptr, constant.ptr);
        return LinearFee.__wrap(ret);
    }
}