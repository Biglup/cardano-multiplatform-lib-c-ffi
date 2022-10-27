/**
export class Pointer {

    static __wrap(ptr) {
        const obj = Object.create(Pointer.prototype);
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
        wasm.__wbg_pointer_free(ptr);
    }
    /**
    * @param {BigNum} slot
    * @param {BigNum} tx_index
    * @param {BigNum} cert_index
    * @returns {Pointer}
    */
    static new(slot, tx_index, cert_index) {
        _assertClass(slot, BigNum);
        _assertClass(tx_index, BigNum);
        _assertClass(cert_index, BigNum);
        const ret = wasm.pointer_new(slot.ptr, tx_index.ptr, cert_index.ptr);
        return Pointer.__wrap(ret);
    }
    /**
    * This will be truncated if above u64::MAX
    * @returns {BigNum}
    */
    slot() {
        const ret = wasm.pointer_slot(this.ptr);
        return BigNum.__wrap(ret);
    }
    /**
    * This will be truncated if above u64::MAX
    * @returns {BigNum}
    */
    tx_index() {
        const ret = wasm.pointer_tx_index(this.ptr);
        return BigNum.__wrap(ret);
    }
    /**
    * This will be truncated if above u64::MAX
    * @returns {BigNum}
    */
    cert_index() {
        const ret = wasm.pointer_cert_index(this.ptr);
        return BigNum.__wrap(ret);
    }
}