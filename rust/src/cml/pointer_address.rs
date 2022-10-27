
/**
export class PointerAddress {

    static __wrap(ptr) {
        const obj = Object.create(PointerAddress.prototype);
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
        wasm.__wbg_pointeraddress_free(ptr);
    }
    /**
    * @param {number} network
    * @param {StakeCredential} payment
    * @param {Pointer} stake
    * @returns {PointerAddress}
    */
    static new(network, payment, stake) {
        _assertClass(payment, StakeCredential);
        _assertClass(stake, Pointer);
        const ret = wasm.pointeraddress_new(network, payment.ptr, stake.ptr);
        return PointerAddress.__wrap(ret);
    }
    /**
    * @returns {StakeCredential}
    */
    payment_cred() {
        const ret = wasm.pointeraddress_payment_cred(this.ptr);
        return StakeCredential.__wrap(ret);
    }
    /**
    * @returns {Pointer}
    */
    stake_pointer() {
        const ret = wasm.pointeraddress_stake_pointer(this.ptr);
        return Pointer.__wrap(ret);
    }
    /**
    * @returns {Address}
    */
    to_address() {
        const ret = wasm.pointeraddress_to_address(this.ptr);
        return Address.__wrap(ret);
    }
    /**
    * @param {Address} addr
    * @returns {PointerAddress | undefined}
    */
    static from_address(addr) {
        _assertClass(addr, Address);
        const ret = wasm.pointeraddress_from_address(addr.ptr);
        return ret === 0 ? undefined : PointerAddress.__wrap(ret);
    }
}