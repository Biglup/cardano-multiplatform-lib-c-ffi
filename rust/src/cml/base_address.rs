/**
export class BaseAddress {

    static __wrap(ptr) {
        const obj = Object.create(BaseAddress.prototype);
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
        wasm.__wbg_baseaddress_free(ptr);
    }
    /**
    * @param {number} network
    * @param {StakeCredential} payment
    * @param {StakeCredential} stake
    * @returns {BaseAddress}
    */
    static new(network, payment, stake) {
        _assertClass(payment, StakeCredential);
        _assertClass(stake, StakeCredential);
        const ret = wasm.baseaddress_new(network, payment.ptr, stake.ptr);
        return BaseAddress.__wrap(ret);
    }
    /**
    * @returns {StakeCredential}
    */
    payment_cred() {
        const ret = wasm.baseaddress_payment_cred(this.ptr);
        return StakeCredential.__wrap(ret);
    }
    /**
    * @returns {StakeCredential}
    */
    stake_cred() {
        const ret = wasm.baseaddress_stake_cred(this.ptr);
        return StakeCredential.__wrap(ret);
    }
    /**
    * @returns {Address}
    */
    to_address() {
        const ret = wasm.baseaddress_to_address(this.ptr);
        return Address.__wrap(ret);
    }
    /**
    * @param {Address} addr
    * @returns {BaseAddress | undefined}
    */
    static from_address(addr) {
        _assertClass(addr, Address);
        const ret = wasm.baseaddress_from_address(addr.ptr);
        return ret === 0 ? undefined : BaseAddress.__wrap(ret);
    }
}