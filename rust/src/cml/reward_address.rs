/**
export class RewardAddress {

    static __wrap(ptr) {
        const obj = Object.create(RewardAddress.prototype);
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
        wasm.__wbg_rewardaddress_free(ptr);
    }
    /**
    * @param {number} network
    * @param {StakeCredential} payment
    * @returns {RewardAddress}
    */
    static new(network, payment) {
        _assertClass(payment, StakeCredential);
        const ret = wasm.rewardaddress_new(network, payment.ptr);
        return RewardAddress.__wrap(ret);
    }
    /**
    * @returns {StakeCredential}
    */
    payment_cred() {
        const ret = wasm.rewardaddress_payment_cred(this.ptr);
        return StakeCredential.__wrap(ret);
    }
    /**
    * @returns {Address}
    */
    to_address() {
        const ret = wasm.rewardaddress_to_address(this.ptr);
        return Address.__wrap(ret);
    }
    /**
    * @param {Address} addr
    * @returns {RewardAddress | undefined}
    */
    static from_address(addr) {
        _assertClass(addr, Address);
        const ret = wasm.rewardaddress_from_address(addr.ptr);
        return ret === 0 ? undefined : RewardAddress.__wrap(ret);
    }
}