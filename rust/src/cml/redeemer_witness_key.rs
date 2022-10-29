/**
export class RedeemerWitnessKey {

    static __wrap(ptr) {
        const obj = Object.create(RedeemerWitnessKey.prototype);
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
        wasm.__wbg_redeemerwitnesskey_free(ptr);
    }
    /**
    * @returns {RedeemerTag}
    */
    tag() {
        const ret = wasm.redeemerwitnesskey_tag(this.ptr);
        return RedeemerTag.__wrap(ret);
    }
    /**
    * @returns {BigNum}
    */
    index() {
        const ret = wasm.redeemerwitnesskey_index(this.ptr);
        return BigNum.__wrap(ret);
    }
    /**
    * @param {RedeemerTag} tag
    * @param {BigNum} index
    * @returns {RedeemerWitnessKey}
    */
    static new(tag, index) {
        _assertClass(tag, RedeemerTag);
        _assertClass(index, BigNum);
        const ret = wasm.redeemerwitnesskey_new(tag.ptr, index.ptr);
        return RedeemerWitnessKey.__wrap(ret);
    }
}