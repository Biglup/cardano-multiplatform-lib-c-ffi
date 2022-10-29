/**
* Redeemer without the tag of index
* This allows builder code to return partial redeemers
* and then later have them placed in the right context
export class UntaggedRedeemer {

    static __wrap(ptr) {
        const obj = Object.create(UntaggedRedeemer.prototype);
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
        wasm.__wbg_untaggedredeemer_free(ptr);
    }
    /**
    * @returns {PlutusData}
    */
    datum() {
        const ret = wasm.untaggedredeemer_datum(this.ptr);
        return PlutusData.__wrap(ret);
    }
    /**
    * @returns {ExUnits}
    */
    ex_units() {
        const ret = wasm.untaggedredeemer_ex_units(this.ptr);
        return ExUnits.__wrap(ret);
    }
    /**
    * @param {PlutusData} data
    * @param {ExUnits} ex_units
    * @returns {UntaggedRedeemer}
    */
    static new(data, ex_units) {
        _assertClass(data, PlutusData);
        _assertClass(ex_units, ExUnits);
        const ret = wasm.untaggedredeemer_new(data.ptr, ex_units.ptr);
        return UntaggedRedeemer.__wrap(ret);
    }
}