/**
export class PlutusScript {

    static __wrap(ptr) {
        const obj = Object.create(PlutusScript.prototype);
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
        wasm.__wbg_plutusscript_free(ptr);
    }
    /**
    * @param {PlutusV1Script} script
    * @returns {PlutusScript}
    */
    static from_v1(script) {
        _assertClass(script, PlutusV1Script);
        const ret = wasm.plutusscript_from_v1(script.ptr);
        return PlutusScript.__wrap(ret);
    }
    /**
    * @param {PlutusV2Script} script
    * @returns {PlutusScript}
    */
    static from_v2(script) {
        _assertClass(script, PlutusV2Script);
        const ret = wasm.plutusscript_from_v2(script.ptr);
        return PlutusScript.__wrap(ret);
    }
    /**
    * @returns {ScriptHash}
    */
    hash() {
        const ret = wasm.plutusscript_hash(this.ptr);
        return ScriptHash.__wrap(ret);
    }
}