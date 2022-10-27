/**
export class PlutusScriptWitness {

    static __wrap(ptr) {
        const obj = Object.create(PlutusScriptWitness.prototype);
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
        wasm.__wbg_plutusscriptwitness_free(ptr);
    }
    /**
    * @param {PlutusScript} script
    * @returns {PlutusScriptWitness}
    */
    static from_script(script) {
        _assertClass(script, PlutusScript);
        var ptr0 = script.ptr;
        script.ptr = 0;
        const ret = wasm.plutusscriptwitness_from_script(ptr0);
        return PlutusScriptWitness.__wrap(ret);
    }
    /**
    * @param {ScriptHash} hash
    * @returns {PlutusScriptWitness}
    */
    static from_ref(hash) {
        _assertClass(hash, ScriptHash);
        var ptr0 = hash.ptr;
        hash.ptr = 0;
        const ret = wasm.plutusscriptwitness_from_ref(ptr0);
        return PlutusScriptWitness.__wrap(ret);
    }
    /**
    * @returns {PlutusScript | undefined}
    */
    script() {
        const ret = wasm.plutusscriptwitness_script(this.ptr);
        return ret === 0 ? undefined : PlutusScript.__wrap(ret);
    }
    /**
    * @returns {ScriptHash}
    */
    hash() {
        const ret = wasm.plutusscriptwitness_hash(this.ptr);
        return ScriptHash.__wrap(ret);
    }
}