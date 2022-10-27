/**
* A partial Plutus witness
* It contains all the information needed to witness the Plutus script execution
* except for the redeemer tag and index
* Note: no datum is attached because only input script types have datums
export class PartialPlutusWitness {

    static __wrap(ptr) {
        const obj = Object.create(PartialPlutusWitness.prototype);
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
        wasm.__wbg_partialplutuswitness_free(ptr);
    }
    /**
    * @param {PlutusScriptWitness} script
    * @param {PlutusData} data
    * @returns {PartialPlutusWitness}
    */
    static new(script, data) {
        _assertClass(script, PlutusScriptWitness);
        _assertClass(data, PlutusData);
        const ret = wasm.partialplutuswitness_new(script.ptr, data.ptr);
        return PartialPlutusWitness.__wrap(ret);
    }
    /**
    * @returns {PlutusScriptWitness}
    */
    script() {
        const ret = wasm.partialplutuswitness_script(this.ptr);
        return PlutusScriptWitness.__wrap(ret);
    }
    /**
    * @returns {PlutusData}
    */
    data() {
        const ret = wasm.partialplutuswitness_data(this.ptr);
        return PlutusData.__wrap(ret);
    }
}