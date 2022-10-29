/**
export class RequiredWitnessSet {

    static __wrap(ptr) {
        const obj = Object.create(RequiredWitnessSet.prototype);
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
        wasm.__wbg_requiredwitnessset_free(ptr);
    }
    /**
    * @param {Vkeywitness} vkey
    */
    add_vkey(vkey) {
        _assertClass(vkey, Vkeywitness);
        wasm.requiredwitnessset_add_vkey(this.ptr, vkey.ptr);
    }
    /**
    * @param {Vkey} vkey
    */
    add_vkey_key(vkey) {
        _assertClass(vkey, Vkey);
        wasm.requiredwitnessset_add_vkey_key(this.ptr, vkey.ptr);
    }
    /**
    * @param {Ed25519KeyHash} hash
    */
    add_vkey_key_hash(hash) {
        _assertClass(hash, Ed25519KeyHash);
        wasm.requiredwitnessset_add_vkey_key_hash(this.ptr, hash.ptr);
    }
    /**
    * @param {ByronAddress} address
    */
    add_bootstrap(address) {
        _assertClass(address, ByronAddress);
        wasm.requiredwitnessset_add_bootstrap(this.ptr, address.ptr);
    }
    /**
    * @param {ScriptHash} script_hash
    */
    add_script_ref(script_hash) {
        _assertClass(script_hash, ScriptHash);
        wasm.requiredwitnessset_add_script_ref(this.ptr, script_hash.ptr);
    }
    /**
    * @param {NativeScript} native_script
    */
    add_native_script(native_script) {
        _assertClass(native_script, NativeScript);
        wasm.requiredwitnessset_add_native_script(this.ptr, native_script.ptr);
    }
    /**
    * @param {ScriptHash} script_hash
    */
    add_script_hash(script_hash) {
        _assertClass(script_hash, ScriptHash);
        wasm.requiredwitnessset_add_script_hash(this.ptr, script_hash.ptr);
    }
    /**
    * @param {PlutusScript} plutus_v1_script
    */
    add_plutus_script(plutus_v1_script) {
        _assertClass(plutus_v1_script, PlutusScript);
        wasm.requiredwitnessset_add_plutus_script(this.ptr, plutus_v1_script.ptr);
    }
    /**
    * @param {PlutusData} plutus_datum
    */
    add_plutus_datum(plutus_datum) {
        _assertClass(plutus_datum, PlutusData);
        wasm.requiredwitnessset_add_plutus_datum(this.ptr, plutus_datum.ptr);
    }
    /**
    * @param {DataHash} plutus_datum
    */
    add_plutus_datum_hash(plutus_datum) {
        _assertClass(plutus_datum, DataHash);
        wasm.requiredwitnessset_add_plutus_datum_hash(this.ptr, plutus_datum.ptr);
    }
    /**
    * @param {Redeemer} redeemer
    */
    add_redeemer(redeemer) {
        _assertClass(redeemer, Redeemer);
        wasm.requiredwitnessset_add_redeemer(this.ptr, redeemer.ptr);
    }
    /**
    * @param {RedeemerWitnessKey} redeemer
    */
    add_redeemer_tag(redeemer) {
        _assertClass(redeemer, RedeemerWitnessKey);
        wasm.requiredwitnessset_add_redeemer_tag(this.ptr, redeemer.ptr);
    }
    /**
    * @param {RequiredWitnessSet} requirements
    */
    add_all(requirements) {
        _assertClass(requirements, RequiredWitnessSet);
        wasm.requiredwitnessset_add_all(this.ptr, requirements.ptr);
    }
    /**
    * @returns {RequiredWitnessSet}
    */
    static new() {
        const ret = wasm.requiredwitnessset_new();
        return RequiredWitnessSet.__wrap(ret);
    }
}