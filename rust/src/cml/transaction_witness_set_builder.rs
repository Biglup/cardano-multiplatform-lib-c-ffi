/**
* Builder de-duplicates witnesses as they are added
export class TransactionWitnessSetBuilder {

    static __wrap(ptr) {
        const obj = Object.create(TransactionWitnessSetBuilder.prototype);
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
        wasm.__wbg_transactionwitnesssetbuilder_free(ptr);
    }
    /**
    * @returns {Vkeys}
    */
    get_vkeys() {
        const ret = wasm.transactionwitnesssetbuilder_get_vkeys(this.ptr);
        return Vkeys.__wrap(ret);
    }
    /**
    * @param {Vkeywitness} vkey
    */
    add_vkey(vkey) {
        _assertClass(vkey, Vkeywitness);
        wasm.transactionwitnesssetbuilder_add_vkey(this.ptr, vkey.ptr);
    }
    /**
    * @param {BootstrapWitness} bootstrap
    */
    add_bootstrap(bootstrap) {
        _assertClass(bootstrap, BootstrapWitness);
        wasm.transactionwitnesssetbuilder_add_bootstrap(this.ptr, bootstrap.ptr);
    }
    /**
    * @returns {Vkeys}
    */
    get_bootstraps() {
        const ret = wasm.transactionwitnesssetbuilder_get_bootstraps(this.ptr);
        return Vkeys.__wrap(ret);
    }
    /**
    * @param {Script} script
    */
    add_script(script) {
        _assertClass(script, Script);
        wasm.transactionwitnesssetbuilder_add_script(this.ptr, script.ptr);
    }
    /**
    * @param {NativeScript} native_script
    */
    add_native_script(native_script) {
        _assertClass(native_script, NativeScript);
        wasm.transactionwitnesssetbuilder_add_native_script(this.ptr, native_script.ptr);
    }
    /**
    * @returns {NativeScripts}
    */
    get_native_script() {
        const ret = wasm.transactionwitnesssetbuilder_get_native_script(this.ptr);
        return NativeScripts.__wrap(ret);
    }
    /**
    * @param {PlutusV1Script} plutus_v1_script
    */
    add_plutus_v1_script(plutus_v1_script) {
        _assertClass(plutus_v1_script, PlutusV1Script);
        wasm.transactionwitnesssetbuilder_add_plutus_v1_script(this.ptr, plutus_v1_script.ptr);
    }
    /**
    * @returns {PlutusV1Scripts}
    */
    get_plutus_v1_script() {
        const ret = wasm.transactionwitnesssetbuilder_get_plutus_v1_script(this.ptr);
        return PlutusV1Scripts.__wrap(ret);
    }
    /**
    * @param {PlutusV2Script} plutus_v2_script
    */
    add_plutus_v2_script(plutus_v2_script) {
        _assertClass(plutus_v2_script, PlutusV2Script);
        wasm.transactionwitnesssetbuilder_add_plutus_v2_script(this.ptr, plutus_v2_script.ptr);
    }
    /**
    * @returns {PlutusV2Scripts}
    */
    get_plutus_v2_script() {
        const ret = wasm.transactionwitnesssetbuilder_get_plutus_v2_script(this.ptr);
        return PlutusV2Scripts.__wrap(ret);
    }
    /**
    * @param {PlutusData} plutus_datum
    */
    add_plutus_datum(plutus_datum) {
        _assertClass(plutus_datum, PlutusData);
        wasm.transactionwitnesssetbuilder_add_plutus_datum(this.ptr, plutus_datum.ptr);
    }
    /**
    * @returns {PlutusList}
    */
    get_plutus_datum() {
        const ret = wasm.transactionwitnesssetbuilder_get_plutus_datum(this.ptr);
        return PlutusList.__wrap(ret);
    }
    /**
    * @param {Redeemer} redeemer
    */
    add_redeemer(redeemer) {
        _assertClass(redeemer, Redeemer);
        wasm.transactionwitnesssetbuilder_add_redeemer(this.ptr, redeemer.ptr);
    }
    /**
    * @param {Redeemers} redeemers
    */
    add_redeemers(redeemers) {
        _assertClass(redeemers, Redeemers);
        wasm.transactionwitnesssetbuilder_add_redeemers(this.ptr, redeemers.ptr);
    }
    /**
    * @returns {Redeemers}
    */
    get_redeemer() {
        const ret = wasm.transactionwitnesssetbuilder_get_redeemer(this.ptr);
        return Redeemers.__wrap(ret);
    }
    /**
    * @param {RequiredWitnessSet} required_wits
    */
    add_required_wits(required_wits) {
        _assertClass(required_wits, RequiredWitnessSet);
        wasm.transactionwitnesssetbuilder_add_required_wits(this.ptr, required_wits.ptr);
    }
    /**
    * @returns {TransactionWitnessSetBuilder}
    */
    static new() {
        const ret = wasm.transactionwitnesssetbuilder_new();
        return TransactionWitnessSetBuilder.__wrap(ret);
    }
    /**
    * @param {TransactionWitnessSet} wit_set
    */
    add_existing(wit_set) {
        _assertClass(wit_set, TransactionWitnessSet);
        wasm.transactionwitnesssetbuilder_add_existing(this.ptr, wit_set.ptr);
    }
    /**
    * @returns {TransactionWitnessSet}
    */
    build() {
        const ret = wasm.transactionwitnesssetbuilder_build(this.ptr);
        return TransactionWitnessSet.__wrap(ret);
    }
    /**
    * @returns {RequiredWitnessSet}
    */
    remaining_wits() {
        const ret = wasm.transactionwitnesssetbuilder_remaining_wits(this.ptr);
        return RequiredWitnessSet.__wrap(ret);
    }
    /**
    * @returns {TransactionWitnessSet}
    */
    try_build() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionwitnesssetbuilder_try_build(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TransactionWitnessSet.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}