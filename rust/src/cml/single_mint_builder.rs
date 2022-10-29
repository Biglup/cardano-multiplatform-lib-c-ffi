/**
export class SingleMintBuilder {

    static __wrap(ptr) {
        const obj = Object.create(SingleMintBuilder.prototype);
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
        wasm.__wbg_singlemintbuilder_free(ptr);
    }
    /**
    * @param {MintAssets} assets
    * @returns {SingleMintBuilder}
    */
    static new(assets) {
        _assertClass(assets, MintAssets);
        const ret = wasm.singlemintbuilder_new(assets.ptr);
        return SingleMintBuilder.__wrap(ret);
    }
    /**
    * @param {NativeScript} native_script
    * @param {NativeScriptWitnessInfo} witness_info
    * @returns {MintBuilderResult}
    */
    native_script(native_script, witness_info) {
        _assertClass(native_script, NativeScript);
        _assertClass(witness_info, NativeScriptWitnessInfo);
        const ret = wasm.singlemintbuilder_native_script(this.ptr, native_script.ptr, witness_info.ptr);
        return MintBuilderResult.__wrap(ret);
    }
    /**
    * @param {PartialPlutusWitness} partial_witness
    * @param {Ed25519KeyHashes} required_signers
    * @returns {MintBuilderResult}
    */
    plutus_script(partial_witness, required_signers) {
        _assertClass(partial_witness, PartialPlutusWitness);
        _assertClass(required_signers, Ed25519KeyHashes);
        const ret = wasm.singlemintbuilder_plutus_script(this.ptr, partial_witness.ptr, required_signers.ptr);
        return MintBuilderResult.__wrap(ret);
    }
}