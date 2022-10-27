/**
export class NativeScriptWitnessInfo {

    static __wrap(ptr) {
        const obj = Object.create(NativeScriptWitnessInfo.prototype);
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
        wasm.__wbg_nativescriptwitnessinfo_free(ptr);
    }
    /**
    * Unsure which keys will sign, but you know the exact number to save on tx fee
    * @param {number} num
    * @returns {NativeScriptWitnessInfo}
    */
    static num_signatures(num) {
        const ret = wasm.nativescriptwitnessinfo_num_signatures(num);
        return NativeScriptWitnessInfo.__wrap(ret);
    }
    /**
    * This native script will be witnessed by exactly these keys
    * @param {Ed25519KeyHashes} vkeys
    * @returns {NativeScriptWitnessInfo}
    */
    static vkeys(vkeys) {
        _assertClass(vkeys, Ed25519KeyHashes);
        const ret = wasm.nativescriptwitnessinfo_vkeys(vkeys.ptr);
        return NativeScriptWitnessInfo.__wrap(ret);
    }
    /**
    * You don't know how many keys will sign, so the maximum possible case will be assumed
    * @returns {NativeScriptWitnessInfo}
    */
    static assume_signature_count() {
        const ret = wasm.nativescriptwitnessinfo_assume_signature_count();
        return NativeScriptWitnessInfo.__wrap(ret);
    }
}

