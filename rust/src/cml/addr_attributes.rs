/*
/**
*/
export class AddrAttributes {

    static __wrap(ptr) {
        const obj = Object.create(AddrAttributes.prototype);
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
        wasm.__wbg_addrattributes_free(ptr);
    }
    /**
    * @param {HDAddressPayload | undefined} hdap
    * @param {ProtocolMagic | undefined} protocol_magic
    * @returns {AddrAttributes}
    */
    static new_bootstrap_era(hdap, protocol_magic) {
        let ptr0 = 0;
        if (!isLikeNone(hdap)) {
            _assertClass(hdap, HDAddressPayload);
            ptr0 = hdap.ptr;
            hdap.ptr = 0;
        }
        let ptr1 = 0;
        if (!isLikeNone(protocol_magic)) {
            _assertClass(protocol_magic, ProtocolMagic);
            ptr1 = protocol_magic.ptr;
            protocol_magic.ptr = 0;
        }
        const ret = wasm.addrattributes_new_bootstrap_era(ptr0, ptr1);
        return AddrAttributes.__wrap(ret);
    }
    /**
    * @param {Bip32PublicKey} pubk
    * @param {HDAddressPayload | undefined} hdap
    * @param {ProtocolMagic} protocol_magic
    * @returns {AddrAttributes}
    */
    static new_single_key(pubk, hdap, protocol_magic) {
        _assertClass(pubk, Bip32PublicKey);
        let ptr0 = 0;
        if (!isLikeNone(hdap)) {
            _assertClass(hdap, HDAddressPayload);
            ptr0 = hdap.ptr;
            hdap.ptr = 0;
        }
        _assertClass(protocol_magic, ProtocolMagic);
        var ptr1 = protocol_magic.ptr;
        protocol_magic.ptr = 0;
        const ret = wasm.addrattributes_new_single_key(pubk.ptr, ptr0, ptr1);
        return AddrAttributes.__wrap(ret);
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.addrattributes_to_bytes(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var v0 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1);
            return v0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {AddrAttributes}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.addrattributes_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return AddrAttributes.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {string}
    */
    to_json() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.addrattributes_to_json(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            var r3 = getInt32Memory0()[retptr / 4 + 3];
            var ptr0 = r0;
            var len0 = r1;
            if (r3) {
                ptr0 = 0; len0 = 0;
                throw takeObject(r2);
            }
            return getStringFromWasm0(ptr0, len0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(ptr0, len0);
        }
    }
    /**
    * @returns {any}
    */
    to_js_value() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.addrattributes_to_js_value(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {string} json
    * @returns {AddrAttributes}
    */
    static from_json(json) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.addrattributes_from_json(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return AddrAttributes.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {StakeDistribution} stake_distribution
    */
    set_stake_distribution(stake_distribution) {
        _assertClass(stake_distribution, StakeDistribution);
        wasm.addrattributes_set_stake_distribution(this.ptr, stake_distribution.ptr);
    }
    /**
    * @returns {StakeDistribution | undefined}
    */
    stake_distribution() {
        const ret = wasm.addrattributes_stake_distribution(this.ptr);
        return ret === 0 ? undefined : StakeDistribution.__wrap(ret);
    }
    /**
    * @param {HDAddressPayload} derivation_path
    */
    set_derivation_path(derivation_path) {
        _assertClass(derivation_path, HDAddressPayload);
        var ptr0 = derivation_path.ptr;
        derivation_path.ptr = 0;
        wasm.addrattributes_set_derivation_path(this.ptr, ptr0);
    }
    /**
    * @returns {HDAddressPayload | undefined}
    */
    derivation_path() {
        const ret = wasm.addrattributes_derivation_path(this.ptr);
        return ret === 0 ? undefined : HDAddressPayload.__wrap(ret);
    }
    /**
    * @param {ProtocolMagic} protocol_magic
    */
    set_protocol_magic(protocol_magic) {
        _assertClass(protocol_magic, ProtocolMagic);
        var ptr0 = protocol_magic.ptr;
        protocol_magic.ptr = 0;
        wasm.addrattributes_set_protocol_magic(this.ptr, ptr0);
    }
    /**
    * @returns {ProtocolMagic | undefined}
    */
    protocol_magic() {
        const ret = wasm.addrattributes_protocol_magic(this.ptr);
        return ret === 0 ? undefined : ProtocolMagic.__wrap(ret);
    }
    /**
    * @returns {AddrAttributes}
    */
    static new() {
        const ret = wasm.addrattributes_new();
        return AddrAttributes.__wrap(ret);
    }
}
*/