/**
export class HeaderBody {

    static __wrap(ptr) {
        const obj = Object.create(HeaderBody.prototype);
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
        wasm.__wbg_headerbody_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.headerbody_to_bytes(retptr, this.ptr);
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
    * @returns {HeaderBody}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.headerbody_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return HeaderBody.__wrap(r0);
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
            wasm.headerbody_to_json(retptr, this.ptr);
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
            wasm.headerbody_to_js_value(retptr, this.ptr);
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
    * @returns {HeaderBody}
    */
    static from_json(json) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.headerbody_from_json(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return HeaderBody.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {number}
    */
    block_number() {
        const ret = wasm.headerbody_block_number(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {BigNum}
    */
    slot() {
        const ret = wasm.headerbody_slot(this.ptr);
        return BigNum.__wrap(ret);
    }
    /**
    * @returns {BlockHeaderHash | undefined}
    */
    prev_hash() {
        const ret = wasm.headerbody_prev_hash(this.ptr);
        return ret === 0 ? undefined : BlockHeaderHash.__wrap(ret);
    }
    /**
    * @returns {Vkey}
    */
    issuer_vkey() {
        const ret = wasm.headerbody_issuer_vkey(this.ptr);
        return Vkey.__wrap(ret);
    }
    /**
    * @returns {VRFVKey}
    */
    vrf_vkey() {
        const ret = wasm.headerbody_vrf_vkey(this.ptr);
        return VRFVKey.__wrap(ret);
    }
    /**
    *
    *     * Present in all Vasil blocks, but not prior ones
    *
    * @returns {VRFCert | undefined}
    */
    vrf_result() {
        const ret = wasm.headerbody_vrf_result(this.ptr);
        return ret === 0 ? undefined : VRFCert.__wrap(ret);
    }
    /**
    *
    *     * Present in all pre-Vasil blocks, but not later ones
    *
    * @returns {VRFCert | undefined}
    */
    leader_vrf() {
        const ret = wasm.headerbody_leader_vrf(this.ptr);
        return ret === 0 ? undefined : VRFCert.__wrap(ret);
    }
    /**
    *
    *     * Present in all pre-Vasil blocks, but not later ones
    *
    * @returns {VRFCert | undefined}
    */
    nonce_vrf() {
        const ret = wasm.headerbody_nonce_vrf(this.ptr);
        return ret === 0 ? undefined : VRFCert.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    block_body_size() {
        const ret = wasm.headerbody_block_body_size(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {BlockBodyHash}
    */
    block_body_hash() {
        const ret = wasm.headerbody_block_body_hash(this.ptr);
        return BlockBodyHash.__wrap(ret);
    }
    /**
    * @returns {OperationalCert}
    */
    operational_cert() {
        const ret = wasm.headerbody_operational_cert(this.ptr);
        return OperationalCert.__wrap(ret);
    }
    /**
    * @returns {ProtocolVersion}
    */
    protocol_version() {
        const ret = wasm.headerbody_protocol_version(this.ptr);
        return ProtocolVersion.__wrap(ret);
    }
    /**
    * Creates a new Vasil-era HeaderBody
    * @param {number} block_number
    * @param {BigNum} slot
    * @param {BlockHeaderHash | undefined} prev_hash
    * @param {Vkey} issuer_vkey
    * @param {VRFVKey} vrf_vkey
    * @param {VRFCert} vrf_result
    * @param {number} block_body_size
    * @param {BlockBodyHash} block_body_hash
    * @param {OperationalCert} operational_cert
    * @param {ProtocolVersion} protocol_version
    * @returns {HeaderBody}
    */
    static new(block_number, slot, prev_hash, issuer_vkey, vrf_vkey, vrf_result, block_body_size, block_body_hash, operational_cert, protocol_version) {
        _assertClass(slot, BigNum);
        let ptr0 = 0;
        if (!isLikeNone(prev_hash)) {
            _assertClass(prev_hash, BlockHeaderHash);
            ptr0 = prev_hash.ptr;
            prev_hash.ptr = 0;
        }
        _assertClass(issuer_vkey, Vkey);
        _assertClass(vrf_vkey, VRFVKey);
        _assertClass(vrf_result, VRFCert);
        _assertClass(block_body_hash, BlockBodyHash);
        _assertClass(operational_cert, OperationalCert);
        _assertClass(protocol_version, ProtocolVersion);
        const ret = wasm.headerbody_new(block_number, slot.ptr, ptr0, issuer_vkey.ptr, vrf_vkey.ptr, vrf_result.ptr, block_body_size, block_body_hash.ptr, operational_cert.ptr, protocol_version.ptr);
        return HeaderBody.__wrap(ret);
    }
}