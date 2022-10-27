/*

/**
*/
export class AddressContent {

    static __wrap(ptr) {
        const obj = Object.create(AddressContent.prototype);
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
        wasm.__wbg_addresscontent_free(ptr);
    }
    /**
    * @param {ByronAddrType} addr_type
    * @param {SpendingData} spending_data
    * @param {AddrAttributes} attributes
    * @returns {AddressContent}
    */
    static hash_and_create(addr_type, spending_data, attributes) {
        _assertClass(addr_type, ByronAddrType);
        _assertClass(spending_data, SpendingData);
        _assertClass(attributes, AddrAttributes);
        const ret = wasm.addresscontent_hash_and_create(addr_type.ptr, spending_data.ptr, attributes.ptr);
        return AddressContent.__wrap(ret);
    }
    /**
    * @param {PublicKey} pubkey
    * @param {ProtocolMagic | undefined} protocol_magic
    * @returns {AddressContent}
    */
    static new_redeem(pubkey, protocol_magic) {
        _assertClass(pubkey, PublicKey);
        let ptr0 = 0;
        if (!isLikeNone(protocol_magic)) {
            _assertClass(protocol_magic, ProtocolMagic);
            ptr0 = protocol_magic.ptr;
            protocol_magic.ptr = 0;
        }
        const ret = wasm.addresscontent_new_redeem(pubkey.ptr, ptr0);
        return AddressContent.__wrap(ret);
    }
    /**
    * @param {Bip32PublicKey} xpub
    * @param {ProtocolMagic | undefined} protocol_magic
    * @returns {AddressContent}
    */
    static new_simple(xpub, protocol_magic) {
        _assertClass(xpub, Bip32PublicKey);
        let ptr0 = 0;
        if (!isLikeNone(protocol_magic)) {
            _assertClass(protocol_magic, ProtocolMagic);
            ptr0 = protocol_magic.ptr;
            protocol_magic.ptr = 0;
        }
        const ret = wasm.addresscontent_new_simple(xpub.ptr, ptr0);
        return AddressContent.__wrap(ret);
    }
    /**
    * @returns {ByronAddress}
    */
    to_address() {
        const ret = wasm.addresscontent_to_address(this.ptr);
        return ByronAddress.__wrap(ret);
    }
    /**
    * returns the byron protocol magic embedded in the address, or mainnet id if none is present
    * note: for bech32 addresses, you need to use network_id instead
    * @returns {number}
    */
    byron_protocol_magic() {
        const ret = wasm.addresscontent_byron_protocol_magic(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {number}
    */
    network_id() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.addresscontent_network_id(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return r0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Bip32PublicKey} key
    * @param {number} protocol_magic
    * @returns {AddressContent}
    */
    static icarus_from_key(key, protocol_magic) {
        _assertClass(key, Bip32PublicKey);
        const ret = wasm.addresscontent_icarus_from_key(key.ptr, protocol_magic);
        return AddressContent.__wrap(ret);
    }
    /**
    * Check if the Addr can be reconstructed with a specific xpub
    * @param {Bip32PublicKey} xpub
    * @returns {boolean}
    */
    identical_with_pubkey(xpub) {
        _assertClass(xpub, Bip32PublicKey);
        const ret = wasm.addresscontent_identical_with_pubkey(this.ptr, xpub.ptr);
        return ret !== 0;
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.addresscontent_to_bytes(retptr, this.ptr);
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
    * @returns {AddressContent}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.addresscontent_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return AddressContent.__wrap(r0);
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
            wasm.addresscontent_to_json(retptr, this.ptr);
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
            wasm.addresscontent_to_js_value(retptr, this.ptr);
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
    * @returns {AddressContent}
    */
    static from_json(json) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.addresscontent_from_json(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return AddressContent.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {AddressId}
    */
    address_id() {
        const ret = wasm.addresscontent_address_id(this.ptr);
        return AddressId.__wrap(ret);
    }
    /**
    * @returns {AddrAttributes}
    */
    addr_attr() {
        const ret = wasm.addresscontent_addr_attr(this.ptr);
        return AddrAttributes.__wrap(ret);
    }
    /**
    * @returns {ByronAddrType}
    */
    addr_type() {
        const ret = wasm.addresscontent_addr_type(this.ptr);
        return ByronAddrType.__wrap(ret);
    }
    /**
    * @param {AddressId} address_id
    * @param {AddrAttributes} addr_attr
    * @param {ByronAddrType} addr_type
    * @returns {AddressContent}
    */
    static new(address_id, addr_attr, addr_type) {
        _assertClass(address_id, AddressId);
        _assertClass(addr_attr, AddrAttributes);
        _assertClass(addr_type, ByronAddrType);
        const ret = wasm.addresscontent_new(address_id.ptr, addr_attr.ptr, addr_type.ptr);
        return AddressContent.__wrap(ret);
    }
}
*/