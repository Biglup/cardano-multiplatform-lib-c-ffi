
/**
export class Certificate {

    static __wrap(ptr) {
        const obj = Object.create(Certificate.prototype);
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
        wasm.__wbg_certificate_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.certificate_to_bytes(retptr, this.ptr);
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
    * @returns {Certificate}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.certificate_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return Certificate.__wrap(r0);
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
            wasm.certificate_to_json(retptr, this.ptr);
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
            wasm.certificate_to_js_value(retptr, this.ptr);
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
    * @returns {Certificate}
    */
    static from_json(json) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.certificate_from_json(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return Certificate.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {StakeRegistration} stake_registration
    * @returns {Certificate}
    */
    static new_stake_registration(stake_registration) {
        _assertClass(stake_registration, StakeRegistration);
        const ret = wasm.certificate_new_stake_registration(stake_registration.ptr);
        return Certificate.__wrap(ret);
    }
    /**
    * @param {StakeDeregistration} stake_deregistration
    * @returns {Certificate}
    */
    static new_stake_deregistration(stake_deregistration) {
        _assertClass(stake_deregistration, StakeDeregistration);
        const ret = wasm.certificate_new_stake_deregistration(stake_deregistration.ptr);
        return Certificate.__wrap(ret);
    }
    /**
    * @param {StakeDelegation} stake_delegation
    * @returns {Certificate}
    */
    static new_stake_delegation(stake_delegation) {
        _assertClass(stake_delegation, StakeDelegation);
        const ret = wasm.certificate_new_stake_delegation(stake_delegation.ptr);
        return Certificate.__wrap(ret);
    }
    /**
    * @param {PoolRegistration} pool_registration
    * @returns {Certificate}
    */
    static new_pool_registration(pool_registration) {
        _assertClass(pool_registration, PoolRegistration);
        const ret = wasm.certificate_new_pool_registration(pool_registration.ptr);
        return Certificate.__wrap(ret);
    }
    /**
    * @param {PoolRetirement} pool_retirement
    * @returns {Certificate}
    */
    static new_pool_retirement(pool_retirement) {
        _assertClass(pool_retirement, PoolRetirement);
        const ret = wasm.certificate_new_pool_retirement(pool_retirement.ptr);
        return Certificate.__wrap(ret);
    }
    /**
    * @param {GenesisKeyDelegation} genesis_key_delegation
    * @returns {Certificate}
    */
    static new_genesis_key_delegation(genesis_key_delegation) {
        _assertClass(genesis_key_delegation, GenesisKeyDelegation);
        const ret = wasm.certificate_new_genesis_key_delegation(genesis_key_delegation.ptr);
        return Certificate.__wrap(ret);
    }
    /**
    * @param {MoveInstantaneousRewardsCert} move_instantaneous_rewards_cert
    * @returns {Certificate}
    */
    static new_move_instantaneous_rewards_cert(move_instantaneous_rewards_cert) {
        _assertClass(move_instantaneous_rewards_cert, MoveInstantaneousRewardsCert);
        const ret = wasm.certificate_new_move_instantaneous_rewards_cert(move_instantaneous_rewards_cert.ptr);
        return Certificate.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    kind() {
        const ret = wasm.certificate_kind(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {StakeRegistration | undefined}
    */
    as_stake_registration() {
        const ret = wasm.certificate_as_stake_registration(this.ptr);
        return ret === 0 ? undefined : StakeRegistration.__wrap(ret);
    }
    /**
    * @returns {StakeDeregistration | undefined}
    */
    as_stake_deregistration() {
        const ret = wasm.certificate_as_stake_deregistration(this.ptr);
        return ret === 0 ? undefined : StakeDeregistration.__wrap(ret);
    }
    /**
    * @returns {StakeDelegation | undefined}
    */
    as_stake_delegation() {
        const ret = wasm.certificate_as_stake_delegation(this.ptr);
        return ret === 0 ? undefined : StakeDelegation.__wrap(ret);
    }
    /**
    * @returns {PoolRegistration | undefined}
    */
    as_pool_registration() {
        const ret = wasm.certificate_as_pool_registration(this.ptr);
        return ret === 0 ? undefined : PoolRegistration.__wrap(ret);
    }
    /**
    * @returns {PoolRetirement | undefined}
    */
    as_pool_retirement() {
        const ret = wasm.certificate_as_pool_retirement(this.ptr);
        return ret === 0 ? undefined : PoolRetirement.__wrap(ret);
    }
    /**
    * @returns {GenesisKeyDelegation | undefined}
    */
    as_genesis_key_delegation() {
        const ret = wasm.certificate_as_genesis_key_delegation(this.ptr);
        return ret === 0 ? undefined : GenesisKeyDelegation.__wrap(ret);
    }
    /**
    * @returns {MoveInstantaneousRewardsCert | undefined}
    */
    as_move_instantaneous_rewards_cert() {
        const ret = wasm.certificate_as_move_instantaneous_rewards_cert(this.ptr);
        return ret === 0 ? undefined : MoveInstantaneousRewardsCert.__wrap(ret);
    }
}