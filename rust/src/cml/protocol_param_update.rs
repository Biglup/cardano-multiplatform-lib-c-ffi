/**
export class ProtocolParamUpdate {

    static __wrap(ptr) {
        const obj = Object.create(ProtocolParamUpdate.prototype);
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
        wasm.__wbg_protocolparamupdate_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.protocolparamupdate_to_bytes(retptr, this.ptr);
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
    * @returns {ProtocolParamUpdate}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.protocolparamupdate_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return ProtocolParamUpdate.__wrap(r0);
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
            wasm.protocolparamupdate_to_json(retptr, this.ptr);
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
            wasm.protocolparamupdate_to_js_value(retptr, this.ptr);
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
    * @returns {ProtocolParamUpdate}
    */
    static from_json(json) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.protocolparamupdate_from_json(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return ProtocolParamUpdate.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {BigNum} minfee_a
    */
    set_minfee_a(minfee_a) {
        _assertClass(minfee_a, BigNum);
        wasm.protocolparamupdate_set_minfee_a(this.ptr, minfee_a.ptr);
    }
    /**
    * @returns {BigNum | undefined}
    */
    minfee_a() {
        const ret = wasm.protocolparamupdate_minfee_a(this.ptr);
        return ret === 0 ? undefined : BigNum.__wrap(ret);
    }
    /**
    * @param {BigNum} minfee_b
    */
    set_minfee_b(minfee_b) {
        _assertClass(minfee_b, BigNum);
        wasm.protocolparamupdate_set_minfee_b(this.ptr, minfee_b.ptr);
    }
    /**
    * @returns {BigNum | undefined}
    */
    minfee_b() {
        const ret = wasm.protocolparamupdate_minfee_b(this.ptr);
        return ret === 0 ? undefined : BigNum.__wrap(ret);
    }
    /**
    * @param {number} max_block_body_size
    */
    set_max_block_body_size(max_block_body_size) {
        wasm.protocolparamupdate_set_max_block_body_size(this.ptr, max_block_body_size);
    }
    /**
    * @returns {number | undefined}
    */
    max_block_body_size() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.protocolparamupdate_max_block_body_size(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return r0 === 0 ? undefined : r1 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {number} max_tx_size
    */
    set_max_tx_size(max_tx_size) {
        wasm.protocolparamupdate_set_max_tx_size(this.ptr, max_tx_size);
    }
    /**
    * @returns {number | undefined}
    */
    max_tx_size() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.protocolparamupdate_max_tx_size(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return r0 === 0 ? undefined : r1 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {number} max_block_header_size
    */
    set_max_block_header_size(max_block_header_size) {
        wasm.protocolparamupdate_set_max_block_header_size(this.ptr, max_block_header_size);
    }
    /**
    * @returns {number | undefined}
    */
    max_block_header_size() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.protocolparamupdate_max_block_header_size(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return r0 === 0 ? undefined : r1 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {BigNum} key_deposit
    */
    set_key_deposit(key_deposit) {
        _assertClass(key_deposit, BigNum);
        wasm.protocolparamupdate_set_key_deposit(this.ptr, key_deposit.ptr);
    }
    /**
    * @returns {BigNum | undefined}
    */
    key_deposit() {
        const ret = wasm.protocolparamupdate_key_deposit(this.ptr);
        return ret === 0 ? undefined : BigNum.__wrap(ret);
    }
    /**
    * @param {BigNum} pool_deposit
    */
    set_pool_deposit(pool_deposit) {
        _assertClass(pool_deposit, BigNum);
        wasm.protocolparamupdate_set_pool_deposit(this.ptr, pool_deposit.ptr);
    }
    /**
    * @returns {BigNum | undefined}
    */
    pool_deposit() {
        const ret = wasm.protocolparamupdate_pool_deposit(this.ptr);
        return ret === 0 ? undefined : BigNum.__wrap(ret);
    }
    /**
    * @param {number} max_epoch
    */
    set_max_epoch(max_epoch) {
        wasm.protocolparamupdate_set_max_epoch(this.ptr, max_epoch);
    }
    /**
    * @returns {number | undefined}
    */
    max_epoch() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.protocolparamupdate_max_epoch(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return r0 === 0 ? undefined : r1 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {number} n_opt
    */
    set_n_opt(n_opt) {
        wasm.protocolparamupdate_set_n_opt(this.ptr, n_opt);
    }
    /**
    * @returns {number | undefined}
    */
    n_opt() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.protocolparamupdate_n_opt(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return r0 === 0 ? undefined : r1 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {UnitInterval} pool_pledge_influence
    */
    set_pool_pledge_influence(pool_pledge_influence) {
        _assertClass(pool_pledge_influence, UnitInterval);
        wasm.protocolparamupdate_set_pool_pledge_influence(this.ptr, pool_pledge_influence.ptr);
    }
    /**
    * @returns {UnitInterval | undefined}
    */
    pool_pledge_influence() {
        const ret = wasm.protocolparamupdate_pool_pledge_influence(this.ptr);
        return ret === 0 ? undefined : UnitInterval.__wrap(ret);
    }
    /**
    * @param {UnitInterval} expansion_rate
    */
    set_expansion_rate(expansion_rate) {
        _assertClass(expansion_rate, UnitInterval);
        wasm.protocolparamupdate_set_expansion_rate(this.ptr, expansion_rate.ptr);
    }
    /**
    * @returns {UnitInterval | undefined}
    */
    expansion_rate() {
        const ret = wasm.protocolparamupdate_expansion_rate(this.ptr);
        return ret === 0 ? undefined : UnitInterval.__wrap(ret);
    }
    /**
    * @param {UnitInterval} treasury_growth_rate
    */
    set_treasury_growth_rate(treasury_growth_rate) {
        _assertClass(treasury_growth_rate, UnitInterval);
        wasm.protocolparamupdate_set_treasury_growth_rate(this.ptr, treasury_growth_rate.ptr);
    }
    /**
    * @returns {UnitInterval | undefined}
    */
    treasury_growth_rate() {
        const ret = wasm.protocolparamupdate_treasury_growth_rate(this.ptr);
        return ret === 0 ? undefined : UnitInterval.__wrap(ret);
    }
    /**
    * This parameter is only used in the Alonzo era. Do not set it for other eras.
    * @param {UnitInterval} d
    */
    set_d(d) {
        _assertClass(d, UnitInterval);
        wasm.protocolparamupdate_set_d(this.ptr, d.ptr);
    }
    /**
    * This parameter is only used in the Alonzo era. Do not set it for other eras.
    * @returns {UnitInterval | undefined}
    */
    d() {
        const ret = wasm.protocolparamupdate_d(this.ptr);
        return ret === 0 ? undefined : UnitInterval.__wrap(ret);
    }
    /**
    * This parameter is only used in the Alonzo era. Do not set it for other eras.
    * @param {Nonce} extra_entropy
    */
    set_extra_entropy(extra_entropy) {
        _assertClass(extra_entropy, Nonce);
        wasm.protocolparamupdate_set_extra_entropy(this.ptr, extra_entropy.ptr);
    }
    /**
    * This parameter is only used in the Alonzo era. Do not set it for other eras.
    * @returns {Nonce | undefined}
    */
    extra_entropy() {
        const ret = wasm.protocolparamupdate_extra_entropy(this.ptr);
        return ret === 0 ? undefined : Nonce.__wrap(ret);
    }
    /**
    * @param {ProtocolVersion} protocol_version
    */
    set_protocol_version(protocol_version) {
        _assertClass(protocol_version, ProtocolVersion);
        wasm.protocolparamupdate_set_protocol_version(this.ptr, protocol_version.ptr);
    }
    /**
    * @returns {ProtocolVersion | undefined}
    */
    protocol_version() {
        const ret = wasm.protocolparamupdate_protocol_version(this.ptr);
        return ret === 0 ? undefined : ProtocolVersion.__wrap(ret);
    }
    /**
    * @param {BigNum} min_pool_cost
    */
    set_min_pool_cost(min_pool_cost) {
        _assertClass(min_pool_cost, BigNum);
        wasm.protocolparamupdate_set_min_pool_cost(this.ptr, min_pool_cost.ptr);
    }
    /**
    * @returns {BigNum | undefined}
    */
    min_pool_cost() {
        const ret = wasm.protocolparamupdate_min_pool_cost(this.ptr);
        return ret === 0 ? undefined : BigNum.__wrap(ret);
    }
    /**
    * @param {BigNum} ada_per_utxo_byte
    */
    set_ada_per_utxo_byte(ada_per_utxo_byte) {
        _assertClass(ada_per_utxo_byte, BigNum);
        wasm.protocolparamupdate_set_ada_per_utxo_byte(this.ptr, ada_per_utxo_byte.ptr);
    }
    /**
    * @returns {BigNum | undefined}
    */
    ada_per_utxo_byte() {
        const ret = wasm.protocolparamupdate_ada_per_utxo_byte(this.ptr);
        return ret === 0 ? undefined : BigNum.__wrap(ret);
    }
    /**
    * @param {Costmdls} cost_models
    */
    set_cost_models(cost_models) {
        _assertClass(cost_models, Costmdls);
        wasm.protocolparamupdate_set_cost_models(this.ptr, cost_models.ptr);
    }
    /**
    * @returns {Costmdls | undefined}
    */
    cost_models() {
        const ret = wasm.protocolparamupdate_cost_models(this.ptr);
        return ret === 0 ? undefined : Costmdls.__wrap(ret);
    }
    /**
    * @param {ExUnitPrices} execution_costs
    */
    set_execution_costs(execution_costs) {
        _assertClass(execution_costs, ExUnitPrices);
        wasm.protocolparamupdate_set_execution_costs(this.ptr, execution_costs.ptr);
    }
    /**
    * @returns {ExUnitPrices | undefined}
    */
    execution_costs() {
        const ret = wasm.protocolparamupdate_execution_costs(this.ptr);
        return ret === 0 ? undefined : ExUnitPrices.__wrap(ret);
    }
    /**
    * @param {ExUnits} max_tx_ex_units
    */
    set_max_tx_ex_units(max_tx_ex_units) {
        _assertClass(max_tx_ex_units, ExUnits);
        wasm.protocolparamupdate_set_max_tx_ex_units(this.ptr, max_tx_ex_units.ptr);
    }
    /**
    * @returns {ExUnits | undefined}
    */
    max_tx_ex_units() {
        const ret = wasm.protocolparamupdate_max_tx_ex_units(this.ptr);
        return ret === 0 ? undefined : ExUnits.__wrap(ret);
    }
    /**
    * @param {ExUnits} max_block_ex_units
    */
    set_max_block_ex_units(max_block_ex_units) {
        _assertClass(max_block_ex_units, ExUnits);
        wasm.protocolparamupdate_set_max_block_ex_units(this.ptr, max_block_ex_units.ptr);
    }
    /**
    * @returns {ExUnits | undefined}
    */
    max_block_ex_units() {
        const ret = wasm.protocolparamupdate_max_block_ex_units(this.ptr);
        return ret === 0 ? undefined : ExUnits.__wrap(ret);
    }
    /**
    * @param {number} max_value_size
    */
    set_max_value_size(max_value_size) {
        wasm.protocolparamupdate_set_max_value_size(this.ptr, max_value_size);
    }
    /**
    * @returns {number | undefined}
    */
    max_value_size() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.protocolparamupdate_max_value_size(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return r0 === 0 ? undefined : r1 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {number} collateral_percentage
    */
    set_collateral_percentage(collateral_percentage) {
        wasm.protocolparamupdate_set_collateral_percentage(this.ptr, collateral_percentage);
    }
    /**
    * @returns {number | undefined}
    */
    collateral_percentage() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.protocolparamupdate_collateral_percentage(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return r0 === 0 ? undefined : r1 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {number} max_collateral_inputs
    */
    set_max_collateral_inputs(max_collateral_inputs) {
        wasm.protocolparamupdate_set_max_collateral_inputs(this.ptr, max_collateral_inputs);
    }
    /**
    * @returns {number | undefined}
    */
    max_collateral_inputs() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.protocolparamupdate_max_collateral_inputs(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return r0 === 0 ? undefined : r1 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {ProtocolParamUpdate}
    */
    static new() {
        const ret = wasm.protocolparamupdate_new();
        return ProtocolParamUpdate.__wrap(ret);
    }
}