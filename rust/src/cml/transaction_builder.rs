/**
export class TransactionBuilder {

    static __wrap(ptr) {
        const obj = Object.create(TransactionBuilder.prototype);
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
        wasm.__wbg_transactionbuilder_free(ptr);
    }
    /**
    * This automatically selects and adds inputs from {inputs} consisting of just enough to cover
    * the outputs that have already been added.
    * This should be called after adding all certs/outputs/etc and will be an error otherwise.
    * Uses CIP2: https://github.com/cardano-foundation/CIPs/blob/master/CIP-0002/CIP-0002.md
    * Adding a change output must be called after via TransactionBuilder::add_change_if_needed()
    * This function, diverging from CIP2, takes into account fees and will attempt to add additional
    * inputs to cover the minimum fees. This does not, however, set the txbuilder's fee.
    * @param {number} strategy
    */
    select_utxos(strategy) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilder_select_utxos(retptr, this.ptr, strategy);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {InputBuilderResult} result
    */
    add_input(result) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(result, InputBuilderResult);
            wasm.transactionbuilder_add_input(retptr, this.ptr, result.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {InputBuilderResult} result
    */
    add_utxo(result) {
        _assertClass(result, InputBuilderResult);
        wasm.transactionbuilder_add_utxo(this.ptr, result.ptr);
    }
    /**
    * calculates how much the fee would increase if you added a given output
    * @param {InputBuilderResult} result
    * @returns {BigNum}
    */
    fee_for_input(result) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(result, InputBuilderResult);
            wasm.transactionbuilder_fee_for_input(retptr, this.ptr, result.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return BigNum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {TransactionUnspentOutput} utxo
    */
    add_reference_input(utxo) {
        _assertClass(utxo, TransactionUnspentOutput);
        wasm.transactionbuilder_add_reference_input(this.ptr, utxo.ptr);
    }
    /**
    * Add explicit output via a TransactionOutput object
    * @param {SingleOutputBuilderResult} builder_result
    */
    add_output(builder_result) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(builder_result, SingleOutputBuilderResult);
            wasm.transactionbuilder_add_output(retptr, this.ptr, builder_result.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * calculates how much the fee would increase if you added a given output
    * @param {SingleOutputBuilderResult} builder
    * @returns {BigNum}
    */
    fee_for_output(builder) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(builder, SingleOutputBuilderResult);
            wasm.transactionbuilder_fee_for_output(retptr, this.ptr, builder.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return BigNum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {BigNum} fee
    */
    set_fee(fee) {
        _assertClass(fee, BigNum);
        wasm.transactionbuilder_set_fee(this.ptr, fee.ptr);
    }
    /**
    * @param {BigNum} ttl
    */
    set_ttl(ttl) {
        _assertClass(ttl, BigNum);
        wasm.transactionbuilder_set_ttl(this.ptr, ttl.ptr);
    }
    /**
    * @param {BigNum} validity_start_interval
    */
    set_validity_start_interval(validity_start_interval) {
        _assertClass(validity_start_interval, BigNum);
        wasm.transactionbuilder_set_validity_start_interval(this.ptr, validity_start_interval.ptr);
    }
    /**
    * @returns {Certificates | undefined}
    */
    get_certs() {
        const ret = wasm.transactionbuilder_get_certs(this.ptr);
        return ret === 0 ? undefined : Certificates.__wrap(ret);
    }
    /**
    * @param {CertificateBuilderResult} result
    */
    add_cert(result) {
        _assertClass(result, CertificateBuilderResult);
        wasm.transactionbuilder_add_cert(this.ptr, result.ptr);
    }
    /**
    * @returns {Withdrawals | undefined}
    */
    get_withdrawals() {
        const ret = wasm.transactionbuilder_get_withdrawals(this.ptr);
        return ret === 0 ? undefined : Withdrawals.__wrap(ret);
    }
    /**
    * @param {WithdrawalBuilderResult} result
    */
    add_withdrawal(result) {
        _assertClass(result, WithdrawalBuilderResult);
        wasm.transactionbuilder_add_withdrawal(this.ptr, result.ptr);
    }
    /**
    * @returns {AuxiliaryData | undefined}
    */
    get_auxiliary_data() {
        const ret = wasm.transactionbuilder_get_auxiliary_data(this.ptr);
        return ret === 0 ? undefined : AuxiliaryData.__wrap(ret);
    }
    /**
    * @param {AuxiliaryData} new_aux_data
    */
    set_auxiliary_data(new_aux_data) {
        _assertClass(new_aux_data, AuxiliaryData);
        wasm.transactionbuilder_set_auxiliary_data(this.ptr, new_aux_data.ptr);
    }
    /**
    * @param {AuxiliaryData} new_aux_data
    */
    add_auxiliary_data(new_aux_data) {
        _assertClass(new_aux_data, AuxiliaryData);
        wasm.transactionbuilder_add_auxiliary_data(this.ptr, new_aux_data.ptr);
    }
    /**
    * @param {MintBuilderResult} result
    */
    add_mint(result) {
        _assertClass(result, MintBuilderResult);
        wasm.transactionbuilder_add_mint(this.ptr, result.ptr);
    }
    /**
    * Returns a copy of the current mint state in the builder
    * @returns {Mint | undefined}
    */
    get_mint() {
        const ret = wasm.transactionbuilder_get_mint(this.ptr);
        return ret === 0 ? undefined : Mint.__wrap(ret);
    }
    /**
    * @param {TransactionBuilderConfig} cfg
    * @returns {TransactionBuilder}
    */
    static new(cfg) {
        _assertClass(cfg, TransactionBuilderConfig);
        const ret = wasm.transactionbuilder_new(cfg.ptr);
        return TransactionBuilder.__wrap(ret);
    }
    /**
    * @param {InputBuilderResult} result
    */
    add_collateral(result) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(result, InputBuilderResult);
            wasm.transactionbuilder_add_collateral(retptr, this.ptr, result.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {TransactionInputs | undefined}
    */
    collateral() {
        const ret = wasm.transactionbuilder_collateral(this.ptr);
        return ret === 0 ? undefined : TransactionInputs.__wrap(ret);
    }
    /**
    * @param {Ed25519KeyHash} hash
    */
    add_required_signer(hash) {
        _assertClass(hash, Ed25519KeyHash);
        wasm.transactionbuilder_add_required_signer(this.ptr, hash.ptr);
    }
    /**
    * @returns {Ed25519KeyHashes | undefined}
    */
    required_signers() {
        const ret = wasm.transactionbuilder_required_signers(this.ptr);
        return ret === 0 ? undefined : Ed25519KeyHashes.__wrap(ret);
    }
    /**
    * @param {NetworkId} network_id
    */
    set_network_id(network_id) {
        _assertClass(network_id, NetworkId);
        var ptr0 = network_id.ptr;
        network_id.ptr = 0;
        wasm.transactionbuilder_set_network_id(this.ptr, ptr0);
    }
    /**
    * @returns {NetworkId | undefined}
    */
    network_id() {
        const ret = wasm.transactionbuilder_network_id(this.ptr);
        return ret === 0 ? undefined : NetworkId.__wrap(ret);
    }
    /**
    * does not include refunds or withdrawals
    * @returns {Value}
    */
    get_explicit_input() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilder_get_explicit_input(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return Value.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * withdrawals and refunds
    * @returns {Value}
    */
    get_implicit_input() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilder_get_implicit_input(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return Value.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Return explicit input plus implicit input plus mint
    * @returns {Value}
    */
    get_total_input() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilder_get_total_input(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return Value.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Return explicit output plus implicit output plus burn (does not consider fee directly)
    * @returns {Value}
    */
    get_total_output() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilder_get_total_output(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return Value.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * does not include fee
    * @returns {Value}
    */
    get_explicit_output() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilder_get_explicit_output(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return Value.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {BigNum}
    */
    get_deposit() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilder_get_deposit(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return BigNum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {BigNum | undefined}
    */
    get_fee_if_set() {
        const ret = wasm.transactionbuilder_get_fee_if_set(this.ptr);
        return ret === 0 ? undefined : BigNum.__wrap(ret);
    }
    /**
    * @param {TransactionOutput} output
    */
    set_collateral_return(output) {
        _assertClass(output, TransactionOutput);
        wasm.transactionbuilder_set_collateral_return(this.ptr, output.ptr);
    }
    /**
    * @returns {number}
    */
    full_size() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilder_full_size(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return r0 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @returns {Uint32Array}
    */
    output_sizes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilder_output_sizes(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var v0 = getArrayU32FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 4);
            return v0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Builds the transaction and moves to the next step redeemer units can be added and a draft tx can
    * be evaluated
    * NOTE: is_valid set to true
    * @param {number} algo
    * @param {Address} change_address
    * @returns {TxRedeemerBuilder}
    */
    build_for_evaluation(algo, change_address) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(change_address, Address);
            wasm.transactionbuilder_build_for_evaluation(retptr, this.ptr, algo, change_address.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return TxRedeemerBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Builds the transaction and moves to the next step where any real witness can be added
    * NOTE: is_valid set to true
    * @param {number} algo
    * @param {Address} change_address
    * @returns {SignedTxBuilder}
    */
    build(algo, change_address) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(change_address, Address);
            wasm.transactionbuilder_build(retptr, this.ptr, algo, change_address.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return SignedTxBuilder.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * used to override the exunit values initially provided when adding inputs
    * @param {RedeemerWitnessKey} redeemer
    * @param {ExUnits} ex_units
    */
    set_exunits(redeemer, ex_units) {
        _assertClass(redeemer, RedeemerWitnessKey);
        _assertClass(ex_units, ExUnits);
        wasm.transactionbuilder_set_exunits(this.ptr, redeemer.ptr, ex_units.ptr);
    }
    /**
    * warning: sum of all parts of a transaction must equal 0. You cannot just set the fee to the min value and forget about it
    * warning: min_fee may be slightly larger than the actual minimum fee (ex: a few lovelaces)
    * this is done to simplify the library code, but can be fixed later
    * @param {boolean} script_calulation
    * @returns {BigNum}
    */
    min_fee(script_calulation) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.transactionbuilder_min_fee(retptr, this.ptr, script_calulation);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return BigNum.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}