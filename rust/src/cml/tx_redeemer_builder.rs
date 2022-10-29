/**
export class TxRedeemerBuilder {

    static __wrap(ptr) {
        const obj = Object.create(TxRedeemerBuilder.prototype);
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
        wasm.__wbg_txredeemerbuilder_free(ptr);
    }
    /**
    * Builds the transaction and moves to the next step where any real witness can be added
    * NOTE: is_valid set to true
    * Will NOT require you to have set required signers & witnesses
    * @returns {Redeemers}
    */
    build() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.txredeemerbuilder_build(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return Redeemers.__wrap(r0);
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
        wasm.txredeemerbuilder_set_exunits(this.ptr, redeemer.ptr, ex_units.ptr);
    }
    /**
    * Transaction body with a dummy values for redeemers & script_data_hash
    * Used for calculating exunits or required signers
    * @returns {TransactionBody}
    */
    draft_body() {
        const ret = wasm.txredeemerbuilder_draft_body(this.ptr);
        return TransactionBody.__wrap(ret);
    }
    /**
    * @returns {AuxiliaryData | undefined}
    */
    auxiliary_data() {
        const ret = wasm.txredeemerbuilder_auxiliary_data(this.ptr);
        return ret === 0 ? undefined : AuxiliaryData.__wrap(ret);
    }
    /**
    * Transaction body with a dummy values for redeemers & script_data_hash and padded with dummy witnesses
    * Used for calculating exunits
    * note: is_valid set to true
    * @returns {Transaction}
    */
    draft_tx() {
        const ret = wasm.txredeemerbuilder_draft_tx(this.ptr);
        return Transaction.__wrap(ret);
    }
}