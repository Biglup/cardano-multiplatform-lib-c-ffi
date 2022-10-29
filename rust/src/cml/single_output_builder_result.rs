/**
export class SingleOutputBuilderResult {

    static __wrap(ptr) {
        const obj = Object.create(SingleOutputBuilderResult.prototype);
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
        wasm.__wbg_singleoutputbuilderresult_free(ptr);
    }
    /**
    * @param {TransactionOutput} output
    * @returns {SingleOutputBuilderResult}
    */
    static new(output) {
        _assertClass(output, TransactionOutput);
        const ret = wasm.singleoutputbuilderresult_new(output.ptr);
        return SingleOutputBuilderResult.__wrap(ret);
    }
    /**
    * @param {PlutusData} datum
    */
    set_communication_datum(datum) {
        _assertClass(datum, PlutusData);
        wasm.singleoutputbuilderresult_set_communication_datum(this.ptr, datum.ptr);
    }
    /**
    * @returns {TransactionOutput}
    */
    output() {
        const ret = wasm.singleoutputbuilderresult_output(this.ptr);
        return TransactionOutput.__wrap(ret);
    }
    /**
    * @returns {PlutusData | undefined}
    */
    communication_datum() {
        const ret = wasm.singleoutputbuilderresult_communication_datum(this.ptr);
        return ret === 0 ? undefined : PlutusData.__wrap(ret);
    }
}