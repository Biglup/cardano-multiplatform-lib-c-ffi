/**
export class TransactionUnspentOutputs {

    static __wrap(ptr) {
        const obj = Object.create(TransactionUnspentOutputs.prototype);
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
        wasm.__wbg_transactionunspentoutputs_free(ptr);
    }
    /**
    * @returns {TransactionUnspentOutputs}
    */
    static new() {
        const ret = wasm.transactionunspentoutputs_new();
        return TransactionUnspentOutputs.__wrap(ret);
    }
    /**
    * @returns {boolean}
    */
    is_empty() {
        const ret = wasm.transactionunspentoutputs_is_empty(this.ptr);
        return ret !== 0;
    }
    /**
    * @returns {number}
    */
    len() {
        const ret = wasm.transactionunspentoutputs_len(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} index
    * @returns {TransactionUnspentOutput}
    */
    get(index) {
        const ret = wasm.transactionunspentoutputs_get(this.ptr, index);
        return TransactionUnspentOutput.__wrap(ret);
    }
    /**
    * @param {TransactionUnspentOutput} elem
    */
    add(elem) {
        _assertClass(elem, TransactionUnspentOutput);
        wasm.transactionunspentoutputs_add(this.ptr, elem.ptr);
    }
}