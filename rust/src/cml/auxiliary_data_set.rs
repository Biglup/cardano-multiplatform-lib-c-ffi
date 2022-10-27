/**
export class AuxiliaryDataSet {

    static __wrap(ptr) {
        const obj = Object.create(AuxiliaryDataSet.prototype);
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
        wasm.__wbg_auxiliarydataset_free(ptr);
    }
    /**
    * @returns {AuxiliaryDataSet}
    */
    static new() {
        const ret = wasm.auxiliarydataset_new();
        return AuxiliaryDataSet.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    len() {
        const ret = wasm.auxiliarydataset_len(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {BigNum} tx_index
    * @param {AuxiliaryData} data
    * @returns {AuxiliaryData | undefined}
    */
    insert(tx_index, data) {
        _assertClass(tx_index, BigNum);
        _assertClass(data, AuxiliaryData);
        const ret = wasm.auxiliarydataset_insert(this.ptr, tx_index.ptr, data.ptr);
        return ret === 0 ? undefined : AuxiliaryData.__wrap(ret);
    }
    /**
    * @param {BigNum} tx_index
    * @returns {AuxiliaryData | undefined}
    */
    get(tx_index) {
        _assertClass(tx_index, BigNum);
        const ret = wasm.auxiliarydataset_get(this.ptr, tx_index.ptr);
        return ret === 0 ? undefined : AuxiliaryData.__wrap(ret);
    }
    /**
    * @returns {TransactionIndexes}
    */
    indices() {
        const ret = wasm.auxiliarydataset_indices(this.ptr);
        return TransactionIndexes.__wrap(ret);
    }
}