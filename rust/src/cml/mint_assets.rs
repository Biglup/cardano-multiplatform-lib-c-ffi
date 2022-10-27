/**
export class MintAssets {

    static __wrap(ptr) {
        const obj = Object.create(MintAssets.prototype);
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
        wasm.__wbg_mintassets_free(ptr);
    }
    /**
    * @returns {MintAssets}
    */
    static new() {
        const ret = wasm.mintassets_new();
        return MintAssets.__wrap(ret);
    }
    /**
    * @param {AssetName} key
    * @param {Int} value
    * @returns {MintAssets}
    */
    static new_from_entry(key, value) {
        _assertClass(key, AssetName);
        _assertClass(value, Int);
        var ptr0 = value.ptr;
        value.ptr = 0;
        const ret = wasm.mintassets_new_from_entry(key.ptr, ptr0);
        return MintAssets.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    len() {
        const ret = wasm.mintassets_len(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {AssetName} key
    * @param {Int} value
    * @returns {Int | undefined}
    */
    insert(key, value) {
        _assertClass(key, AssetName);
        _assertClass(value, Int);
        var ptr0 = value.ptr;
        value.ptr = 0;
        const ret = wasm.mintassets_insert(this.ptr, key.ptr, ptr0);
        return ret === 0 ? undefined : Int.__wrap(ret);
    }
    /**
    * @param {AssetName} key
    * @returns {Int | undefined}
    */
    get(key) {
        _assertClass(key, AssetName);
        const ret = wasm.mintassets_get(this.ptr, key.ptr);
        return ret === 0 ? undefined : Int.__wrap(ret);
    }
    /**
    * @returns {AssetNames}
    */
    keys() {
        const ret = wasm.mintassets_keys(this.ptr);
        return AssetNames.__wrap(ret);
    }
}