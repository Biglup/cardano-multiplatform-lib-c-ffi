/**
export class NetworkInfo {

    static __wrap(ptr) {
        const obj = Object.create(NetworkInfo.prototype);
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
        wasm.__wbg_networkinfo_free(ptr);
    }
    /**
    * @param {number} network_id
    * @param {number} protocol_magic
    * @returns {NetworkInfo}
    */
    static new(network_id, protocol_magic) {
        const ret = wasm.networkinfo_new(network_id, protocol_magic);
        return NetworkInfo.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    network_id() {
        const ret = wasm.networkinfo_network_id(this.ptr);
        return ret;
    }
    /**
    * @returns {number}
    */
    protocol_magic() {
        const ret = wasm.networkinfo_protocol_magic(this.ptr);
        return ret >>> 0;
    }
    /**
    * @returns {NetworkInfo}
    */
    static testnet() {
        const ret = wasm.networkinfo_testnet();
        return NetworkInfo.__wrap(ret);
    }
    /**
    * @returns {NetworkInfo}
    */
    static mainnet() {
        const ret = wasm.networkinfo_mainnet();
        return NetworkInfo.__wrap(ret);
    }
}