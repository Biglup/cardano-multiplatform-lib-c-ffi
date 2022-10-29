/**
export class ProtocolMagic {

    static __wrap(ptr) {
        const obj = Object.create(ProtocolMagic.prototype);
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
        wasm.__wbg_protocolmagic_free(ptr);
    }
    /**
    * @param {number} val
    * @returns {ProtocolMagic}
    */
    static new(val) {
        const ret = wasm.protocolmagic_new(val);
        return ProtocolMagic.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    value() {
        const ret = wasm.protocolmagic_value(this.ptr);
        return ret >>> 0;
    }
}