/**
export class Vkeys {

    static __wrap(ptr) {
        const obj = Object.create(Vkeys.prototype);
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
        wasm.__wbg_vkeys_free(ptr);
    }
    /**
    * @returns {Vkeys}
    */
    static new() {
        const ret = wasm.vkeys_new();
        return Vkeys.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    len() {
        const ret = wasm.vkeys_len(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} index
    * @returns {Vkey}
    */
    get(index) {
        const ret = wasm.vkeys_get(this.ptr, index);
        return Vkey.__wrap(ret);
    }
    /**
    * @param {Vkey} elem
    */
    add(elem) {
        _assertClass(elem, Vkey);
        wasm.vkeys_add(this.ptr, elem.ptr);
    }
}