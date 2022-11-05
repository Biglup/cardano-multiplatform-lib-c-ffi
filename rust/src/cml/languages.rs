/**
export class Languages {

    static __wrap(ptr) {
        const obj = Object.create(Languages.prototype);
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
        wasm.__wbg_languages_free(ptr);
    }
    /**
    * @returns {Languages}
    */
    static new() {
        const ret = wasm.languages_new();
        return Languages.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    len() {
        const ret = wasm.languages_len(this.ptr);
        return ret >>> 0;
    }
    /**
    * @param {number} index
    * @returns {Language}
    */
    get(index) {
        const ret = wasm.languages_get(this.ptr, index);
        return Language.__wrap(ret);
    }
    /**
    * @param {Language} elem
    */
    add(elem) {
        _assertClass(elem, Language);
        var ptr0 = elem.ptr;
        elem.ptr = 0;
        wasm.languages_add(this.ptr, ptr0);
    }
}