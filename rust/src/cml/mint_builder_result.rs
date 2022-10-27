/**
export class MintBuilderResult {

    static __wrap(ptr) {
        const obj = Object.create(MintBuilderResult.prototype);
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
        wasm.__wbg_mintbuilderresult_free(ptr);
    }
}