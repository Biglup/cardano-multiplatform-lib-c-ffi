/**
export class WithdrawalBuilderResult {

    static __wrap(ptr) {
        const obj = Object.create(WithdrawalBuilderResult.prototype);
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
        wasm.__wbg_withdrawalbuilderresult_free(ptr);
    }
}