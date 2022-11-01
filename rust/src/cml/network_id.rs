mod ffi_utils;

extern crate cardano_multiplatform_lib;
extern crate libc;

use cardano_multiplatform_lib::NetworkId;

#[no_mangle]
pub extern "C" fn network_id_free(ptr: *mut NetworkId) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn network_id_testnet() -> *mut NetworkId {
    Box::into_raw(Box::new(NetworkId::testnet()))
}

#[no_mangle]
pub extern "C" fn network_id_mainnet() -> *mut NetworkId {
    Box::into_raw(Box::new(NetworkId::mainnet()))
}

#[no_mangle]
pub extern "C" fn network_id_to_json(ptr: *mut NetworkId) -> *const c_char {
    let network_id = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let result = network_id.to_json();

    match result {
        Ok(v) => {
            let s = CString::new(v).unwrap();
            let p = s.as_ptr();
            std::mem::forget(s);
            return p;
        },
        Err(_) => {
            return ptr::null();
        }
    };
}

#[no_mangle]
pub extern "C" fn network_id_from_json(json: *const c_char) -> *mut NetworkId {

    let c_str: &CStr = unsafe { CStr::from_ptr(json) };
    let str_slice: &str = c_str.to_str().unwrap();
    let str_buf: String = str_slice.to_owned(); 

   
    let result = NetworkId::from_json(str_buf);

    match result {
        Ok(v) => {
            return Box::into_raw(Box::new(v));
        },
        Err(_) => {
            return ptr::null_mut();
        }
    };
}

#[no_mangle]
pub extern "C" fn network_id_from_bytes(buffer: *mut Buffer) -> *mut NetworkId {
     unsafe {
        let bytes: &mut [u8] = core::slice::from_raw_parts_mut(ptr, size);
        return Box::into_raw(Box::new(NetworkId::from_bytes(bytes)));
    }
}


#[no_mangle]
pub extern "C" fn network_id_to_bytes(ptr: *mut NetworkId, force_canonical: bool) -> Buffer {
    let network_info = unsafe {
        assert!(!ptr.is_null());
        &*ptr
    };

    let result = network_info.to_bytes(force_canonical);

    let mut buf = result.into_boxed_slice();
    let data = buf.as_mut_ptr();
    let len = buf.len() as i32;

    std::mem::forget(buf);
    Buffer { len, data }
}




/**
export class NetworkId {

    static __wrap(ptr) {
        const obj = Object.create(NetworkId.prototype);
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
        wasm.__wbg_networkid_free(ptr);
    }
    /**
    * @returns {Uint8Array}
    */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.networkid_to_bytes(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var v0 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_free(r0, r1 * 1);
            return v0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {NetworkId}
    */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.networkid_from_bytes(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return NetworkId.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
  
    /**
    * @returns {NetworkId}
    */
    static testnet() {
        const ret = wasm.networkid_testnet();
        return NetworkId.__wrap(ret);
    }
    /**
    * @returns {NetworkId}
    */
    static mainnet() {
        const ret = wasm.networkid_mainnet();
        return NetworkId.__wrap(ret);
    }
    /**
    * @returns {number}
    */
    kind() {
        const ret = wasm.networkid_kind(this.ptr);
        return ret >>> 0;
    }
}