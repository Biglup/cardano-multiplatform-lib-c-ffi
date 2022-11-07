extern crate cardano_multiplatform_lib;
extern crate libc;

use cardano_multiplatform_lib::address::NetworkInfo;

#[no_mangle]
pub extern "C" fn network_info_new(network_id: u8, protocol_magic: u32) -> *mut NetworkInfo {
    Box::into_raw(Box::new(NetworkInfo::new(network_id, protocol_magic)))
}

#[no_mangle]
pub extern "C" fn network_info_free(ptr: *mut NetworkInfo) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn network_info_network_id(ptr: *mut NetworkInfo) -> u8 {
    let network_info = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return network_info.network_id();
}

#[no_mangle]
pub extern "C" fn network_info_protocol_magic(ptr: *mut NetworkInfo) -> u32 {
    let network_info = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return network_info.protocol_magic();
}

#[no_mangle]
pub extern "C" fn network_info_testnet() -> *mut NetworkInfo {
    Box::into_raw(Box::new(NetworkInfo::testnet()))
}

#[no_mangle]
pub extern "C" fn network_info_mainnet() -> *mut NetworkInfo {
    Box::into_raw(Box::new(NetworkInfo::mainnet()))
}