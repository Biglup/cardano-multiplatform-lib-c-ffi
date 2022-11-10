extern crate cardano_multiplatform_lib;
extern crate libc;

use cardano_multiplatform_lib::plutus::Languages;
use cardano_multiplatform_lib::plutus::Language;

#[no_mangle]
pub extern "C" fn languages_new() -> *mut Languages {
    return Box::into_raw(Box::new(Languages::new()));
}

#[no_mangle]
pub extern "C" fn languages_free(ptr: *mut Languages) {
    assert!(!ptr.is_null());

    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn languages_len(ptr: *mut Languages) -> usize {
    let val = unsafe {
        assert!(!ptr.is_null());
        &*ptr
    };

    return val.len();
}

#[no_mangle]
pub extern "C" fn languages_get(ptr: *mut Languages, index: usize) -> *mut Language {
    let val = unsafe {
        assert!(!ptr.is_null());
        &*ptr
    };

    return Box::into_raw(Box::new(val.get(index)));
}

#[no_mangle]
pub extern "C" fn languages_add(ptr: *mut Languages, elem: *mut Language) {
    let val = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    let val2 = unsafe {
        assert!(!elem.is_null());
        &*elem
    };

    val.add(*val2);
}