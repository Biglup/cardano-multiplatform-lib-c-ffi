mod utils;
mod cml;

extern crate cardano_multiplatform_lib;
extern crate libc;


use crate::utils::CBuffer;

use cardano_multiplatform_lib::metadata::TransactionMetadatum;
use cardano_multiplatform_lib::metadata::MetadataJsonSchema;

use cardano_multiplatform_lib::metadata::decode_arbitrary_bytes_from_metadatum as _decode_arbitrary_bytes_from_metadatum;
use cardano_multiplatform_lib::metadata::encode_arbitrary_bytes_as_metadatum as _encode_arbitrary_bytes_as_metadatum;

use cardano_multiplatform_lib::metadata::encode_json_str_to_metadatum as _encode_json_str_to_metadatum;
use cardano_multiplatform_lib::metadata::decode_metadatum_to_json_str as _decode_metadatum_to_json_str;
use cardano_multiplatform_lib::emip3::encrypt_with_password as _encrypt_with_password;
use cardano_multiplatform_lib::emip3::decrypt_with_password as _decrypt_with_password;

use cardano_multiplatform_lib::plutus::PlutusData;
use cardano_multiplatform_lib::plutus::PlutusDatumSchema;
use cardano_multiplatform_lib::plutus::encode_json_str_to_plutus_datum as _encode_json_str_to_plutus_datum;
use cardano_multiplatform_lib::plutus::decode_plutus_datum_to_json_str as _decode_plutus_datum_to_json_str;

use libc::c_char;
use std::ffi::CString;
use std::ffi::CStr;
use std::ptr;

// metadata
#[no_mangle]
pub extern "C" fn encode_arbitrary_bytes_as_metadatum(ptr: *mut u8, size: usize) -> *mut TransactionMetadatum {
     unsafe {
        let bytes: &mut [u8] = core::slice::from_raw_parts_mut(ptr, size);
        return Box::into_raw(Box::new(_encode_arbitrary_bytes_as_metadatum(bytes)));
    }
}


// decodes from chunks of bytes in a list to a byte vector if that is the metadata format, otherwise returns None
#[no_mangle]
pub extern "C" fn decode_arbitrary_bytes_from_metadatum(ptr: *mut TransactionMetadatum) -> *mut CBuffer {
    let metadata = unsafe {
        assert!(!ptr.is_null());
        &*ptr
    };

    let result = _decode_arbitrary_bytes_from_metadatum(metadata);

    let output = match result {
        Ok(v) => v,
        Err(_) => unsafe { Vec::from_raw_parts(0 as *mut u8, 0, 0) }
    };

    let mut buf = output.into_boxed_slice();
    let data = buf.as_mut_ptr();
    let len = buf.len() as i32;

    std::mem::forget(buf);
    
    return Box::into_raw(Box::new(CBuffer { len, data }));
}



//let p: *const i32 = ptr::null();


fn metadata_json_schema_from_u32(value: u32) -> MetadataJsonSchema {
    match value {
        0 => MetadataJsonSchema::NoConversions,
        1 => MetadataJsonSchema::BasicConversions,
        2 => MetadataJsonSchema::DetailedSchema,
        _ => panic!("Unknown value: {}", value),
    }
}


// metadata
#[no_mangle]
pub extern "C" fn encode_json_str_to_metadatum(json: *const c_char, schema: u32) -> *mut TransactionMetadatum {

    let c_str: &CStr = unsafe { CStr::from_ptr(json) };
    let str_slice: &str = c_str.to_str().unwrap();
    let str_buf: String = str_slice.to_owned(); 

   
    let result = _encode_json_str_to_metadatum(str_buf, metadata_json_schema_from_u32(schema));

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
pub extern "C" fn decode_metadatum_to_json_str(ptr: *mut TransactionMetadatum , schema: u32) -> *const c_char {
    let metadatum = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let result = _decode_metadatum_to_json_str(metadatum, metadata_json_schema_from_u32(schema));

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
pub extern "C" fn encrypt_with_password(password: *const c_char, salt: *const c_char, nonce: *const c_char, data: *const c_char) -> *const c_char {
    
    let password_c_str: &CStr = unsafe { CStr::from_ptr(password) };
    let password_str_slice: &str = password_c_str.to_str().unwrap();
    let salt_c_str: &CStr = unsafe { CStr::from_ptr(salt) };
    let salt_str_slice: &str = salt_c_str.to_str().unwrap();
    let nonce_c_str: &CStr = unsafe { CStr::from_ptr(nonce) };
    let nonce_str_slice: &str = nonce_c_str.to_str().unwrap();
    let data_c_str: &CStr = unsafe { CStr::from_ptr(data) };
    let data_str_slice: &str = data_c_str.to_str().unwrap();

    let result = _encrypt_with_password(password_str_slice, salt_str_slice, nonce_str_slice, data_str_slice);

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
pub extern "C" fn decrypt_with_password(password: *const c_char, data: *const c_char) -> *const c_char {
    
    let password_c_str: &CStr = unsafe { CStr::from_ptr(password) };
    let password_str_slice: &str = password_c_str.to_str().unwrap();
    let data_c_str: &CStr = unsafe { CStr::from_ptr(data) };
    let data_str_slice: &str = data_c_str.to_str().unwrap();

    let result = _decrypt_with_password(password_str_slice, data_str_slice);

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



fn plutus_datum_schema_from_u32(value: u32) -> PlutusDatumSchema {
    match value {
        0 => PlutusDatumSchema::BasicConversions,
        1 => PlutusDatumSchema::DetailedSchema,
        _ => panic!("Unknown value: {}", value),
    }
}

// metadata
#[no_mangle]
pub extern "C" fn encode_json_str_to_plutus_datum(json: *const c_char, schema: u32) -> *mut PlutusData {

    let c_str: &CStr = unsafe { CStr::from_ptr(json) };
    let str_slice: &str = c_str.to_str().unwrap();
   
    let result = _encode_json_str_to_plutus_datum(str_slice, plutus_datum_schema_from_u32(schema));

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
pub extern "C" fn decode_plutus_datum_to_json_str(ptr: *mut PlutusData , schema: u32) -> *const c_char {
    let plutus_data = unsafe {
        assert!(!ptr.is_null());
        &mut* ptr
    };

    let result = _decode_plutus_datum_to_json_str(plutus_data, plutus_datum_schema_from_u32(schema));

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


/* 

* @param {TransactionHash} tx_body_hash
* @param {ByronAddress} addr
* @param {LegacyDaedalusPrivateKey} key
* @returns {BootstrapWitness}

export function make_daedalus_bootstrap_witness(tx_body_hash, addr, key) {
    _assertClass(tx_body_hash, TransactionHash);
    _assertClass(addr, ByronAddress);
    _assertClass(key, LegacyDaedalusPrivateKey);
    const ret = wasm.make_daedalus_bootstrap_witness(tx_body_hash.ptr, addr.ptr, key.ptr);
    return BootstrapWitness.__wrap(ret);
}


* @param {TransactionHash} tx_body_hash
* @param {ByronAddress} addr
* @param {Bip32PrivateKey} key
* @returns {BootstrapWitness}

export function make_icarus_bootstrap_witness(tx_body_hash, addr, key) {
    _assertClass(tx_body_hash, TransactionHash);
    _assertClass(addr, ByronAddress);
    _assertClass(key, Bip32PrivateKey);
    const ret = wasm.make_icarus_bootstrap_witness(tx_body_hash.ptr, addr.ptr, key.ptr);
    return BootstrapWitness.__wrap(ret);
}


* Receives a script JSON string
* and returns a NativeScript.
* Cardano Wallet and Node styles are supported.
*
* * wallet: https://github.com/input-output-hk/cardano-wallet/blob/master/specifications/api/swagger.yaml
* * node: https://github.com/input-output-hk/cardano-node/blob/master/doc/reference/simple-scripts.md
*
* self_xpub is expected to be a Bip32PublicKey as hex-encoded bytes
* @param {string} json
* @param {string} self_xpub
* @param {number} schema
* @returns {NativeScript}

export function encode_json_str_to_native_script(json, self_xpub, schema) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(self_xpub, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        wasm.encode_json_str_to_native_script(retptr, ptr0, len0, ptr1, len1, schema);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return NativeScript.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}


* Provide backwards compatibility to Alonzo by taking the max min value of both er
* @param {TransactionOutput} output
* @param {BigNum} coins_per_utxo_byte
* @param {BigNum} coins_per_utxo_word
* @returns {BigNum}

export function compatible_min_ada_required(output, coins_per_utxo_byte, coins_per_utxo_word) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(output, TransactionOutput);
        _assertClass(coins_per_utxo_byte, BigNum);
        _assertClass(coins_per_utxo_word, BigNum);
        wasm.compatible_min_ada_required(retptr, output.ptr, coins_per_utxo_byte.ptr, coins_per_utxo_word.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return BigNum.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}


* @param {TransactionOutput} output
* @param {BigNum} coins_per_utxo_byte
* @returns {BigNum}

export function min_ada_required(output, coins_per_utxo_byte) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(output, TransactionOutput);
        _assertClass(coins_per_utxo_byte, BigNum);
        wasm.min_ada_required(retptr, output.ptr, coins_per_utxo_byte.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return BigNum.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}



* @param {Transaction} tx
* @param {ExUnitPrices} ex_unit_prices
* @returns {BigNum}

export function min_script_fee(tx, ex_unit_prices) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(tx, Transaction);
        _assertClass(ex_unit_prices, ExUnitPrices);
        wasm.min_script_fee(retptr, tx.ptr, ex_unit_prices.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return BigNum.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}


* @param {Transaction} tx
* @param {LinearFee} linear_fee
* @returns {BigNum}

export function min_no_script_fee(tx, linear_fee) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(tx, Transaction);
        _assertClass(linear_fee, LinearFee);
        wasm.min_no_script_fee(retptr, tx.ptr, linear_fee.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return BigNum.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}


* @param {Transaction} tx
* @param {LinearFee} linear_fee
* @param {ExUnitPrices} ex_unit_prices
* @returns {BigNum}

export function min_fee(tx, linear_fee, ex_unit_prices) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(tx, Transaction);
        _assertClass(linear_fee, LinearFee);
        _assertClass(ex_unit_prices, ExUnitPrices);
        wasm.min_fee(retptr, tx.ptr, linear_fee.ptr, ex_unit_prices.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return BigNum.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}


* @param {TransactionBody} txbody
* @param {BigNum} pool_deposit
* @param {BigNum} key_deposit
* @returns {Value}

export function get_implicit_input(txbody, pool_deposit, key_deposit) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(txbody, TransactionBody);
        _assertClass(pool_deposit, BigNum);
        _assertClass(key_deposit, BigNum);
        wasm.get_implicit_input(retptr, txbody.ptr, pool_deposit.ptr, key_deposit.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return Value.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}


* @param {TransactionBody} txbody
* @param {BigNum} pool_deposit
* @param {BigNum} key_deposit
* @returns {BigNum}

export function get_deposit(txbody, pool_deposit, key_deposit) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(txbody, TransactionBody);
        _assertClass(pool_deposit, BigNum);
        _assertClass(key_deposit, BigNum);
        wasm.get_deposit(retptr, txbody.ptr, pool_deposit.ptr, key_deposit.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return BigNum.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}


* @param {AuxiliaryData} auxiliary_data
* @returns {AuxiliaryDataHash}

export function hash_auxiliary_data(auxiliary_data) {
    _assertClass(auxiliary_data, AuxiliaryData);
    const ret = wasm.hash_auxiliary_data(auxiliary_data.ptr);
    return AuxiliaryDataHash.__wrap(ret);
}


* @param {TransactionBody} tx_body
* @returns {TransactionHash}

export function hash_transaction(tx_body) {
    _assertClass(tx_body, TransactionBody);
    const ret = wasm.hash_transaction(tx_body.ptr);
    return TransactionHash.__wrap(ret);
}


* @param {PlutusData} plutus_data
* @returns {DataHash}

export function hash_plutus_data(plutus_data) {
    _assertClass(plutus_data, PlutusData);
    const ret = wasm.hash_plutus_data(plutus_data.ptr);
    return DataHash.__wrap(ret);
}


* @param {Redeemers} redeemers
* @param {Costmdls} cost_models
* @param {PlutusList | undefined} datums
* @returns {ScriptDataHash}

export function hash_script_data(redeemers, cost_models, datums) {
    _assertClass(redeemers, Redeemers);
    _assertClass(cost_models, Costmdls);
    let ptr0 = 0;
    if (!isLikeNone(datums)) {
        _assertClass(datums, PlutusList);
        ptr0 = datums.ptr;
        datums.ptr = 0;
    }
    const ret = wasm.hash_script_data(redeemers.ptr, cost_models.ptr, ptr0);
    return ScriptDataHash.__wrap(ret);
}


* @param {Redeemers} redeemers
* @param {PlutusList} datums
* @param {Costmdls} cost_models
* @param {Languages} used_langs
* @returns {ScriptDataHash | undefined}

export function calc_script_data_hash(redeemers, datums, cost_models, used_langs) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(redeemers, Redeemers);
        _assertClass(datums, PlutusList);
        _assertClass(cost_models, Costmdls);
        _assertClass(used_langs, Languages);
        wasm.calc_script_data_hash(retptr, redeemers.ptr, datums.ptr, cost_models.ptr, used_langs.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return r0 === 0 ? undefined : ScriptDataHash.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}


* @param {TransactionHash} tx_body_hash
* @param {PrivateKey} sk
* @returns {Vkeywitness}

export function make_vkey_witness(tx_body_hash, sk) {
    _assertClass(tx_body_hash, TransactionHash);
    _assertClass(sk, PrivateKey);
    const ret = wasm.make_vkey_witness(tx_body_hash.ptr, sk.ptr);
    return Vkeywitness.__wrap(ret);
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_exn_store(addHeapObject(e));
    }
}


export const DatumKind = Object.freeze({ Hash:0,"0":"Hash",Inline:1,"1":"Inline", });


export const CertificateKind = Object.freeze({ StakeRegistration:0,"0":"StakeRegistration",StakeDeregistration:1,"1":"StakeDeregistration",StakeDelegation:2,"2":"StakeDelegation",PoolRegistration:3,"3":"PoolRegistration",PoolRetirement:4,"4":"PoolRetirement",GenesisKeyDelegation:5,"5":"GenesisKeyDelegation",MoveInstantaneousRewardsCert:6,"6":"MoveInstantaneousRewardsCert", });


export const MIRPot = Object.freeze({ Reserves:0,"0":"Reserves",Treasury:1,"1":"Treasury", });


export const MIRKind = Object.freeze({ ToOtherPot:0,"0":"ToOtherPot",ToStakeCredentials:1,"1":"ToStakeCredentials", });


export const RelayKind = Object.freeze({ SingleHostAddr:0,"0":"SingleHostAddr",SingleHostName:1,"1":"SingleHostName",MultiHostName:2,"2":"MultiHostName", });


export const NativeScriptKind = Object.freeze({ ScriptPubkey:0,"0":"ScriptPubkey",ScriptAll:1,"1":"ScriptAll",ScriptAny:2,"2":"ScriptAny",ScriptNOfK:3,"3":"ScriptNOfK",TimelockStart:4,"4":"TimelockStart",TimelockExpiry:5,"5":"TimelockExpiry", });


export const NetworkIdKind = Object.freeze({ Testnet:0,"0":"Testnet",Mainnet:1,"1":"Mainnet", });


export const LanguageKind = Object.freeze({ PlutusV1:0,"0":"PlutusV1",PlutusV2:1,"1":"PlutusV2", });


export const PlutusDataKind = Object.freeze({ ConstrPlutusData:0,"0":"ConstrPlutusData",Map:1,"1":"Map",List:2,"2":"List",Integer:3,"3":"Integer",Bytes:4,"4":"Bytes", });


export const RedeemerTagKind = Object.freeze({ Spend:0,"0":"Spend",Mint:1,"1":"Mint",Cert:2,"2":"Cert",Reward:3,"3":"Reward", });


export const ScriptKind = Object.freeze({ NativeScript:0,"0":"NativeScript",PlutusScriptV1:1,"1":"PlutusScriptV1",PlutusScriptV2:2,"2":"PlutusScriptV2", });

* JSON <-> PlutusData conversion schemas.
* Follows ScriptDataJsonSchema in cardano-cli defined at:
* https://github.com/input-output-hk/cardano-node/blob/master/cardano-api/src/Cardano/Api/ScriptData.hs#L254
*
* All methods here have the following restrictions due to limitations on dependencies:
* * JSON numbers above u64::MAX (positive) or below i64::MIN (negative) will throw errors
* * Hex strings for bytes don't accept odd-length (half-byte) strings.
*      cardano-cli seems to support these however but it seems to be different than just 0-padding
*      on either side when tested so proceed with caution

export const PlutusDatumSchema = Object.freeze({

* ScriptDataJsonNoSchema in cardano-node.
*
* This is the format used by --script-data-value in cardano-cli
* This tries to accept most JSON but does not support the full spectrum of Plutus datums.
* From JSON:
* * null/true/false/floats NOT supported
* * strings starting with 0x are treated as hex bytes. All other strings are encoded as their utf8 bytes.
* To JSON:
* * ConstrPlutusData not supported in ANY FORM (neither keys nor values)
* * Lists not supported in keys
* * Maps not supported in keys

BasicConversions:0,"0":"BasicConversions",

* ScriptDataJsonDetailedSchema in cardano-node.
*
* This is the format used by --script-data-file in cardano-cli
* This covers almost all (only minor exceptions) Plutus datums, but the JSON must conform to a strict schema.
* The schema specifies that ALL keys and ALL values must be contained in a JSON map with 2 cases:
* 1. For ConstrPlutusData there must be two fields "constructor" contianing a number and "fields" containing its fields
*    e.g. { "constructor": 2, "fields": [{"int": 2}, {"list": [{"bytes": "CAFEF00D"}]}]}
* 2. For all other cases there must be only one field named "int", "bytes", "list" or "map"
*    Integer's value is a JSON number e.g. {"int": 100}
*    Bytes' value is a hex string representing the bytes WITHOUT any prefix e.g. {"bytes": "CAFEF00D"}
*    Lists' value is a JSON list of its elements encoded via the same schema e.g. {"list": [{"bytes": "CAFEF00D"}]}
*    Maps' value is a JSON list of objects, one for each key-value pair in the map, with keys "k" and "v"
*          respectively with their values being the plutus datum encoded via this same schema
*          e.g. {"map": [
*              {"k": {"int": 2}, "v": {"int": 5}},
*              {"k": {"map": [{"k": {"list": [{"int": 1}]}, "v": {"bytes": "FF03"}}]}, "v": {"list": []}}
*          ]}
* From JSON:
* * null/true/false/floats NOT supported
* * the JSON must conform to a very specific schema
* To JSON:
* * all Plutus datums should be fully supported outside of the integer range limitations outlined above.

DetailedSchema:1,"1":"DetailedSchema", });


export const TransactionMetadatumKind = Object.freeze({ MetadataMap:0,"0":"MetadataMap",MetadataList:1,"1":"MetadataList",Int:2,"2":"Int",Bytes:3,"3":"Bytes",Text:4,"4":"Text", });


export const MetadataJsonSchema = Object.freeze({ NoConversions:0,"0":"NoConversions",BasicConversions:1,"1":"BasicConversions",DetailedSchema:2,"2":"DetailedSchema", });

* Used to choose the schema for a script JSON string

export const ScriptSchema = Object.freeze({ Wallet:0,"0":"Wallet",Node:1,"1":"Node", });


export const StakeDistributionKind = Object.freeze({ BootstrapEraDistr:0,"0":"BootstrapEraDistr",SingleKeyDistr:1,"1":"SingleKeyDistr", });


export const AddrtypeKind = Object.freeze({ ATPubKey:0,"0":"ATPubKey",ATScript:1,"1":"ATScript",ATRedeem:2,"2":"ATRedeem", });


export const SpendingDataKind = Object.freeze({ SpendingDataPubKeyASD:0,"0":"SpendingDataPubKeyASD",SpendingDataScriptASD:1,"1":"SpendingDataScriptASD",SpendingDataRedeemASD:2,"2":"SpendingDataRedeemASD", });


export const StakeCredKind = Object.freeze({ Key:0,"0":"Key",Script:1,"1":"Script", });

* Careful: this enum doesn't include the network ID part of the header
* ex: base address isn't 0b0000_0000 but instead 0b0000
* Use `header_matches_kind` if you don't want to implement the bitwise operators yourself

export const AddressHeaderKind = Object.freeze({ BasePaymentKeyStakeKey:0,"0":"BasePaymentKeyStakeKey",BasePaymentScriptStakeKey:1,"1":"BasePaymentScriptStakeKey",BasePaymentKeyStakeScript:2,"2":"BasePaymentKeyStakeScript",BasePaymentScriptStakeScript:3,"3":"BasePaymentScriptStakeScript",PointerKey:4,"4":"PointerKey",PointerScript:5,"5":"PointerScript",EnterpriseKey:6,"6":"EnterpriseKey",EnterpriseScript:7,"7":"EnterpriseScript",Byron:8,"8":"Byron",RewardKey:14,"14":"RewardKey",RewardScript:15,"15":"RewardScript", });


export const CoinSelectionStrategyCIP2 = Object.freeze({

* Performs CIP2's Largest First ada-only selection. Will error if outputs contain non-ADA assets.

LargestFirst:0,"0":"LargestFirst",

* Performs CIP2's Random Improve ada-only selection. Will error if outputs contain non-ADA assets.

RandomImprove:1,"1":"RandomImprove",

* Same as LargestFirst, but before adding ADA, will insert by largest-first for each asset type.

LargestFirstMultiAsset:2,"2":"LargestFirstMultiAsset",

* Same as RandomImprove, but before adding ADA, will insert by random-improve for each asset type.

RandomImproveMultiAsset:3,"3":"RandomImproveMultiAsset", });


export const ChangeSelectionAlgo = Object.freeze({ Default:0,"0":"Default", });

* Each new language uses a different namespace for hashing its script
* This is because you could have a language where the same bytes have different semantics
* So this avoids scripts in different languages mapping to the same hash
* Note that the enum value here is different than the enum value for deciding the cost model of a script
* https://github.com/input-output-hk/cardano-ledger/blob/9c3b4737b13b30f71529e76c5330f403165e28a6/eras/alonzo/impl/src/Cardano/Ledger/Alonzo.hs#L127

export const ScriptHashNamespace = Object.freeze({ NativeScript:0,"0":"NativeScript",PlutusV1:1,"1":"PlutusV1",PlutusV2:2,"2":"PlutusV2", });
*/