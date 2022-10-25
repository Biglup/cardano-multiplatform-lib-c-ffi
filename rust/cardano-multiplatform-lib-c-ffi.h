#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

typedef struct network_info network_info_t;
typedef struct transaction_metadatum transaction_metadatum_t;
typedef struct plutus_data plutus_data_t;

enum MetadataJsonSchema {
    METADATA_JSON_SCHEMA_NO_CONVERSIONS = 0,
    METADATA_JSON_SCHEMA_BASIC_CONVERSIONS = 1,
    METADATA_JSON_SCHEMA_DETAILED_SCHEMA = 2
};

enum PlutusDatumSchema {
    PLUTUS_DATUM_SCHEMA_BASIC_CONVERSIONS = 0,
    PLUTUS_DATUM_SCHEMA_DETAILED_SCHEMA = 1
};

struct Buffer {
  int32_t len;
  uint8_t *data;
};

extern "C" {

void free_buffer(Buffer buf);

/// This is intended for the C code to call for deallocating the
/// Rust-allocated i32 array.
void deallocate_rust_buffer(int32_t* ptr, uint32_t len);

network_info* network_info_new(uint8_t network_id, uint32_t protocol_magic);

void network_info_free(network_info* ptr);

uint8_t network_info_network_id(network_info* ptr);

uint32_t network_info_protocol_magic(network_info* ptr);

transaction_metadatum_t* encode_arbitrary_bytes_as_metadatum(uint8_t* ptr, uintptr_t size);

Buffer decode_arbitrary_bytes_from_metadatum(transaction_metadatum_t* ptr);

transaction_metadatum_t* encode_json_str_to_metadatum(const char* json, MetadataJsonSchema schema);

const char* decode_metadatum_to_json_str(transaction_metadatum_t* ptr, MetadataJsonSchema schema);

void free_c_str(const char* str);


const char* encrypt_with_password(const char* password, const char* salt, const char* nonce, const char* data);
const char* decrypt_with_password(const char* password, const char* data);


plutus_data_t* encode_json_str_to_plutus_datum(const char* json, PlutusDatumSchema schema);
const char* decode_plutus_datum_to_json_str(plutus_data_t* ptr, PlutusDatumSchema schema);

} // extern "C"
