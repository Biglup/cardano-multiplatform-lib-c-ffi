#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

typedef struct network_info network_info_t;
typedef struct transaction_metadatum transaction_metadatum_t;

enum MetadataJsonSchema {
    NoConversions = 0,
    BasicConversions = 1,
    DetailedSchema = 2
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

} // extern "C"
