/**
 * @file transaction_metadatum.h
 *
 * @author Angel Castillo <angel.castillob@protonmail.com>
 * @date   Sep 08 2022
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CML_TRANSACTION_METADATUM_H_
#define CML_TRANSACTION_METADATUM_H_

/* INCLUDES ******************************************************************/

#include <cml/metadata_json_schema.h>
#include <cml/buffer.h>

#include <cstdint>

/* DEFINITIONS **************************************************************/

typedef struct transaction_metadatum transaction_metadatum_t;

/* PROTOTYPES ***************************************************************/

transaction_metadatum_t* encode_arbitrary_bytes_as_metadatum(uint8_t* ptr, uint32_t size);
buffer_t* decode_arbitrary_bytes_from_metadatum(transaction_metadatum_t* ptr);
transaction_metadatum_t* encode_json_str_to_metadatum(const char* json, MetadataJsonSchema schema);
const char* decode_metadatum_to_json_str(transaction_metadatum_t* ptr, MetadataJsonSchema schema);

#endif /* CML_TRANSACTION_METADATUM_H_ */