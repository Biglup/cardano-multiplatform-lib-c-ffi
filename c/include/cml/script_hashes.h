/**
 * @file script_hashes.h
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

#ifndef CML_SCRIPT_HASHES_H_
#define CML_SCRIPT_HASHES_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <cml/script_hash.h>
#include <cml/result.h>
#include <cml/buffer.h>

/* DEFINITIONS **************************************************************/

typedef struct _script_hashes_ script_hashes_t;

/* PROTOTYPES ***************************************************************/

script_hashes_t* script_hashes_new();
void script_hashes_free(script_hashes_t* ptr);
script_hash_t* script_hashes_get(script_hashes_t* ptr, uint64_t index);
uint64_t script_hashes_len(script_hashes_t* ptr);
void script_hashes_add(script_hashes_t* ptr, script_hash_t* element);
buffer_t* script_hashes_to_bytes(script_hashes_t* ptr);
result_t* script_hashes_from_bytes(uint8_t* data, uint32_t size);
result_t* script_hashes_from_json(const char* str);
result_t* script_hashes_to_json(script_hashes_t* ptr);

#endif /* CML_SCRIPT_HASHES_H_ */