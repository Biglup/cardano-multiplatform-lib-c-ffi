/**
 * @file script_hash.h
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

#ifndef CML_SCRIPT_HASH_H_
#define CML_SCRIPT_HASH_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <stdbool.h>
#include <cml/big_num.h>
#include <cml/option.h>
#include <cml/result.h>
#include <cml/buffer.h>

/* DEFINITIONS **************************************************************/

typedef struct _script_hash_ script_hash_t;

/* PROTOTYPES ***************************************************************/

void script_hash_free(script_hash_t* ptr);
buffer_t* script_hash_to_bytes(script_hash_t* ptr);
result_t* script_hash_from_bytes(uint8_t* data, uint32_t size);
result_t* script_hash_from_bech32(const char* str);
result_t* script_hash_to_bech32(script_hash_t* ptr, const char* str);
result_t* script_hash_from_hex(const char* str);
const char*  script_hash_to_hex(script_hash_t* ptr);

#endif /* CML_SCRIPT_HASH_H_ */




