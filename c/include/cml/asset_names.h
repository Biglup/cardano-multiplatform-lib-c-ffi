/**
 * @file asset_names.h
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

#ifndef CML_ASSET_NAMES_H_
#define CML_ASSET_NAMES_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <cml/asset_name.h>
#include <cml/result.h>
#include <cml/buffer.h>

/* DEFINITIONS **************************************************************/

typedef struct _asset_names_ asset_names_t;

/* PROTOTYPES ***************************************************************/

result_t* asset_names_new(uint8_t* data, uint32_t size);
void asset_names_free(asset_names_t* ptr);
asset_name_t* asset_names_get(asset_names_t* ptr, uint64_t index);
uint64_t asset_names_len(asset_names_t* ptr);
void asset_names_get(asset_names_t* ptr, asset_name_t* element);
buffer_t* asset_names_to_bytes(asset_names_t* ptr);
result_t* asset_names_from_bytes(uint8_t* data, uint32_t size);
result_t* asset_names_from_json(const char* str);
result_t* asset_names_to_json(asset_names_t* ptr);

#endif /* CML_ASSET_NAMES_H_ */