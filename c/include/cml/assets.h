/**
 * @file assets.h
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

#ifndef CML_ASSETS_H_
#define CML_ASSETS_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <cml/asset_name.h>
#include <cml/asset_names.h>
#include <cml/result.h>
#include <cml/big_num.h>
#include <cml/buffer.h>
#include <cml/option.h>

/* DEFINITIONS **************************************************************/

typedef struct _assets_ assets_t;

/* PROTOTYPES ***************************************************************/

assets_t* assets_new();
void assets_free(assets_t* ptr);
uint64_t assets_len(assets_t* ptr);
option_t* assets_get(assets_t* ptr, asset_name_t* key);
option_t* assets_insert(assets_t* ptr, asset_name_t* key, big_num_t* value);
asset_names_t* assets_keys(assets_t* ptr);
buffer_t* assets_to_bytes(assets_t* ptr);
result_t* assets_from_bytes(uint8_t* data, uint32_t size);
result_t* assets_from_json(const char* str);
result_t* assets_to_json(assets_t* ptr);

#endif /* CML_ASSETS_H_ */