/**
 * @file multi_asset.h
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

#ifndef CML_MULTI_ASSET_H_
#define CML_MULTI_ASSET_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <cml/assets.h>
#include <cml/asset_name.h>
#include <cml/asset_names.h>
#include <cml/script_hash.h>
#include <cml/script_hashes.h>
#include <cml/result.h>
#include <cml/big_num.h>
#include <cml/buffer.h>
#include <cml/option.h>

/* DEFINITIONS **************************************************************/

typedef struct _multi_asset_ multi_asset_t;

/* PROTOTYPES ***************************************************************/

multi_asset_t* multi_asset_new();
void multi_asset_free(multi_asset_t* ptr);
uint64_t multi_asset_len(multi_asset_t* ptr);
option_t* multi_asset_insert(multi_asset_t* ptr, script_hash_t* policy_id, assets_t* assets);
option_t* multi_asset_get(multi_asset_t* ptr, script_hash_t* policy_id);
option_t* multi_asset_set_asset(multi_asset_t* ptr, script_hash_t* policy_id, asset_name_t* asset, big_num_t* value);
big_num_t* multi_asset_get_asset(multi_asset_t* ptr, script_hash_t* policy_id, asset_name_t* asset);
script_hashes_t* multi_asset_keys(multi_asset_t* ptr);
multi_asset_t* multi_asset_sub(multi_asset_t* ptr, multi_asset_t* rhs_ma);
buffer_t* multi_asset_to_bytes(multi_asset_t* ptr);
result_t* multi_asset_from_bytes(uint8_t* data, uint32_t size);
result_t* multi_asset_from_json(const char* str);
result_t* multi_asset_to_json(multi_asset_t* ptr);

#endif /* CML_MULTI_ASSET_H_ */
