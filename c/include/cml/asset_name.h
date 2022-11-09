/**
 * @file asset_name.h
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

#ifndef CML_ASSET_NAME_H_
#define CML_ASSET_NAME_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <stdbool.h>
#include <cml/result.h>
#include <cml/buffer.h>

/* DEFINITIONS **************************************************************/

typedef struct _asset_name_ asset_name_t;

/* PROTOTYPES ***************************************************************/

result_t* asset_name_new(uint8_t* data, uint32_t size);
void asset_name_free(asset_name_t* ptr);
buffer_t* asset_name_name(asset_name_t* ptr);
buffer_t* asset_name_to_bytes(asset_name_t* ptr);
result_t* asset_name_from_bytes(uint8_t* data, uint32_t size);
result_t* asset_name_from_json(const char* str);
result_t* asset_name_to_json(asset_name_t* ptr);

#endif /* CML_ASSET_NAME_H_ */