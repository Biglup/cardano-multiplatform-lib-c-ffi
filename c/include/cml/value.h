/**
 * @file value.h
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

#ifndef CML_VALUE_H_
#define CML_VALUE_H_

/* INCLUDES ******************************************************************/

#include <cml/buffer.h>
#include <cml/result.h>
#include <cml/option.h>
#include <cml/big_num.h>
#include <cml/ordering.h>
#include <cml/multi_asset.h>

#include <cstdint>
#include <stdbool.h>

/* DEFINITIONS **************************************************************/

typedef struct _value_ value_t;

/* PROTOTYPES ***************************************************************/

void value_free(value_t* ptr);
value_t* value_new(big_num_t* ptr);
value_t* value_from_multi_asset(multi_asset_t* ptr);
value_t* value_zero();
bool value_is_zero(value_t* ptr);
big_num_t* value_coin(value_t* ptr);
void value_set_coin(value_t* ptr, big_num_t* coin);
option_t* value_multi_asset(value_t* ptr);
void value_set_multi_asset(value_t* ptr, multi_asset_t* assets);
buffer_t* value_to_bytes(value_t* ptr);
result_t* value_from_bytes(uint8_t* data, uint32_t size);
result_t* value_from_json(const char* str);
const char* value_from_json(value_t* ptr);
result_t* value_checked_add(value_t* ptr, value_t* other);
result_t* value_checked_mul(value_t* ptr, value_t* other);
result_t* value_checked_sub(value_t* ptr, value_t* other);
value_t* value_clamped_sub(value_t* ptr, value_t* other);
Ordering value_compare(value_t* lhs, value_t* rhs);

#endif /* CML_VALUE_H_ */
