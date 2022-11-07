/**
 * @file big_num.h
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

#ifndef CML_BIGNUM_H_
#define CML_BIGNUM_H_

/* INCLUDES ******************************************************************/

#include <cml/buffer.h>
#include <cml/result.h>

#include <cstdint>
#include <stdbool.h>

/* DEFINITIONS **************************************************************/

typedef struct big_num big_num_t;

/* PROTOTYPES ***************************************************************/

void big_num_free(big_num_t* ptr);
buffer_t* big_num_to_bytes(big_num_t* ptr);
result_t* big_num_from_bytes(uint8_t* data, uint32_t size);
result_t* big_num_from_string(const char* str);
const char* big_num_to_string(big_num_t* ptr);
big_num_t* big_num_zero();
bool big_num_is_zero(big_num_t* ptr);
result_t* big_num_checked_mul(big_num_t* ptr, big_num_t* other);
result_t* big_num_checked_add(big_num_t* ptr, big_num_t* other);
result_t* big_num_checked_sub(big_num_t* ptr, big_num_t* other);
big_num_t* big_num_clamped_sub(big_num_t* ptr, big_num_t* other);
result_t* big_num_checked_div(big_num_t* ptr, big_num_t* other);
result_t* big_num_checked_div_ceil(big_num_t* ptr, big_num_t* other);
result_t* big_num_compare(big_num_t* lhs, big_num_t* rhs);

#endif /* CML_BIGNUM_H_ */