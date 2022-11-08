/**
 * @file option.h
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

#ifndef CML_INT_H_
#define CML_INT_H_

/* INCLUDES ******************************************************************/

#include <stdbool.h>
#include <cml/big_num.h>
#include <cml/option.h>
#include <cml/result.h>
#include <cml/buffer.h>

/* DEFINITIONS **************************************************************/

typedef struct _int_ int_t;

/* PROTOTYPES ***************************************************************/

int_t* int_new(big_num_t* bignum);
int_t* int_new_negative(big_num_t* bignum);
int_t* int_new_i32(int32_t x);
void int_free(int_t* x);
option_t* int_as_positive(int_t* x);
option_t* int_as_negative(int_t* x);
bool int_is_positive(int_t* x);
option_t* int_as_i32_or_nothing(int_t* x);
result_t* int_as_i32_or_fail(int_t* x);
buffer_t* int_to_bytes(int_t* x);
result_t* int_from_bytes(uint8_t* data, uint32_t size);
result_t* int_from_string(const char* str);
const char* int_to_string(int_t* ptr);

#endif /* CML_INT_H_ */