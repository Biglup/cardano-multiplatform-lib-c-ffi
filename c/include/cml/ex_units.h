/**
 * @file ex_units.h
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

#ifndef CML_ex_units_H_
#define CML_ex_units_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <stdbool.h>
#include <cml/big_num.h>
#include <cml/option.h>
#include <cml/result.h>
#include <cml/buffer.h>
#include <cml/unit_interval.h>

/* DEFINITIONS **************************************************************/

typedef struct _ex_units_ ex_units_t;

/* PROTOTYPES ***************************************************************/

ex_units_t* ex_units_new(big_num_t* mem, big_num_t* step);
ex_units_t* ex_units_dummy();
void ex_units_free(ex_units_t* ptr);
big_num_t* ex_units_mem(ex_units_t* ptr);
big_num_t* ex_units_step(ex_units_t* ptr);
result_t* ex_units_checked_add(ex_units_t* ptr, ex_units_t* other);
buffer_t* ex_units_to_bytes(ex_units_t* ptr);
result_t* ex_units_from_bytes(uint8_t* data, uint32_t size);
result_t* ex_units_from_json(const char* str);
result_t* ex_units_to_json(ex_units_t* ptr);

#endif /* CML_ex_units_H_ */