/**
 * @file unit_interval.h
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

#ifndef CML_UNIT_INTERVAL_H_
#define CML_UNIT_INTERVAL_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <stdbool.h>
#include <cml/big_num.h>
#include <cml/option.h>
#include <cml/result.h>
#include <cml/buffer.h>

/* DEFINITIONS **************************************************************/

typedef struct _unit_interval_ unit_interval_t;

/* PROTOTYPES ***************************************************************/

unit_interval_t* unit_interval_new(big_num_t* numerator, big_num_t* denominator);
void unit_interval_free(unit_interval_t* ptr);
big_num_t* unit_interval_numerator(unit_interval_t* ptr);
big_num_t* unit_interval_denominator(unit_interval_t* ptr);
buffer_t* unit_interval_to_bytes(unit_interval_t* ptr);
result_t* unit_interval_from_bytes(uint8_t* data, uint32_t size);
result_t* unit_interval_from_json(const char* str);
result_t* unit_interval_to_json(unit_interval_t* ptr);

#endif /* CML_UNIT_INTERVAL_H_ */