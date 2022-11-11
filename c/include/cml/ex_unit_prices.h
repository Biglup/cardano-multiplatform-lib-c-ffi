/**
 * @file ex_unit_prices.h
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

#ifndef CML_EX_UNIT_PRICES_H_
#define CML_EX_UNIT_PRICES_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <stdbool.h>
#include <cml/big_num.h>
#include <cml/option.h>
#include <cml/result.h>
#include <cml/buffer.h>
#include <cml/unit_interval.h>

/* DEFINITIONS **************************************************************/

typedef struct _ex_unit_prices_ ex_unit_prices_t;

/* PROTOTYPES ***************************************************************/

ex_unit_prices_t* ex_unit_prices_new(unit_interval_t* mem_price, unit_interval_t* step_price);
void ex_unit_prices_free(ex_unit_prices_t* ptr);
unit_interval_t* ex_unit_prices_mem_price(ex_unit_prices_t* ptr);
unit_interval_t* ex_unit_prices_step_price(ex_unit_prices_t* ptr);
buffer_t* ex_unit_prices_to_bytes(ex_unit_prices_t* ptr);
result_t* ex_unit_prices_from_bytes(uint8_t* data, uint32_t size);
result_t* ex_unit_prices_from_json(const char* str);
result_t* ex_unit_prices_to_json(ex_unit_prices_t* ptr);


#endif /* CML_EX_UNIT_PRICES_H_ */