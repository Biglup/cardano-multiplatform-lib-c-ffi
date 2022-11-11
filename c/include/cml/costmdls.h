/**
 * @file costmdls.h
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

#ifndef CML_COSTMDLS_H_
#define CML_COSTMDLS_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <cml/language.h>
#include <cml/languages.h>
#include <cml/cost_model.h>
#include <cml/result.h>
#include <cml/big_num.h>
#include <cml/buffer.h>
#include <cml/option.h>

/* DEFINITIONS **************************************************************/

typedef struct _costmdls_ costmdls_t;

/* PROTOTYPES ***************************************************************/

costmdls_t* costmdls_new();
void costmdls_free(costmdls_t* ptr);
uint64_t costmdls_len(costmdls_t* ptr);
option_t* costmdls_get(costmdls_t* ptr, language_t* key);
option_t* costmdls_insert(costmdls_t* ptr, cost_model_t* value);
languages_t* costmdls_keys(costmdls_t* ptr);
buffer_t* costmdls_to_bytes(costmdls_t* ptr);
result_t* costmdls_from_bytes(uint8_t* data, uint32_t size);
result_t* costmdls_from_json(const char* str);
result_t* costmdls_to_json(costmdls_t* ptr);

#endif /* CML_COSTMDLS_H_ */