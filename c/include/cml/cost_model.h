/**
 * @file cost_model.h
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

#ifndef CML_COST_MODEL_H_
#define CML_COST_MODEL_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <stdbool.h>
#include <cml/result.h>
#include <cml/buffer.h>
#include <cml/language.h>
#include <cml/int.h>

/* DEFINITIONS **************************************************************/

typedef struct _cost_model_ cost_model_t;

/* PROTOTYPES ***************************************************************/

void cost_model_free(cost_model_t* ptr);
result_t* cost_model_set(cost_model_t* ptr, uint32_t operation, int_t* cost);
result_t* cost_model_get(cost_model_t* ptr, uint32_t operation);
language_t* cost_model_language(cost_model_t* ptr);
cost_model_t* cost_model_empty_model(language_t* language);
buffer_t* cost_model_to_bytes(cost_model_t* ptr);
result_t* cost_model_from_bytes(uint8_t* data, uint32_t size);
result_t* cost_model_from_json(const char* str);
result_t* cost_model_to_json(cost_model_t* ptr);

#endif /* CML_COST_MODEL_H_ */