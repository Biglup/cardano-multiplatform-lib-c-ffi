/**
 * @file language.h
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

#ifndef CML_LANGUAGE_H_
#define CML_LANGUAGE_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <cml/buffer.h>
#include <cml/result.h>
#include <cml/language_kind.h>

/* DEFINITIONS **************************************************************/

typedef struct _language_ language_t;

/* PROTOTYPES ***************************************************************/

void language_free(language_t* ptr);
buffer_t* language_to_bytes(language_t* ptr);
result_t* language_from_bytes(uint8_t* data, uint32_t size);
language_t* language_new_plutus_v1();
language_t* language_new_plutus_v2();
LanguageKind language_kind(language_t* ptr);


#endif /* CML_LANGUAGE_H_ */