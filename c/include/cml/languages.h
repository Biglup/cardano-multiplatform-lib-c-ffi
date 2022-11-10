/**
 * @file languages.h
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

#ifndef CML_LANGUAGES_H_
#define CML_LANGUAGES_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <cml/asset_name.h>
#include <cml/result.h>
#include <cml/buffer.h>

/* DEFINITIONS **************************************************************/

typedef struct _languages_ languages_t;

/* PROTOTYPES ***************************************************************/

void languages_free(languages_t* ptr);
asset_name_t* languages_get(languages_t* ptr, uint64_t index);
uint64_t languages_len(languages_t* ptr);
void languages_add(languages_t* ptr, asset_name_t* element);

#endif /* CML_languages_H_ */