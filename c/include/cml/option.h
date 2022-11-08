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

#ifndef CML_OPTION_H_
#define CML_OPTION_H_

/* INCLUDES ******************************************************************/

#include <stdbool.h>

/* DEFINITIONS **************************************************************/

typedef struct option option_t;

/* PROTOTYPES ***************************************************************/

void option_free(option_t* ptr);
void* option_get_some(option_t* ptr);
bool option_get_is_none(option_t* ptr);

#endif /* CML_OPTION_H_ */