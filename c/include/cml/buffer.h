/**
 * @file buffer.h
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

#ifndef CML_BUFFER_H_
#define CML_BUFFER_H_

/* INCLUDES ******************************************************************/

#include <cstdint>

/* DEFINITIONS **************************************************************/

typedef struct buffer buffer_t;

/* PROTOTYPES ***************************************************************/

void buffer_free(buffer_t* ptr);
uint32_t buffer_get_len(buffer_t* ptr);
uint8_t* buffer_get_data(buffer_t* ptr);

#endif /* CML_BUFFER_H_ */