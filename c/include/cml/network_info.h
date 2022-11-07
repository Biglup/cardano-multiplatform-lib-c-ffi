/**
 * @file network_info.h
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

#ifndef CML_NETWORK_INFO_H_
#define CML_NETWORK_INFO_H_

/* INCLUDES ******************************************************************/

#include <cstdint>

/* DEFINITIONS **************************************************************/

typedef struct network_info network_info_t;

/* PROTOTYPES ***************************************************************/

network_info* network_info_new(uint8_t network_id, uint32_t protocol_magic);
void network_info_free(network_info* ptr);
uint8_t network_info_network_id(network_info* ptr);
uint32_t network_info_protocol_magic(network_info* ptr);

#endif /* CML_NETWORK_INFO_H_ */