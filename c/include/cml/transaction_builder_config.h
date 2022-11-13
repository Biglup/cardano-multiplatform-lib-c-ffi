/**
 * @file transaction_builder_config.h
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

#ifndef CML_TRANSACTION_BUILDER_CONFIG_H_
#define CML_TRANSACTION_BUILDER_CONFIG_H_

/* DEFINITIONS **************************************************************/

typedef struct _transaction_builder_config_ transaction_builder_config_t;

/* PROTOTYPES ***************************************************************/

void transaction_builder_config_free(transaction_builder_config_t* ptr);
const char* transaction_builder_config_to_string(transaction_builder_config_t* ptr);

#endif /* CML_TRANSACTION_BUILDER_CONFIG_H_ */