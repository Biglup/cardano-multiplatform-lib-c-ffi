/**
 * @file plutus_data.h
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

#ifndef CML_PLUTUS_DATA_H_
#define CML_PLUTUS_DATA_H_

/* INCLUDES ******************************************************************/

#include <cml/plutus_datum_schema.h>

/* DEFINITIONS **************************************************************/

typedef struct plutus_data plutus_data_t;

/* PROTOTYPES ***************************************************************/

plutus_data_t* encode_json_str_to_plutus_datum(const char* json, PlutusDatumSchema schema);
const char* decode_plutus_datum_to_json_str(plutus_data_t* ptr, PlutusDatumSchema schema);

#endif /* CML_PLUTUS_DATA_H_ */