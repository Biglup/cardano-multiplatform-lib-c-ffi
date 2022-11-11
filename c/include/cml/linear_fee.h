/**
 * @file linear_fee.h
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

#ifndef CML_LINEAR_FEE_H_
#define CML_LINEAR_FEE_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <stdbool.h>
#include <cml/big_num.h>
#include <cml/option.h>
#include <cml/result.h>
#include <cml/buffer.h>

/* DEFINITIONS **************************************************************/

typedef struct _linear_fee_ linear_fee_t;

/* PROTOTYPES ***************************************************************/

linear_fee_t* linear_fee_new(big_num_t* coefficient, big_num_t* constant);
void linear_fee_free(linear_fee_t* ptr);
big_num_t* linear_fee_coefficient(linear_fee_t* ptr);
big_num_t* linear_fee_constant(linear_fee_t* ptr);

#endif /* CML_LINEAR_FEE_H_ */