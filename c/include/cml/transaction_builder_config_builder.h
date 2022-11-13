/**
 * @file transaction_builder_config_builder.h
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

#ifndef CML_TRANSACTION_BUILDER_CONFIG_BUILDER_H_
#define CML_TRANSACTION_BUILDER_CONFIG_BUILDER_H_

/* INCLUDES ******************************************************************/

#include <cstdint>
#include <stdbool.h>
#include <cml/big_num.h>
#include <cml/result.h>
#include <cml/linear_fee.h>
#include <cml/ex_unit_prices.h>
#include <cml/costmdls.h>

/* DEFINITIONS **************************************************************/

typedef struct _transaction_builder_config_builder_ transaction_builder_config_builder_t;

/* PROTOTYPES ***************************************************************/

void transaction_builder_config_builder_free(transaction_builder_config_builder_t* ptr);
transaction_builder_config_builder_t* transaction_builder_config_builder_new();
transaction_builder_config_builder_t* transaction_builder_config_builder_fee_algo(transaction_builder_config_builder_t* ptr, linear_fee_t* linear_fee);
transaction_builder_config_builder_t* transaction_builder_config_builder_coins_per_utxo_byte(transaction_builder_config_builder_t* ptr, big_num_t* coins_per_utxo_byte);
transaction_builder_config_builder_t* transaction_builder_config_builder_pool_deposit(transaction_builder_config_builder_t* ptr, big_num_t* pool_deposit);
transaction_builder_config_builder_t* transaction_builder_config_builder_key_deposit(transaction_builder_config_builder_t* ptr, big_num_t* key_deposit);
transaction_builder_config_builder_t* transaction_builder_config_builder_max_value_size(transaction_builder_config_builder_t* ptr, uint32_t max_value_size);
transaction_builder_config_builder_t* transaction_builder_config_builder_max_tx_size(transaction_builder_config_builder_t* ptr, uint32_t max_tx_size);
transaction_builder_config_builder_t* transaction_builder_config_builder_prefer_pure_change(transaction_builder_config_builder_t* ptr, bool prefer_pure_change);
transaction_builder_config_builder_t* transaction_builder_config_builder_ex_unit_prices(transaction_builder_config_builder_t* ptr, ex_unit_prices_t* ex_unit_prices);
transaction_builder_config_builder_t* transaction_builder_config_builder_costmdls(transaction_builder_config_builder_t* ptr, costmdls_t* costmdls);
transaction_builder_config_builder_t* transaction_builder_config_builder_collateral_percentage(transaction_builder_config_builder_t* ptr, uint32_t collateral_percentage);
transaction_builder_config_builder_t* transaction_builder_config_builder_max_collateral_inputs(transaction_builder_config_builder_t* ptr, uint32_t max_collateral_inputs);
result_t* transaction_builder_config_builder_build(transaction_builder_config_builder_t* ptr);

#endif /* CML_TRANSACTION_BUILDER_CONFIG_BUILDER_H_ */