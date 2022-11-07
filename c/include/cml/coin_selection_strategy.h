/**
 * @file big_num.h
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

#ifndef CML_COINSELECTIONSTRATEGY_H_
#define CML_COINSELECTIONSTRATEGY_H_

/* DECLARATIONS **************************************************************/

/**
 * Similarly to how a physical wallet holds value in the form of unspent coins and banknotes, a Cardano wallet holds
 * value in the form of unspent transaction outputs. An unspent transaction output is the result of a previous transaction
 * that transferred money to the wallet, where the value has not yet been spent by another transaction. Each unspent
 * transaction output has an associated coin value, and the total value of a wallet is the sum of these coin values.
 * Collectively, the set of unspent transaction outputs is known as the UTxO set.
 * 
 * When using a Cardano wallet to make a payment, the wallet software must select a combination of unspent outputs from
 * the wallet's UTxO set, so that the total value of selected outputs is enough to cover the target amount.
 * 
 * Just as with physical coins and notes, unspent outputs from the UTxO set cannot be subdivided, and must either be spent
 * completely in a given transaction, or not be spent at all. Similarly to a transaction with physical money, the wallet
 * software must select a combination of unspent outputs whose total value is greater than the target amount, and then
 * arrange that change is paid back to the wallet.
 * 
 * Coin selection refers to the process of selecting a combination of unspent outputs from a wallet's UTxO set in order
 * to make one or more payments, and computing the set of change to be paid back to the wallet.
 */
enum CoinSelectionStrategy
{
    /**
     * The Largest-First coin selection algorithm considers UTxO set entries in descending order of value, from
     * argest to smallest.
     * 
     * When applied to a set of requested outputs, the algorithm repeatedly selects entries from the initial
     * UTxO set until the total value of selected entries is greater than or equal to the total value of requested outputs.
     * 
     * The name of the algorithm is taken from the idea that the largest UTxO entry is always selected first.
     */
    COIN_SELECTION_STRATEGY_LARGEST_FIRST = 0,

    /**
     * The Random-Improve coin selection algorithm works in two phases:
     * 
     * In the first phase, the algorithm iterates through each of the requested outputs in descending order of coin value, from
     * largest to smallest. For each output, the algorithm repeatedly selects entries at random from the initial UTxO set,
     * until each requested output has been associated with a set of UTxO entries whose total value is enough to pay for that ouput.
     * 
     * In the second phase, the algorithm attempts to expand each existing UTxO selection with additional values taken at random
     * from the initial UTxO set, to the point where the total value of each selection is as close as possible to twice the value
     * of its associated output.
     * 
     * After the above phases are complete, for each output of value voutput and accompanying UTxO selection of value vselection,
     * the algorithm generates a single change output of value vchange, where:
     * 
     *      vchange = vselection − voutput
     * 
     * Since the goal of the second phase was to expand each selection to the point where its total value is approximately twice the
     * value of its associated output, this corresponds to a change output whose target value is approximately equal to the value of
     * the output itself:
     * 
     *      vchange = vselection − voutput
     *      vchange ≈ 2voutput − voutput
     *      vchange ≈ voutput
     */
    COIN_SELECTION_STRATEGY_RANDOM_IMPROVE = 1,

    /**
     * Same as LargestFirst, but before adding ADA, will insert by largest-first for each asset type.
     */
    COIN_SELECTION_STRATEGY_LARGEST_FIRST_MULTIASSET = 2,

    /**
     * Same as RandomImprove, but before adding ADA, will insert by random-improve for each asset type.
     */
    COIN_SELECTION_STRATEGY_RANDOM_IMPROVE_MULTIASSET = 3
};

#endif /* CML_COINSELECTIONSTRATEGY_H_ */
