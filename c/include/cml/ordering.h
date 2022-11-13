/**
 * @file ordering.h
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

#ifndef CML_ORDERING_H_
#define CML_ORDERING_H_

/* DECLARATIONS **************************************************************/

enum Ordering
{
    ORDERING_EQUAL = 0,
    ORDERING_LESS = -1,
    ORDERING_GREATER = 1
};

#endif /* CML_ORDERING_H_ */