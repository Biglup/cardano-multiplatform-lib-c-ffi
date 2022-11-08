/**
 * @file free.h
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

#ifndef CML_FREE_H_
#define CML_FREE_H_

/* PROTOTYPES ***************************************************************/

/**
 * Frees a C string allocated in the Rust side of the FFI. 
 */
void free_c_str(const char* str);

/**
 * Frees a i32 allocated in the Rust side of the FFI. 
 */
void free_int32(const void* i32);

#endif /* CML_FREE_H_ */




