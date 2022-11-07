/**
 * @file encrypt.h
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

#ifndef CML_ENCRYPT_H_
#define CML_ENCRYPT_H_

/* DECLARATIONS **************************************************************/

/**
 * Encrypts the given data.
 * 
 * @param password The password to be use for the encryption as a HEX string.
 * @param salt The salt to be use for the encryption as a HEX string.
 * @param nonce The nonce to be use for the encryption as a HEX string.
 * @param data The data to be encrypted a HEX string.
 * 
 * @returns The encyrpted data as a HEX string. 
 */
const char* encrypt_with_password(const char* password, const char* salt, const char* nonce, const char* data);

/**
 * Decrypts the given data.
 * 
 * @param password The password to be use for the encryption as a HEX string.
 * @param data The data to be decrpted as a HEX string.
 * 
 * @returns The decrypted data as a HEX string. 
 */
const char* decrypt_with_password(const char* password, const char* data);

#endif /* CML_ENCRYPT_H_ */