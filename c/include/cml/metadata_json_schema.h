/**
 * @file metadata_json_schema.h
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

#ifndef CML_METADATAJSONSCHEMA_H_
#define CML_METADATAJSONSCHEMA_H_

/* DECLARATIONS **************************************************************/

enum MetadataJsonSchema {
    METADATA_JSON_SCHEMA_NO_CONVERSIONS = 0,
    METADATA_JSON_SCHEMA_BASIC_CONVERSIONS = 1,
    METADATA_JSON_SCHEMA_DETAILED_SCHEMA = 2
};

#endif /* CML_METADATAJSONSCHEMA_H_ */