/*
 * Copyright 2020 Prathab Murugan
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

package com.myhome.controllers.response;

import com.myhome.model.CreateUserRequest;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Represents a response model for creating a user request, encapsulating essential
 * details such as user ID, name, and email.
 * 
 * - userId (String): represents an identifier for a user in the CreateUserResponse
 * model.
 * 
 * - name (String): represents a string value for the user's name in the CreateUserResponse
 * model.
 * 
 * - email (String): represents an e-mail address.
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class CreateUserResponse {
  private String userId;
  private String name;
  private String email;
}
