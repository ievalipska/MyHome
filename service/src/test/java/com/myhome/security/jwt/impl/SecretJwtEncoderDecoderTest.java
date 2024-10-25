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

package com.myhome.security.jwt.impl;

import com.myhome.security.jwt.AppJwt;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.WeakKeyException;
import java.time.LocalDateTime;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * This class tests the functionality of a SecretJwtEncoderDecoder class through unit
 * tests, covering successful and failed encoding and decoding of JSON Web Tokens (JWTs).
 */
class SecretJwtEncoderDecoderTest {
  private static final String TEST_USER_ID = "test-user-id";

  private static final String EXPIRED_JWT = "eyJhbGciOiJIUzUxMiJ9."
      + "eyJzdWIiOiJ0ZXN0LXVzZXItaWQiLCJleHAiOjE1OTYwOTg4MDF9."
      + "jnvLiLzobwW2XKz0iuNHZu3W_XO3FNDJoDySxQv_9oUsTPGPcy83_9ETMZRsUBLB9YzkZ0ZtSfP05g4RVKuFhg";

  private static final String INVALID_SECRET = "secret";
  private static final String VALID_SECRET = "secretsecretsecretsecretsecretsecretsecretsecret"
      + "secretsecretsecretsecretsecretsecretsecretsecret"
      + "secretsecretsecretsecretsecretsecretsecretsecret"
      + "secretsecretsecretsecretsecretsecretsecretsecret"
      + "secretsecretsecretsecretsecretsecretsecretsecret";

  /**
   * Encodes an AppJwt object using a SecretJwtEncoderDecoder instance with a valid
   * secret, verifying that a non-null encoded token is returned.
   * The AppJwt object is built with a user ID and an expiration time set to the current
   * date and time.
   */
  @Test
  void jwtEncodeSuccess() {
    // given
    SecretJwtEncoderDecoder jwtEncoderDecoder = new SecretJwtEncoderDecoder();

    // when
    AppJwt appJwt = AppJwt.builder().expiration(LocalDateTime.now()).userId(TEST_USER_ID).build();

    // then
    Assertions.assertNotNull(jwtEncoderDecoder.encode(appJwt, VALID_SECRET));
  }

  /**
   * Tests the behavior of a SecretJwtEncoderDecoder when encoding a JWT with an invalid
   * secret key. It uses an assertion to verify that a WeakKeyException is thrown when
   * the encode method is called with the invalid secret key. The test setup includes
   * a SecretJwtEncoderDecoder instance and an AppJwt object created with a valid user
   * ID.
   */
  @Test
  void jwtEncodeFailWithException() {
    // given
    SecretJwtEncoderDecoder jwtEncoderDecoder = new SecretJwtEncoderDecoder();
    AppJwt appJwt = AppJwt.builder().expiration(LocalDateTime.now()).userId(TEST_USER_ID).build();

    // when and then
    Assertions.assertThrows(WeakKeyException.class,
        () -> jwtEncoderDecoder.encode(appJwt, INVALID_SECRET));
  }

  /**
   * Tests a successful JWT decoding process. It creates a JWT, decodes it with a secret
   * key, and verifies that the decoded object contains the expected user ID and
   * expiration time.
   */
  @Test
  void jwtDecodeSuccess() {
    // given
    SecretJwtEncoderDecoder jwtEncoderDecoder = new SecretJwtEncoderDecoder();
    AppJwt appJwt =
        AppJwt.builder().userId(TEST_USER_ID).expiration(LocalDateTime.now().plusHours(1)).build();
    String encodedJwt = jwtEncoderDecoder.encode(appJwt, VALID_SECRET);

    // when
    AppJwt decodedJwt = jwtEncoderDecoder.decode(encodedJwt, VALID_SECRET);

    // then
    Assertions.assertNotNull(decodedJwt);
    Assertions.assertEquals(decodedJwt.getUserId(), TEST_USER_ID);
    Assertions.assertNotNull(decodedJwt.getExpiration());
  }

  /**
   * Verifies that a JWT decoder throws an `ExpiredJwtException` when attempting to
   * decode an expired JWT token with a valid secret key.
   */
  @Test
  void jwtDecodeFailWithExpiredJwt() {
    // given
    SecretJwtEncoderDecoder jwtEncoderDecoder = new SecretJwtEncoderDecoder();

    // when and then
    Assertions.assertThrows(ExpiredJwtException.class,
        () -> jwtEncoderDecoder.decode(EXPIRED_JWT, VALID_SECRET));
  }
}