/*
 * Copyright 2019 NXP
 */

/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON  ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS  SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 *
 * @file ECCcrypto.h
 *
 * @brief Header file for tests for ECC cryptography (requirements R3.*)
 *
 */

#ifndef ECC_CRYPTO_H
#define ECC_CRYPTO_H

#include <stdint.h>

#define ECC_CRYPTO_TESTS \
	VTEST_DEFINE_TEST(30101, &ecc_test_signature_verification,            \
		"Test signature verification")                                \
	VTEST_DEFINE_TEST(30102, &ecc_test_signature_verification_negative,   \
		"Test signature verification failure")                        \
	VTEST_DEFINE_TEST(30103, &ecc_test_signature_verification_message,    \
		"Test signature verification of a message")                   \
	VTEST_DEFINE_TEST(30104, &ecc_test_signature_verification_key,        \
		"Test signature verification with key storage")               \
	VTEST_DEFINE_TEST(30105, &ecc_test_signature_verification_key_of_msg, \
		"Test signature verification of a message with key storage")  \
	VTEST_DEFINE_TEST(30106, &ecc_test_pubkey_decompression,              \
		"Test public key decompression")                              \
	VTEST_DEFINE_TEST(30107, &ecc_test_pubkey_decompression_negative,     \
		"Test public key decompression failure")                      \

void ecc_test_signature_verification(void);
void ecc_test_signature_verification_negative(void);
void ecc_test_signature_verification_message(void);
void ecc_test_signature_verification_key(void);
void ecc_test_signature_verification_key_of_msg(void);
void ecc_test_pubkey_decompression(void);
void ecc_test_pubkey_decompression_negative(void);

#endif /* ECC_CRYPTO_H */

