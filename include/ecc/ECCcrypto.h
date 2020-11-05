/*
 * Copyright 2019-2020 NXP
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

/**
 * List of tests from to be run from ECCcrypto.c
 * Tests should be listed in order of incrementing test number
 */
#define ECC_CRYPTO_TESTS \
	VTEST_DEFINE_TEST(30101, &ecc_test_signature_verification,            \
		"Test signature verification")                                \
	VTEST_DEFINE_TEST(30102, &ecc_test_signature_verification_negative,   \
		"Test signature verification failure")                        \
	VTEST_DEFINE_TEST(30103, &ecc_test_signature_verification_invalid,    \
		"Test signature verification with invalid params/state")      \
	VTEST_DEFINE_TEST(30104, &ecc_test_sm2_signature_verification,        \
		"Test SM2 signature verification")                            \
	VTEST_DEFINE_TEST(30105, &ecc_test_sm2_signature_verification_negative,\
		"Test SM2 signature verification failure")                    \
	VTEST_DEFINE_TEST(30301, &ecc_test_signature_verification_message,    \
		"Test signature verification of a message")                   \
	VTEST_DEFINE_TEST(30302, &ecc_test_sm2_signature_verification_message,\
		"Test SM2 signature verification of a message")               \
	VTEST_DEFINE_TEST(30501, &ecc_test_pubkey_decompression,              \
		"Test public key decompression")                              \
	VTEST_DEFINE_TEST(30502, &ecc_test_pubkey_decompression_negative,     \
		"Test public key decompression failure")                      \
	VTEST_DEFINE_TEST(30503, &ecc_test_pubkey_decompression_invalid,      \
		"Test public key decompression with invalid params/state")    \
	VTEST_DEFINE_TEST(30504, &ecc_test_pubkey_decompression_sm2,          \
		"Test public key decompression with SM2 key")                 \
	VTEST_DEFINE_TEST(30505, &ecc_test_pubkey_decompression_sm2_negative, \
		"Test public key decompression failure with SM2 key")         \
	VTEST_DEFINE_TEST(30601, &ecc_test_pubkey_reconstruction,             \
		"Test public key reconstruction")                             \
	VTEST_DEFINE_TEST(30602, &ecc_test_pubkey_reconstruction_negative,    \
		"Test public key reconstruction failure")                     \
	VTEST_DEFINE_TEST(30603, &ecc_test_pubkey_reconstruction_invalid,     \
		"Test public key reconstruction with invalid params/state")   \
	VTEST_DEFINE_TEST(30701, &ecc_test_ecdsa_decompress_and_verify_signature, \
		"Test signature verification with compressed key")            \
	VTEST_DEFINE_TEST(30801, &ecc_test_ecdsa_decompress_and_verify_signature_of_message, \
		"Test signature verification of a message with compressed key") \
	VTEST_DEFINE_TEST(40101, &ecc_test_hash,                              \
		"Test hash functions")                                        \
	VTEST_DEFINE_TEST(40102, &ecc_test_hash_negative,                     \
		"Test hash functions failure")                                \
	VTEST_DEFINE_TEST(40103, &ecc_test_hash_invalid,                      \
		"Test hash functions when invalid state")                     \
	VTEST_DEFINE_TEST(40401, &ecc_test_sm3,                               \
		"Test SM3 hash functions")                                    \
	VTEST_DEFINE_TEST(40402, &ecc_test_sm3_negative,                      \
		"Test SM3 hash functions failure")                            \
	VTEST_DEFINE_TEST(40403, &ecc_test_sm3_invalid,                       \
		"Test SM3 hash functions when invalid state")                 \

void ecc_test_signature_verification(void);
void ecc_test_signature_verification_negative(void);
void ecc_test_signature_verification_message(void);
void ecc_test_signature_verification_invalid(void);
void ecc_test_sm2_signature_verification(void);
void ecc_test_sm2_signature_verification_negative(void);
void ecc_test_sm2_signature_verification_message(void);
void ecc_test_pubkey_decompression(void);
void ecc_test_pubkey_decompression_sm2(void);
void ecc_test_pubkey_decompression_negative(void);
void ecc_test_pubkey_decompression_sm2_negative(void);
void ecc_test_pubkey_decompression_invalid(void);
void ecc_test_pubkey_reconstruction(void);
void ecc_test_pubkey_reconstruction_negative(void);
void ecc_test_pubkey_reconstruction_invalid(void);
void ecc_test_ecdsa_decompress_and_verify_signature(void);
void ecc_test_ecdsa_decompress_and_verify_signature_of_message(void);
void ecc_test_hash(void);
void ecc_test_hash_negative(void);
void ecc_test_hash_invalid(void);
void ecc_test_sm3(void);
void ecc_test_sm3_negative(void);
void ecc_test_sm3_invalid(void);

#endif /* ECC_CRYPTO_H */
