
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
 * @file SEsignature.c
 *
 * @brief Tests for SE Signature (requirements R7.*)
 *
 */
#include <string.h>
#include <v2xSe.h>
#include "vtest.h"
#include "SEmisc.h"
#include "SEsignature.h"
#include "ecdsa.h"
#include "vtest_async.h"

static volatile int count_async = ASYNC_COUNT_RESET;

/** Data to calculate signature on for tests */
TypeHash_t testHash = {
	.data = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
	}
};

/**
 * @brief   Signature verification callback: positive test
 *
 * @param	sequence_number		sequence operation id (not used?)
 * @param	ret			returned value by the dispatcher
 * @param	verification_result	verification result
 *
 */

static void signatureVerificationCallback(void *sequence_number,
	int ret,
	ecdsa_verification_result_t verification_result)
{
	VTEST_CHECK_RESULT_ASYNC_DEC(ret, ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT(verification_result, ECDSA_VERIFICATION_SUCCESS);
}

#ifndef ECC_PATTERNS_BIG_ENDIAN
/**
 * @brief   Convert endianness for data array
 *
 * @param	src_array	source array (before conversion)
 * @param	dst_array	destination array (after conversion)
 * @param	length		length to convert
 *
 */

static void convertEndianness(uint8_t *src_array, uint8_t *dst_array,
							uint16_t length)
{
	uint16_t i;

	for (i = 0; i < length; i++)
		dst_array[i] = src_array[length - 1 - i];
}
#endif

/**
 *
 * @brief Test v2xSe_createBaSign for expected behaviour
 *
 * This function tests v2xSe_createBaSign for expected behaviour
 * The following behaviours are tested:
 *  - Valid signature can be generated for EU applet
 *  - Valid signature can be generated for US applet
 *  - Valid signature for curve V2XSE_CURVE_NISTP256 can be generated
 *  - Valid signature for curve V2XSE_CURVE_BP256R1 can be generated
 *  - Valid signature for curve V2XSE_CURVE_BP256T1 can be generated
 *  - Valid signature for curve V2XSE_CURVE_NISTP384 can be generated
 *  - Valid signature for curve V2XSE_CURVE_BP384R1 can be generated
 *  - Valid signature for curve V2XSE_CURVE_BP384T1 can be generated
 *  - Valid signature can be generated using key in slot 0
 *  - Valid signature can be generated using key in non-zero slot
 *  - Valid signature can be generated using key in max slot
 *  - signature generated with valid inputs
 *
 */
void test_createBaSign(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeSignature_t signature;
	TypeInformation_t seInfo;
	ecdsa_pubkey_t pubKey_ecdsa;
	ecdsa_sig_t sig_ecdsa;
	uint8_t ecdsa_hash[V2XSE_384_EC_HASH_SIZE];
	uint8_t ecdsa_x[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	uint8_t ecdsa_y[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	uint8_t ecdsa_r[V2XSE_384_EC_R_SIGN];
	uint8_t ecdsa_s[V2XSE_384_EC_S_SIGN];

	/* Set up pub key and signature structures for ECDSA verification */
	pubKey_ecdsa.x = ecdsa_x;
	pubKey_ecdsa.y = ecdsa_y;
	sig_ecdsa.r    = ecdsa_r;
	sig_ecdsa.s    = ecdsa_s;

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert hash data for ECSDA verification - 256 bit curves */
	convertEndianness(testHash.data, ecdsa_hash, V2XSE_256_EC_HASH_SIZE);
#else
	memcpy(ecdsa_hash, testHash.data, V2XSE_256_EC_HASH_SIZE);
#endif

/* Test Valid signature can be generated for EU applet */
/* Test Valid signature for curve V2XSE_CURVE_NISTP256 can be generated */
/* Test Valid signature can be generated using key in slot 0 */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxBaKeysAllowed <= NON_ZERO_SLOT, 0);
	/* Create BA key in slot 0 */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert public key for ECSDA verification */
	convertEndianness(pubKey.x, ecdsa_x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	convertEndianness(pubKey.y, ecdsa_y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#else
	memcpy(ecdsa_x, pubKey.x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	memcpy(ecdsa_y, pubKey.y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#endif

	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createBaSign(SLOT_ZERO,
		V2XSE_256_EC_HASH_SIZE, &testHash, &statusCode, &signature),
								V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert signature for ECDSA verification */
	convertEndianness(signature.r, ecdsa_r, V2XSE_256_EC_R_SIGN);
	convertEndianness(signature.s, ecdsa_s, V2XSE_256_EC_S_SIGN);
#else
	memcpy(ecdsa_r, signature.r, V2XSE_256_EC_R_SIGN);
	memcpy(ecdsa_s, signature.s, V2XSE_256_EC_S_SIGN);
#endif

	/* Use ECDSA to verify signature */
	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_NISTP256, pubKey_ecdsa,
			ecdsa_hash, sig_ecdsa, 0,
			signatureVerificationCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(SLOT_ZERO,
						&statusCode), V2XSE_SUCCESS);

/* Test Valid signature can be generated for US applet */
/* Test Valid signature for curve V2XSE_CURVE_NISTP256 can be generated */
/* Test Valid signature can be generated using key in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_US), VTEST_PASS);
	/* Create BA key in non-zero slot */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createBaSign(NON_ZERO_SLOT,
		V2XSE_256_EC_HASH_SIZE, &testHash, &statusCode, &signature),
								V2XSE_SUCCESS);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(NON_ZERO_SLOT,
						&statusCode), V2XSE_SUCCESS);

/* Test Valid signature for curve V2XSE_CURVE_BP256T1 can be generated */
/* Test Valid signature can be generated using key in max slot */
	/* Create BA key in max slot */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(MAX_BA_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createBaSign(MAX_BA_SLOT,
		V2XSE_256_EC_HASH_SIZE, &testHash, &statusCode, &signature),
								V2XSE_SUCCESS);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(MAX_BA_SLOT,
						&statusCode), V2XSE_SUCCESS);

/* Test Valid signature for curve V2XSE_CURVE_NISTP384 can be generated */
	/* Create BA key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP384, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createBaSign(SLOT_ZERO,
		V2XSE_384_EC_HASH_SIZE, &testHash, &statusCode, &signature),
								V2XSE_SUCCESS);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode),
								V2XSE_SUCCESS);

/* Test Valid signature for curve V2XSE_CURVE_BP384R1 can be generated */
	/* Create BA key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP384R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createBaSign(SLOT_ZERO,
		V2XSE_384_EC_HASH_SIZE, &testHash, &statusCode, &signature),
								V2XSE_SUCCESS);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode),
								V2XSE_SUCCESS);

/* Test Valid signature for curve V2XSE_CURVE_BP384T1 can be generated */
	/* Create BA key */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP384T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createBaSign(SLOT_ZERO,
		V2XSE_384_EC_HASH_SIZE, &testHash, &statusCode, &signature),
								V2XSE_SUCCESS);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode),
								V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

/* Flag CONF if signature verification not implemented yet */
	VTEST_FLAG_CONF();
}

/**
 *
 * @brief Test v2xSe_createMaSign for expected behaviour
 *
 * This function tests v2xSe_createMaSign for expected behaviour
 * The following behaviours are tested:
 *  - Valid signature can be generated for EU applet
 *  - Valid signature can be generated for US applet
 *  - Valid signature for curve V2XSE_CURVE_NISTP256 can be generated
 *  - Valid signature for curve V2XSE_CURVE_BP256R1 can be generated
 *  - Valid signature for curve V2XSE_CURVE_BP256T1 can be generated
 *  - Valid signature for curve V2XSE_CURVE_NISTP384 can be generated
 *  - Valid signature for curve V2XSE_CURVE_BP384R1 can be generated
 *  - Valid signature for curve V2XSE_CURVE_BP384T1 can be generated
 *
 */
void test_createMaSign(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeSignature_t signature;
	ecdsa_pubkey_t pubKey_ecdsa;
	ecdsa_sig_t sig_ecdsa;
	uint8_t ecdsa_hash[V2XSE_384_EC_HASH_SIZE];
	uint8_t ecdsa_x[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	uint8_t ecdsa_y[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	uint8_t ecdsa_r[V2XSE_384_EC_R_SIGN];
	uint8_t ecdsa_s[V2XSE_384_EC_S_SIGN];

	/* Set up pub key and signature structures for ECDSA verification */
	pubKey_ecdsa.x = ecdsa_x;
	pubKey_ecdsa.y = ecdsa_y;
	sig_ecdsa.r    = ecdsa_r;
	sig_ecdsa.s    = ecdsa_s;

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert hash data for ECSDA verification - 256 bit curves */
	convertEndianness(testHash.data, ecdsa_hash, V2XSE_256_EC_HASH_SIZE);
#else
	memcpy(ecdsa_hash, testHash.data, V2XSE_256_EC_HASH_SIZE);
#endif

/* Test Valid signature can be generated for EU applet */
/* Test Valid signature for curve V2XSE_CURVE_NISTP256 can be generated */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Generate MA key of known curveId */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_NISTP256,
					&statusCode, &pubKey), V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert public key for ECSDA verification */
	convertEndianness(pubKey.x, ecdsa_x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	convertEndianness(pubKey.y, ecdsa_y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#else
	memcpy(ecdsa_x, pubKey.x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	memcpy(ecdsa_y, pubKey.y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#endif

	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createMaSign(V2XSE_256_EC_HASH_SIZE,
			&testHash, &statusCode,	&signature), V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert signature for ECDSA verification */
	convertEndianness(signature.r, ecdsa_r, V2XSE_256_EC_R_SIGN);
	convertEndianness(signature.s, ecdsa_s, V2XSE_256_EC_S_SIGN);
#else
	memcpy(ecdsa_r, signature.r, V2XSE_256_EC_R_SIGN);
	memcpy(ecdsa_s, signature.s, V2XSE_256_EC_S_SIGN);
#endif

	/* Use ECDSA to verify signature */
	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_NISTP256, pubKey_ecdsa,
			ecdsa_hash, sig_ecdsa, 0,
			signatureVerificationCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);

/* Test Valid signature can be generated for US applet */
/* Test Valid signature for curve V2XSE_CURVE_BP256R1 can be generated */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(US_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_US), VTEST_PASS);
	/* Generate MA key of known curveId */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_BP256R1,
					&statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createMaSign(V2XSE_256_EC_HASH_SIZE,
			&testHash, &statusCode,	&signature), V2XSE_SUCCESS);

/* Test Valid signature for curve V2XSE_CURVE_BP256T1 can be generated */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Generate MA key of known curveId */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_BP256T1,
					&statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createMaSign(V2XSE_256_EC_HASH_SIZE,
			&testHash, &statusCode,	&signature), V2XSE_SUCCESS);

/* Test Valid signature for curve V2XSE_CURVE_NISTP384 can be generated */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Generate MA key of known curveId */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_NISTP384,
					&statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createMaSign(V2XSE_384_EC_HASH_SIZE,
			&testHash, &statusCode,	&signature), V2XSE_SUCCESS);

/* Test Valid signature for curve V2XSE_CURVE_BP384R1 can be generated */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Generate MA key of known curveId */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_BP384R1,
					&statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createMaSign(V2XSE_384_EC_HASH_SIZE,
			&testHash, &statusCode,	&signature), V2XSE_SUCCESS);

/* Test Valid signature for curve V2XSE_CURVE_BP384T1 can be generated */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Generate MA key of known curveId */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_BP384T1,
					&statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createMaSign(V2XSE_384_EC_HASH_SIZE,
			&testHash, &statusCode,	&signature), V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

/* Flag CONF if signature verification not implemented yet */
	VTEST_FLAG_CONF();
}

/**
 *
 * @brief Test v2xSe_createRtSignLowLatency for expected behaviour
 *
 * This function tests v2xSe_createRtSignLowLatency for expected behaviour
 * The following behaviours are tested:
 *  - Valid signature can be generated for EU applet
 *  - Valid signature can be generated for US applet
 *  - Valid signature for curve V2XSE_CURVE_NISTP256 can be generated
 *  - Valid signature for curve V2XSE_CURVE_BP256R1 can be generated
 *  - Valid signature for curve V2XSE_CURVE_BP256T1 can be generated
 *  - Valid signature can be generated using key in slot 0
 *  - Valid signature can be generated using key in non-zero slot
 *  - Valid signature can be generated using key in max slot
 *
 */
void test_createRtSignLowLatency(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeSignature_t signature;
	TypeLowlatencyIndicator_t fastIndicator;
	TypeInformation_t seInfo;
	ecdsa_pubkey_t pubKey_ecdsa;
	ecdsa_sig_t sig_ecdsa;
	uint8_t ecdsa_hash[V2XSE_384_EC_HASH_SIZE];
	uint8_t ecdsa_x[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	uint8_t ecdsa_y[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	uint8_t ecdsa_r[V2XSE_384_EC_R_SIGN];
	uint8_t ecdsa_s[V2XSE_384_EC_S_SIGN];

	/* Set up pub key and signature structures for ECDSA verification */
	pubKey_ecdsa.x = ecdsa_x;
	pubKey_ecdsa.y = ecdsa_y;
	sig_ecdsa.r    = ecdsa_r;
	sig_ecdsa.s    = ecdsa_s;

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert hash data for ECSDA verification - 256 bit curves */
	convertEndianness(testHash.data, ecdsa_hash, V2XSE_256_EC_HASH_SIZE);
#else
	memcpy(ecdsa_hash, testHash.data, V2XSE_256_EC_HASH_SIZE);
#endif

/* Test Valid signature can be generated for EU applet */
/* Test Valid signature for curve V2XSE_CURVE_NISTP256 can be generated */
/* Test Valid signature can be generated using key in slot 0 */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxRtKeysAllowed <= NON_ZERO_SLOT, 0);
	/* Create Rt key in slot 0 */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert public key for ECSDA verification */
	convertEndianness(pubKey.x, ecdsa_x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	convertEndianness(pubKey.y, ecdsa_y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#else
	memcpy(ecdsa_x, pubKey.x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	memcpy(ecdsa_y, pubKey.y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#endif

	/* Activate key for low latency signature */
	VTEST_CHECK_RESULT(v2xSe_activateRtKeyForSigning(SLOT_ZERO,
						&statusCode), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createRtSignLowLatency(&testHash, &statusCode,
				&signature, &fastIndicator), V2XSE_SUCCESS);
	VTEST_CHECK_RESULT(fastIndicator, 0);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert signature for ECDSA verification */
	convertEndianness(signature.r, ecdsa_r, V2XSE_256_EC_R_SIGN);
	convertEndianness(signature.s, ecdsa_s, V2XSE_256_EC_S_SIGN);
#else
	memcpy(ecdsa_r, signature.r, V2XSE_256_EC_R_SIGN);
	memcpy(ecdsa_s, signature.s, V2XSE_256_EC_S_SIGN);
#endif

	/* Use ECDSA to verify signature */
	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_NISTP256, pubKey_ecdsa,
			ecdsa_hash, sig_ecdsa, 0,
			signatureVerificationCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(SLOT_ZERO,
						&statusCode), V2XSE_SUCCESS);

/* Test Valid signature can be generated for US applet */
/* Test Valid signature for curve V2XSE_CURVE_BP256R1 can be generated */
/* Test Valid signature can be generated using key in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_US), VTEST_PASS);
	/* Create Rt key in non-zero slot */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Activate key for low latency signature */
	VTEST_CHECK_RESULT(v2xSe_activateRtKeyForSigning(NON_ZERO_SLOT,
						&statusCode), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createRtSignLowLatency(&testHash, &statusCode,
				&signature, &fastIndicator), V2XSE_SUCCESS);
	VTEST_CHECK_RESULT(fastIndicator, 0);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(NON_ZERO_SLOT,
						&statusCode), V2XSE_SUCCESS);

/* Test Valid signature for curve V2XSE_CURVE_BP256T1 can be generated */
/* Test Valid signature can be generated using key in non-zero slot */
	/* Create Rt key in max slot */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(MAX_RT_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Activate key for low latency signature */
	VTEST_CHECK_RESULT(v2xSe_activateRtKeyForSigning(MAX_RT_SLOT,
						&statusCode), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createRtSignLowLatency(&testHash, &statusCode,
				&signature, &fastIndicator), V2XSE_SUCCESS);
	VTEST_CHECK_RESULT(fastIndicator, 0);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(MAX_RT_SLOT,
						&statusCode), V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

/* Flag CONF if signature verification not implemented yet */
	VTEST_FLAG_CONF();
}

/**
 *
 * @brief Test v2xSe_createRtSign for expected behaviour
 *
 * This function tests v2xSe_createRtSign for expected behaviour
 * The following behaviours are tested:
 *  - Valid signature can be generated for EU applet
 *  - Valid signature can be generated for US applet
 *  - Valid signature for curve V2XSE_CURVE_NISTP256 can be generated
 *  - Valid signature for curve V2XSE_CURVE_BP256R1 can be generated
 *  - Valid signature for curve V2XSE_CURVE_BP256T1 can be generated
 *  - Valid signature can be generated using key in slot 0
 *  - Valid signature can be generated using key in non-zero slot
 *  - Valid signature can be generated using key in max slot
 *
 */
void test_createRtSign(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeSignature_t signature;
	TypeInformation_t seInfo;
	ecdsa_pubkey_t pubKey_ecdsa;
	ecdsa_sig_t sig_ecdsa;
	uint8_t ecdsa_hash[V2XSE_384_EC_HASH_SIZE];
	uint8_t ecdsa_x[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	uint8_t ecdsa_y[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	uint8_t ecdsa_r[V2XSE_384_EC_R_SIGN];
	uint8_t ecdsa_s[V2XSE_384_EC_S_SIGN];

	/* Set up pub key and signature structures for ECDSA verification */
	pubKey_ecdsa.x = ecdsa_x;
	pubKey_ecdsa.y = ecdsa_y;
	sig_ecdsa.r    = ecdsa_r;
	sig_ecdsa.s    = ecdsa_s;

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert hash data for ECSDA verification - 256 bit curves */
	convertEndianness(testHash.data, ecdsa_hash, V2XSE_256_EC_HASH_SIZE);
#else
	memcpy(ecdsa_hash, testHash.data, V2XSE_256_EC_HASH_SIZE);
#endif

/* Test Valid signature can be generated for EU applet */
/* Test Valid signature for curve V2XSE_CURVE_NISTP256 can be generated */
/* Test Valid signature can be generated using key in slot 0 */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxRtKeysAllowed <= NON_ZERO_SLOT, 0);
	/* Create Rt key in slot 0 */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert public key for ECSDA verification */
	convertEndianness(pubKey.x, ecdsa_x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	convertEndianness(pubKey.y, ecdsa_y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#else
	memcpy(ecdsa_x, pubKey.x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	memcpy(ecdsa_y, pubKey.y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#endif

	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createRtSign(SLOT_ZERO, &testHash,
				&statusCode, &signature), V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert signature for ECDSA verification */
	convertEndianness(signature.r, ecdsa_r, V2XSE_256_EC_R_SIGN);
	convertEndianness(signature.s, ecdsa_s, V2XSE_256_EC_S_SIGN);
#else
	memcpy(ecdsa_r, signature.r, V2XSE_256_EC_R_SIGN);
	memcpy(ecdsa_s, signature.s, V2XSE_256_EC_S_SIGN);
#endif

	/* Use ECDSA to verify signature */
	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_NISTP256, pubKey_ecdsa,
			ecdsa_hash, sig_ecdsa, 0,
			signatureVerificationCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(SLOT_ZERO,
						&statusCode), V2XSE_SUCCESS);

/* Test Valid signature can be generated for US applet */
/* Test Valid signature for curve V2XSE_CURVE_BP256R1 can be generated */
/* Test Valid signature can be generated using key in non-zero slot */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_US), VTEST_PASS);
	/* Create Rt key in non-zero slot */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createRtSign(NON_ZERO_SLOT, &testHash,
				&statusCode, &signature), V2XSE_SUCCESS);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(NON_ZERO_SLOT,
						&statusCode), V2XSE_SUCCESS);

/* Test Valid signature for curve V2XSE_CURVE_BP256T1 can be generated */
/* Test Valid signature can be generated using key in non-zero slot */
	/* Create Rt key in max slot */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(MAX_RT_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createRtSign(MAX_RT_SLOT, &testHash,
				&statusCode, &signature), V2XSE_SUCCESS);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(MAX_RT_SLOT,
						&statusCode), V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

/* Flag CONF if signature verification not implemented yet */
	VTEST_FLAG_CONF();
}

/**
 *
 * @brief Test v2xSe_createMaSign with SM2 key for expected behaviour
 *
 * This function tests v2xSe_createMaSign for expected behaviour
 * The following behaviours are tested:
 *  - Valid signature can be generated for CN applet
 *  - Valid signature for curve V2XSE_CURVE_SM2_256 can be generated
 *  - Valid signature can be generated using key in slot 0
 *  - Valid signature can be generated using key in non-zero slot
 *  - Valid signature can be generated using key in max slot
 *
 */
void test_createMaSign_sm2(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeSignature_t signature;
	ecdsa_pubkey_t pubKey_ecdsa;
	ecdsa_sig_t sig_ecdsa;
	uint8_t ecdsa_hash[V2XSE_384_EC_HASH_SIZE];
	uint8_t ecdsa_x[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	uint8_t ecdsa_y[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	uint8_t ecdsa_r[V2XSE_384_EC_R_SIGN];
	uint8_t ecdsa_s[V2XSE_384_EC_S_SIGN];

	VTEST_RETURN_CONF_IF_NO_V2X_HW();

	/* Set up pub key and signature structures for ECDSA verification */
	pubKey_ecdsa.x = ecdsa_x;
	pubKey_ecdsa.y = ecdsa_y;
	sig_ecdsa.r    = ecdsa_r;
	sig_ecdsa.s    = ecdsa_s;

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert hash data for ECSDA verification - 256 bit curves */
	convertEndianness(testHash.data, ecdsa_hash, V2XSE_256_EC_HASH_SIZE);
#else
	memcpy(ecdsa_hash, testHash.data, V2XSE_256_EC_HASH_SIZE);
#endif

/* Test Valid signature can be generated for CN applet */
/* Test Valid signature for curve V2XSE_CURVE_SM2_256 can be generated */
/* Test Valid signature can be generated using key in slot 0 */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(CN_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode, CN applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_CN), VTEST_PASS);
	/* Generate MA key */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_SM2_256,
				&statusCode, &pubKey), V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert public key for ECSDA verification */
	convertEndianness(pubKey.x, ecdsa_x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	convertEndianness(pubKey.y, ecdsa_y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#else
	memcpy(ecdsa_x, pubKey.x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	memcpy(ecdsa_y, pubKey.y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#endif

	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createMaSign(V2XSE_256_EC_HASH_SIZE,
			&testHash, &statusCode, &signature), V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert signature for ECDSA verification */
	convertEndianness(signature.r, ecdsa_r, V2XSE_256_EC_R_SIGN);
	convertEndianness(signature.s, ecdsa_s, V2XSE_256_EC_S_SIGN);
#else
	memcpy(ecdsa_r, signature.r, V2XSE_256_EC_R_SIGN);
	memcpy(ecdsa_s, signature.s, V2XSE_256_EC_S_SIGN);
#endif

	/* Use ECDSA to verify signature */
	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_SM2P256, pubKey_ecdsa,
			ecdsa_hash, sig_ecdsa, 0,
			signatureVerificationCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_createBaSign with SM2 key for expected behaviour
 *
 * This function tests v2xSe_createBaSign for expected behaviour
 * The following behaviours are tested:
 *  - Valid signature can be generated for CN applet
 *  - Valid signature for curve V2XSE_CURVE_SM2_256 can be generated
 *  - Valid signature can be generated using key in slot 0
 *  - Valid signature can be generated using key in non-zero slot
 *  - Valid signature can be generated using key in max slot
 *
 */
void test_createBaSign_sm2(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeSignature_t signature;
	TypeInformation_t seInfo;
	ecdsa_pubkey_t pubKey_ecdsa;
	ecdsa_sig_t sig_ecdsa;
	uint8_t ecdsa_hash[V2XSE_384_EC_HASH_SIZE];
	uint8_t ecdsa_x[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	uint8_t ecdsa_y[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	uint8_t ecdsa_r[V2XSE_384_EC_R_SIGN];
	uint8_t ecdsa_s[V2XSE_384_EC_S_SIGN];

	VTEST_RETURN_CONF_IF_NO_V2X_HW();

	/* Set up pub key and signature structures for ECDSA verification */
	pubKey_ecdsa.x = ecdsa_x;
	pubKey_ecdsa.y = ecdsa_y;
	sig_ecdsa.r    = ecdsa_r;
	sig_ecdsa.s    = ecdsa_s;

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert hash data for ECSDA verification - 256 bit curves */
	convertEndianness(testHash.data, ecdsa_hash, V2XSE_256_EC_HASH_SIZE);
#else
	memcpy(ecdsa_hash, testHash.data, V2XSE_256_EC_HASH_SIZE);
#endif

/* Test Valid signature can be generated for CN applet */
/* Test Valid signature for curve V2XSE_CURVE_SM2_256 can be generated */
/* Test Valid signature can be generated using key in slot 0 */
	/* Move to ACTIVATED state, normal operating mode, CN applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_CN), VTEST_PASS);
	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxBaKeysAllowed <= NON_ZERO_SLOT, 0);
	/* Create Ba key in slot 0 */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_SM2_256, &statusCode, &pubKey), V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert public key for ECSDA verification */
	convertEndianness(pubKey.x, ecdsa_x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	convertEndianness(pubKey.y, ecdsa_y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#else
	memcpy(ecdsa_x, pubKey.x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	memcpy(ecdsa_y, pubKey.y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#endif

	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createBaSign(SLOT_ZERO, V2XSE_256_EC_HASH_SIZE,
				&testHash, &statusCode, &signature),
			V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert signature for ECDSA verification */
	convertEndianness(signature.r, ecdsa_r, V2XSE_256_EC_R_SIGN);
	convertEndianness(signature.s, ecdsa_s, V2XSE_256_EC_S_SIGN);
#else
	memcpy(ecdsa_r, signature.r, V2XSE_256_EC_R_SIGN);
	memcpy(ecdsa_s, signature.s, V2XSE_256_EC_S_SIGN);
#endif

	/* Use ECDSA to verify signature */
	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_SM2P256, pubKey_ecdsa,
			ecdsa_hash, sig_ecdsa, 0,
			signatureVerificationCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(SLOT_ZERO,
						&statusCode), V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}


/**
 *
 * @brief Test v2xSe_createRtSign with SM2 key for expected behaviour
 *
 * This function tests v2xSe_createRtSign for expected behaviour
 * The following behaviours are tested:
 *  - Valid signature can be generated for CN applet
 *  - Valid signature for curve V2XSE_CURVE_SM2_256 can be generated
 *  - Valid signature can be generated using key in slot 0
 *  - Valid signature can be generated using key in non-zero slot
 *  - Valid signature can be generated using key in max slot
 *
 */
void test_createRtSign_sm2(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeSignature_t signature;
	TypeInformation_t seInfo;
	ecdsa_pubkey_t pubKey_ecdsa;
	ecdsa_sig_t sig_ecdsa;
	uint8_t ecdsa_hash[V2XSE_384_EC_HASH_SIZE];
	uint8_t ecdsa_x[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	uint8_t ecdsa_y[V2XSE_384_EC_PUB_KEY_XY_SIZE];
	uint8_t ecdsa_r[V2XSE_384_EC_R_SIGN];
	uint8_t ecdsa_s[V2XSE_384_EC_S_SIGN];

	VTEST_RETURN_CONF_IF_NO_V2X_HW();

	/* Set up pub key and signature structures for ECDSA verification */
	pubKey_ecdsa.x = ecdsa_x;
	pubKey_ecdsa.y = ecdsa_y;
	sig_ecdsa.r    = ecdsa_r;
	sig_ecdsa.s    = ecdsa_s;

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert hash data for ECSDA verification - 256 bit curves */
	convertEndianness(testHash.data, ecdsa_hash, V2XSE_256_EC_HASH_SIZE);
#else
	memcpy(ecdsa_hash, testHash.data, V2XSE_256_EC_HASH_SIZE);
#endif

/* Test Valid signature can be generated for CN applet */
/* Test Valid signature for curve V2XSE_CURVE_SM2_256 can be generated */
/* Test Valid signature can be generated using key in slot 0 */
	/* Move to ACTIVATED state, normal operating mode, CN applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_CN), VTEST_PASS);
	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxRtKeysAllowed <= NON_ZERO_SLOT, 0);
	/* Create Rt key in slot 0 */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_SM2_256, &statusCode, &pubKey), V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert public key for ECSDA verification */
	convertEndianness(pubKey.x, ecdsa_x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	convertEndianness(pubKey.y, ecdsa_y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#else
	memcpy(ecdsa_x, pubKey.x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	memcpy(ecdsa_y, pubKey.y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#endif

	/* Create signature */
	VTEST_CHECK_RESULT(v2xSe_createRtSign(SLOT_ZERO, &testHash,
				&statusCode, &signature), V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert signature for ECDSA verification */
	convertEndianness(signature.r, ecdsa_r, V2XSE_256_EC_R_SIGN);
	convertEndianness(signature.s, ecdsa_s, V2XSE_256_EC_S_SIGN);
#else
	memcpy(ecdsa_r, signature.r, V2XSE_256_EC_R_SIGN);
	memcpy(ecdsa_s, signature.s, V2XSE_256_EC_S_SIGN);
#endif

	/* Use ECDSA to verify signature */
	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_SM2P256, pubKey_ecdsa,
			ecdsa_hash, sig_ecdsa, 0,
			signatureVerificationCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(SLOT_ZERO,
						&statusCode), V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}
