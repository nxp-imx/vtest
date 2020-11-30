
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
 * @file SEperformance.c
 *
 * @brief Tests for SE Performance (requirements R13.* and R14.*)
 *
 */

#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <v2xSe.h>
#include "vtest.h"
#include "SEmisc.h"
#include "SEperformance.h"
#include "ecdsa.h"
#include "vtest_async.h"

#ifndef MIN
/** Compute the minimum value of two numbers */
#define MIN(a, b) ((a) > (b) ? (b) : (a))
#endif

static volatile int count_async = ASYNC_COUNT_RESET;
static volatile int loopCount;

static struct timespec startTime, endTime;
static long nsMinLatency, nsMaxLatency;

static TypePublicKey_t *pubKeyArray;
static TypePlainTextMsg_t *msgArray;
static TypeHash_t *hashArray;
static TypeSignature_t *sigArray;

static ecdsa_pubkey_t verif_pubkey;
static uint8_t *verif_msg;
static size_t verif_msgLen;
static ecdsa_hash_t verif_hash;
static ecdsa_sig_t verif_sig;

/** Hash for canned signature, big enough for 384 bits, 256 uses less */
static TypeHash_t cannedHash = {{
#ifdef ECC_PATTERNS_BIG_ENDIAN
	0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18,
	0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
	0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
	0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
	0x2f, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x29, 0x28,
	0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21, 0x20
#else
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
#endif
	}
};

static uint8_t cannedPubkeyNIST256_X[V2XSE_256_EC_PUB_KEY_XY_SIZE] = {
#ifdef ECC_PATTERNS_BIG_ENDIAN
	0x57, 0xb3, 0xc4, 0xec, 0xcf, 0x2e, 0x62, 0x11,
	0x13, 0xb3, 0x84, 0xcd, 0x9e, 0x42, 0xaf, 0x40,
	0x20, 0xb7, 0xdc, 0xfb, 0x89, 0xeb, 0xd3, 0xec,
	0x87, 0xf2, 0xd8, 0xb5, 0x75, 0x78, 0x51, 0x89
#else
	0x89, 0x51, 0x78, 0x75, 0xb5, 0xd8, 0xf2, 0x87,
	0xec, 0xd3, 0xeb, 0x89, 0xfb, 0xdc, 0xb7, 0x20,
	0x40, 0xaf, 0x42, 0x9e, 0xcd, 0x84, 0xb3, 0x13,
	0x11, 0x62, 0x2e, 0xcf, 0xec, 0xc4, 0xb3, 0x57
#endif
};

static uint8_t cannedPubkeyNIST256_Y[V2XSE_256_EC_PUB_KEY_XY_SIZE] = {
#ifdef ECC_PATTERNS_BIG_ENDIAN
	0x3e, 0xf6, 0x74, 0x06, 0x6d, 0x06, 0x67, 0xb3,
	0x48, 0x7b, 0xff, 0x46, 0xe5, 0x04, 0xe9, 0x4d,
	0xb6, 0x6b, 0x6d, 0x81, 0xfb, 0xf2, 0x41, 0xbf,
	0x9c, 0xb3, 0xdd, 0x3d, 0xba, 0x0d, 0xf7, 0x69
#else
	0x69, 0xf7, 0x0d, 0xba, 0x3d, 0xdd, 0xb3, 0x9c,
	0xbf, 0x41, 0xf2, 0xfb, 0x81, 0x6d, 0x6b, 0xb6,
	0x4d, 0xe9, 0x04, 0xe5, 0x46, 0xff, 0x7b, 0x48,
	0xb3, 0x67, 0x06, 0x6d, 0x06, 0x74, 0xf6, 0x3e
#endif
};

static uint8_t cannedSigNIST256_R[V2XSE_256_EC_R_SIGN] = {
#ifdef ECC_PATTERNS_BIG_ENDIAN
	0x6a, 0xe2, 0x7b, 0x70, 0x55, 0x9f, 0x61, 0x4d,
	0xf7, 0x8a, 0xf1, 0x48, 0xef, 0x1f, 0xe7, 0x55,
	0xe5, 0x8d, 0x24, 0x5f, 0xb3, 0xdf, 0x04, 0xb5,
	0x73, 0xdd, 0x84, 0xf6, 0xeb, 0xc4, 0x38, 0x7b
#else
	0x7b, 0x38, 0xc4, 0xeb, 0xf6, 0x84, 0xdd, 0x73,
	0xb5, 0x04, 0xdf, 0xb3, 0x5f, 0x24, 0x8d, 0xe5,
	0x55, 0xe7, 0x1f, 0xef, 0x48, 0xf1, 0x8a, 0xf7,
	0x4d, 0x61, 0x9f, 0x55, 0x70, 0x7b, 0xe2, 0x6a
#endif
};

static uint8_t cannedSigNIST256_S[V2XSE_256_EC_S_SIGN] = {
#ifdef ECC_PATTERNS_BIG_ENDIAN
	0x76, 0x54, 0x05, 0x4d, 0x00, 0xda, 0xa0, 0xce,
	0x99, 0xbd, 0x1d, 0x30, 0x82, 0x29, 0x5d, 0x1b,
	0x63, 0xc5, 0x85, 0x7d, 0x2e, 0x85, 0x76, 0x9d,
	0x50, 0x7c, 0xde, 0x6e, 0xda, 0x68, 0x73, 0x99
#else
	0x99, 0x73, 0x68, 0xda, 0x6e, 0xde, 0x7c, 0x50,
	0x9d, 0x76, 0x85, 0x2e, 0x7d, 0x85, 0xc5, 0x63,
	0x1b, 0x5d, 0x29, 0x82, 0x30, 0x1d, 0xbd, 0x99,
	0xce, 0xa0, 0xda, 0x00, 0x4d, 0x05, 0x54, 0x76
#endif
};

/**
 * @brief   Create an array of msg values for signature verification
 *
 * @param numMsg number of messages to generate
 *
 * @return pointer to msg array, or NULL on failure
 *
 */
static TypePlainTextMsg_t *createMsgArray(uint32_t numMsg)
{
	uint32_t i;
	TypeSW_t hsmStatusCode;
	TypePlainTextMsg_t *msgArray;

	/* Generate random messages to hash */
	msgArray = calloc(numMsg, sizeof(TypePlainTextMsg_t));
	if (!msgArray)
		return NULL;

	for (i = 0; i < numMsg; i++) {
		if (v2xSe_getRandomNumber(MIN(V2XSE_MAX_RND_NUM_SIZE,
				sizeof(TypePlainTextMsg_t)), &hsmStatusCode,
				(TypeRandomNumber_t *)msgArray[i].data)) {
			free(msgArray);
			msgArray = NULL;
			return NULL;
		}
	}
	return msgArray;
}

/**
 * @brief   Create an array of hash values for signature generation
 *
 * @param numHash number of hashes to generate
 * @param msgArray array of msg values to hash (optional)
 *
 * @return pointer to hash array, or NULL on failure
 *
 */
static TypeHash_t *createHashArray(uint32_t numHash, TypePlainTextMsg_t *msgArray)
{
	uint32_t i;
	TypeSW_t hsmStatusCode;
	TypeHash_t *hashArray;

	hashArray = calloc(numHash, sizeof(TypeHash_t));
	if (!hashArray)
		return NULL;

	if (!msgArray) {
		/* Generate random hashes to sign */
		for (i = 0; i < numHash; i++) {
			if (v2xSe_getRandomNumber(sizeof(TypeHash_t), &hsmStatusCode,
					(TypeRandomNumber_t *)hashArray[i].data)) {
				free(hashArray);
				return NULL;
			}
		}
	} else {
		/* Compute hash value from message */

		/* Set up system for hash computation */
		if (ecdsa_open()) {
			VTEST_FLAG_CONF();
			return NULL;
		}
		for (i = 0; i < numHash; i++) {
			if (ecdsa_sha256((const void *)msgArray[i].data,
					sizeof(msgArray[i].data),
					(ecdsa_hash_t)hashArray[i].data)) {
				ecdsa_close();
				free(hashArray);
				return NULL;
			}
		}
		if (ecdsa_close()) {
			VTEST_FLAG_CONF();
			return NULL;
		}
	}

	return hashArray;
}

/**
 * @brief   Create an array of public key values for signature generation
 *
 * @param numPubKey number of public key values to generate
 * @param curveId curve to use to create key
 *
 * @return pointer to public key array, or NULL on failure
 *
 */
static TypePublicKey_t *createPubKeyArray(uint32_t numPubKey, TypeCurveId_t
								curveId)
{
	uint32_t i;
	TypeSW_t hsmStatusCode;
	TypePublicKey_t *pubKeyArray;

	pubKeyArray = calloc(numPubKey, sizeof(TypePublicKey_t));
	if (!pubKeyArray)
		return NULL;

	for (i = 0; i < numPubKey; i++) {
		if (v2xSe_generateRtEccKeyPair(i, curveId,
				&hsmStatusCode,	&pubKeyArray[i])) {
			free(pubKeyArray);
			return NULL;
		}
	}
	return pubKeyArray;
}

/**
 * @brief   Free an array of public key values used for signature generation
 *
 * @param pubKeyArray pointer to array of public keys
 * @param numPubKey number of public key values that were generated
 *
 * @return pointer to public key array, or NULL on failure
 *
 */
static void deletePubKeyArray(TypePublicKey_t *pubKeyArray, uint32_t numPubKey)
{
	uint32_t i;
	TypeSW_t hsmStatusCode;

	if (!pubKeyArray)
		return;

	/* Delete unneeded private keys */
	for (i = 0; i < numPubKey; i++)
		v2xSe_deleteRtEccPrivateKey(i, &hsmStatusCode);

	free(pubKeyArray);
}

/**
 * @brief   Create an array of signatures for verification
 *
 * @param numSig number of signatures to generate
 * @param hashArray array of hash values to sign
 * @param numKeys number of keys generated for signing
 *
 * @return pointer to signature array, or NULL on failure
 *
 */
static TypeSignature_t *createSigArray(uint32_t numSig, TypeHash_t *hashArray,
							uint32_t numKeys)
{
	uint32_t i;
	TypeSW_t hsmStatusCode;
	TypeSignature_t *sigArray;

	sigArray = calloc(numSig, sizeof(TypeSignature_t));
	if (!sigArray)
		return NULL;

	for (i = 0; i < numSig; i++) {
		if (v2xSe_createRtSign(i % numKeys, &hashArray[i],
				&hsmStatusCode,	&sigArray[i])) {
			free(sigArray);
			return NULL;
		}
	}
	return sigArray;
}

#ifndef ECC_PATTERNS_BIG_ENDIAN
/**
 * @brief   Reverse the endianness of an array of hash values
 *
 * @param hashArray array of hashes to reverse
 * @param numHash number of hashes to reverse
 * @param hashSize size of used hash data in each hash
 *
 */
static void reverseHashEndianness(TypeHash_t *hashArray, uint32_t numHash,
							uint32_t dataSize)
{
	uint32_t i, j;
	TypeHash_t swapped;

	for (i = 0; i < numHash; i++) {
		for (j = 0; j < dataSize; j++)
			swapped.data[j] = hashArray[i].data[dataSize - 1 - j];
		memcpy(hashArray[i].data, swapped.data, dataSize);
	}
}

/**
 * @brief   Reverse the endianness of an array of public keys
 *
 * @param pubKeyArray array of public keys to reverse
 * @param numPubKey number of public keys to reverse
 * @param dataSize size of used data in each key coordinate
 *
 */
static void reversePubKeyEndianness(TypePublicKey_t *pubKeyArray,
					uint32_t numPubKey, uint32_t dataSize)
{
	uint32_t i, j;
	TypePublicKey_t swapped;

	for (i = 0; i < numPubKey; i++) {
		for (j = 0; j < dataSize; j++) {
			swapped.x[j] = pubKeyArray[i].x[dataSize - 1 - j];
			swapped.y[j] = pubKeyArray[i].y[dataSize - 1 - j];
		}
		memcpy(pubKeyArray[i].x, swapped.x, dataSize);
		memcpy(pubKeyArray[i].y, swapped.y, dataSize);
	}
}

/**
 * @brief   Reverse the endianness of an array of signatures
 *
 * @param sigArray array of signatures to reverse
 * @param numSig number of signatures to reverse
 * @param dataSize size of used data in each signature element
 *
 */
static void reverseSigEndianness(TypeSignature_t *sigArray, uint32_t numSig,
							uint32_t dataSize)
{
	uint32_t i, j;
	TypeSignature_t swapped;

	for (i = 0; i < numSig; i++) {
		for (j = 0; j < dataSize; j++) {
			swapped.r[j] = sigArray[i].r[dataSize - 1 - j];
			swapped.s[j] = sigArray[i].s[dataSize - 1 - j];
		}
		memcpy(sigArray[i].r, swapped.r, dataSize);
		memcpy(sigArray[i].s, swapped.s, dataSize);
	}
}
#endif

/**
 * @brief   Allocate data for  tests
 *
 * @param testType type of test
 *
 * @return VTEST_PASS or VTEST_FAIL
 *
 */
static uint32_t populateTestData(uint32_t testType)
{
	uint32_t retVal = VTEST_PASS;
	uint32_t numElements;

	VTEST_CHECK_RESULT(testType > TEST_TYPE_SIG_GEN_LATENCY, 0);
	if (testType > TEST_TYPE_SIG_GEN_LATENCY)
		goto fail;

	/* Move to ACTIVATED state, normal operating mode for SE functions */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);

	/* Generate keys to sign with - all tests need this */
	pubKeyArray = createPubKeyArray(NUM_KEYS_PERF_TESTS,
							V2XSE_CURVE_NISTP256);
	VTEST_CHECK_RESULT((!pubKeyArray), 0);
	if (!pubKeyArray)
		goto fail;

	/* Determine number of hash/sigs to generate for test type */
	switch (testType) {
	case TEST_TYPE_SIG_VERIF_RATE:
		numElements = SIG_RATE_VERIF_NUM;
		break;
	case TEST_TYPE_SIG_GEN_RATE:
		numElements = SIG_RATE_GEN_NUM;
		break;
	case TEST_TYPE_SIG_VERIF_LATENCY:
		numElements = SIG_LATENCY_VERIF_NUM;
		break;
	case TEST_TYPE_SIG_GEN_LATENCY:
		numElements = SIG_LATENCY_GEN_NUM;
		break;
	default:
		goto fail_num;
	}

	/* Generate messages to verify */
	if ((testType == TEST_TYPE_SIG_VERIF_RATE) ||
			(testType == TEST_TYPE_SIG_VERIF_LATENCY)) {
		msgArray = createMsgArray(numElements);
		VTEST_CHECK_RESULT((!msgArray), 0);
		if (!msgArray)
			goto fail_msg;
	}

	/* Generate hash to sign */
	hashArray = createHashArray(numElements, msgArray);
	VTEST_CHECK_RESULT((!hashArray), 0);
	if (!hashArray)
		goto fail_hash;

	/* If sig gen test, don't need to pre-prepare signatures */
	if ((testType == TEST_TYPE_SIG_GEN_RATE) ||
			(testType == TEST_TYPE_SIG_GEN_LATENCY))
		goto exit;

	/* Generate signatures to verify */
	sigArray = createSigArray(numElements, hashArray, NUM_KEYS_PERF_TESTS);
	VTEST_CHECK_RESULT((!sigArray), 0);
	if (!sigArray)
		goto fail_sig;

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Reverse endianness for ECDSA sig verification */
	reversePubKeyEndianness(pubKeyArray, NUM_KEYS_PERF_TESTS,
						V2XSE_256_EC_PUB_KEY_XY_SIZE);
	/* TODO, if needed: */
	reverseMsgEndianness(msgArray, ...);
	reverseHashEndianness(hashArray, numElements,
						V2XSE_256_EC_HASH_SIZE);
	reverseSigEndianness(sigArray, numElements, V2XSE_256_EC_R_SIGN);
#endif
	goto exit;

fail_sig:
	free(hashArray);
fail_hash:
	free(msgArray);
	msgArray = NULL;
fail_msg:
fail_num:
	deletePubKeyArray(pubKeyArray, NUM_KEYS_PERF_TESTS);
fail:
	retVal = VTEST_FAIL;
exit:
	/* SE back to init to leave in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	return retVal;
}

/**
 * @brief   Free data tests
 *
 * @param testType type of test
 *
 */
static void freeTestData(uint32_t testType)
{
	if (testType <= TEST_TYPE_SIG_GEN_LATENCY) {
		free(pubKeyArray);
		free(hashArray);
	}
	if ((testType == TEST_TYPE_SIG_VERIF_RATE) ||
			(testType == TEST_TYPE_SIG_VERIF_LATENCY)) {
		free(sigArray);
		free(msgArray);
		msgArray = NULL;
	}
}

/**
 * @brief   Signature verification callback: rate tests
 *
 * @param[in]  sequence_number       sequence operation id (not used?)
 * @param[out] ret                   returned value by the dispatcher
 * @param[out] verification_result   verification result
 *
 */
static void signatureVerificationCallback_rate(void *sequence_number,
	int ret,
	ecdsa_verification_result_t verification_result)
{
	VTEST_CHECK_RESULT_ASYNC_DEC(ret, ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT(verification_result, ECDSA_VERIFICATION_SUCCESS);
	if (--loopCount > 0) {
		/* Setup ECDSA pointers for next loop */
		SETUP_ECDSA_SIG_VERIF_PTRS(loopCount);
		/* Launch next loop */
		VTEST_CHECK_RESULT_ASYNC_INC(
			ecdsa_verify_signature_of_message(ECDSA_CURVE_NISTP256,
				verif_pubkey, verif_msg, verif_msgLen, verif_sig, 0,
				signatureVerificationCallback_rate,
				(void *)0),
			ECDSA_NO_ERROR, count_async);
	} else {
		/* Log end time */
		if (clock_gettime(CLOCK_BOOTTIME, &endTime) == -1) {
			VTEST_FLAG_CONF();
			return;
		}
	}
}

/**
 * @brief   Signature verification callback: latency tests
 *
 * @param[in]  sequence_number       sequence operation id (not used?)
 * @param[out] ret                   returned value by the dispatcher
 * @param[out] verification_result   verification result
 *
 */
static void signatureVerificationCallback_latency(void *sequence_number,
	int ret,
	ecdsa_verification_result_t verification_result)
{
	long nsLatency;

	if (clock_gettime(CLOCK_BOOTTIME, &endTime) == -1) {
		VTEST_FLAG_CONF();
		return;
	}

	VTEST_CHECK_RESULT_ASYNC_DEC(ret, ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT(verification_result, ECDSA_VERIFICATION_SUCCESS);

	/* Calculate latency */
	CALCULATE_TIME_DIFF_NS(startTime, endTime, nsLatency);

	/* Update max/min if required */
	if (nsLatency > nsMaxLatency)
		nsMaxLatency = nsLatency;
	if (nsLatency < nsMinLatency)
		nsMinLatency = nsLatency;

	/* Start next loop if required */
	if (--loopCount > 0) {
		/* Setup ECDSA pointers for next loop */
		SETUP_ECDSA_SIG_VERIF_PTRS(loopCount);
		/* Launch next loop */
		if (clock_gettime(CLOCK_BOOTTIME, &startTime) == -1) {
			VTEST_FLAG_CONF();
			return;
		}
		VTEST_CHECK_RESULT_ASYNC_INC(
			ecdsa_verify_signature_of_message(ECDSA_CURVE_NISTP256,
				verif_pubkey, verif_msg, verif_msgLen, verif_sig, 0,
				signatureVerificationCallback_latency, (void *)0),
			ECDSA_NO_ERROR, count_async);
	}
}

/**
 * @brief   Signature verification callback: background (no measurement)
 *
 * @param[in]  sequence_number       sequence operation id (not used?)
 * @param[out] ret                   returned value by the dispatcher
 * @param[out] verification_result   verification result
 *
 */
static void signatureVerificationCallback_background(void *sequence_number,
	int ret,
	ecdsa_verification_result_t verification_result)
{
	VTEST_CHECK_RESULT_ASYNC_DEC(ret, ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT(verification_result, ECDSA_VERIFICATION_SUCCESS);
	if (--loopCount > 0) {
		/* Launch next loop */
		VTEST_CHECK_RESULT_ASYNC_INC(
			ecdsa_verify_signature(ECDSA_CURVE_NISTP256, verif_pubkey,
				verif_hash, verif_sig, 0,
				signatureVerificationCallback_background,
				(void *)0),
			ECDSA_NO_ERROR, count_async);
	}
}

/**
 *
 * @brief Test rate of signature verification
 *
 * This function tests the rate of signature verification
 *
 */
void test_sigVerifRate(void)
{
	long nsTimeDiff;
	long sigVerifRate;
	long threshold;

	if (seco_os_abs_has_v2x_hw())
		threshold = SIG_VERIF_RATE_THRESHOLD_V2XFW;
	else
		threshold = SIG_VERIF_RATE_THRESHOLD_SECOFW;

	/* Populate data for test */
	if (populateTestData(TEST_TYPE_SIG_VERIF_RATE))
		return;

	/* Set up system for signature verification */
	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
	loopCount = SIG_RATE_VERIF_NUM;

	/* Setup ECDSA variables to point to first data to verify */
	SETUP_ECDSA_SIG_VERIF_PTRS(loopCount);

	/* Log start time */
	if (clock_gettime(CLOCK_BOOTTIME, &startTime) == -1) {
		VTEST_FLAG_CONF();
		/* Free allocated data */
		freeTestData(TEST_TYPE_SIG_VERIF_RATE);
		return;
	}

	/* Start verification loops */
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature_of_message(ECDSA_CURVE_NISTP256,
			verif_pubkey, verif_msg, verif_msgLen, verif_sig, 0,
			signatureVerificationCallback_rate, (void *)0),
		ECDSA_NO_ERROR, count_async);
	/* Wait for end of loop */
	VTEST_CHECK_RESULT_ASYNC_LOOP(count_async, loopCount);
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);

	/* If test finished as expected */
	if (!loopCount) {
		/* Calculate elapsed time and sign verif rate */
		CALCULATE_TIME_DIFF_NS(startTime, endTime, nsTimeDiff);
		VTEST_LOG("Elapsed time for %d signature verifications:"
			" %ld ms\n", SIG_RATE_VERIF_NUM, nsTimeDiff/1000000);
		sigVerifRate = SIG_RATE_VERIF_NUM * 1000000000 / nsTimeDiff;
		VTEST_LOG("Signature verification rate: %ld verifs/sec"
			" (expect %d)\n", sigVerifRate,
			threshold);

		/* Compare to requirement */
		VTEST_CHECK_RESULT(sigVerifRate < threshold, 0);
	}

	/* Free allocated data */
	freeTestData(TEST_TYPE_SIG_VERIF_RATE);
}

/**
 *
 * @brief Test rate of signature generation
 *
 * This function tests the rate of signature generation
 *
 */
void test_sigGenRate(void)
{
	TypeSW_t statusCode;
	TypeSignature_t signature;
	int i;
	long nsTimeDiff;
	long sigGenRate;

	/* Populate data for test */
	if (populateTestData(TEST_TYPE_SIG_GEN_RATE))
		return;

	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);

	/* Log start time */
	if (clock_gettime(CLOCK_BOOTTIME, &startTime) == -1) {
		VTEST_FLAG_CONF();
		freeTestData(TEST_TYPE_SIG_GEN_RATE);
		return;
	}

	/* Generate the signatures */
	for (i = 0; i < SIG_RATE_GEN_NUM; i++) {
		VTEST_CHECK_RESULT(v2xSe_createRtSign(i % NUM_KEYS_PERF_TESTS,
				&hashArray[i],	&statusCode, &signature),
				V2XSE_SUCCESS);
	}

	/* Log end time */
	if (clock_gettime(CLOCK_BOOTTIME, &endTime) == -1) {
		VTEST_FLAG_CONF();
		freeTestData(TEST_TYPE_SIG_GEN_RATE);
		return;
	}

	/* Free allocated data */
	freeTestData(TEST_TYPE_SIG_GEN_RATE);

	/* Calculate elapsed time and sig gen rate */
	CALCULATE_TIME_DIFF_NS(startTime, endTime, nsTimeDiff);
	VTEST_LOG("Elapsed time for %d signature generations: %ld ns\n",
					SIG_RATE_GEN_NUM, nsTimeDiff);
	sigGenRate = SIG_RATE_GEN_NUM * 1000000000 / nsTimeDiff;
	VTEST_LOG("Signature generation rate: %ld sig/sec (expect %d)\n",
					sigGenRate, SIG_GEN_RATE_THRESHOLD);

	/* Compare to requirement */
	VTEST_CHECK_RESULT(sigGenRate < SIG_GEN_RATE_THRESHOLD, 0);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test latency of signature verification.
 *
 * This function tests the latency of signature verification.  If requested,
 * simulation of a loaded system is done using constant signature generations
 * in parallel with the signature verifications.
 *
 * @param testType indicates whether test should run on loaded system or not
 *
 */
void test_sigVerifLatency(uint32_t testType)
{
	float sigVerifMinLatencyMs;
	float sigVerifMaxLatencyMs;
	TypeSW_t statusCode;
	TypePublicKey_t gen_pubKey;
	TypeSignature_t gen_signature;

	/* Populate data for test */
	if (populateTestData(TEST_TYPE_SIG_VERIF_LATENCY))
		return;

	if (testType == LOADED_TEST) {
		/* Move to ACTIVATED state, normal operating mode */
		VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
		/* Create RT key for background sig gen operations */
		VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(SLOT_ZERO,
			V2XSE_CURVE_NISTP256, &statusCode, &gen_pubKey),
								V2XSE_SUCCESS);
	}

	/* Set up system for signature verification */
	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
	loopCount = SIG_LATENCY_VERIF_NUM;

	/* Setup ECDSA variables to point to first data to verify */
	SETUP_ECDSA_SIG_VERIF_PTRS(loopCount);

	/* Init max & min before first measurement */
	nsMinLatency = SIG_LATENCY_MIN_INIT;
	nsMaxLatency = SIG_LATENCY_MAX_INIT;
	/* Log start time */
	if (clock_gettime(CLOCK_BOOTTIME, &startTime) == -1) {
		VTEST_FLAG_CONF();
		goto stopVerifLatencyTest;
	}

	/* Start verification loops */
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature_of_message(ECDSA_CURVE_NISTP256,
			verif_pubkey, verif_msg, verif_msgLen, verif_sig, 0,
			signatureVerificationCallback_latency, (void *)0),
		ECDSA_NO_ERROR, count_async);

	if (testType == LOADED_TEST) {
	/*
	 * Run parallel signature generation until verif counter goes to 0.
	 * Use canned hash & single key for parallel sig gen.  Performance
	 * of sig gen operations not measured so don't care about possible
	 * cache effects of always using same data.
	 */
		while (loopCount > 0) {
			VTEST_CHECK_RESULT(v2xSe_createRtSign(SLOT_ZERO,
				&cannedHash, &statusCode, &gen_signature),
								V2XSE_SUCCESS);
		}
		/* Clean up - loops should be finished */
		VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_1_MS);
	} else {
	/* Unloaded test - just wait for end */
		VTEST_CHECK_RESULT_ASYNC_LOOP(count_async, loopCount);
	}

stopVerifLatencyTest:
	/* Finished verifications */
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);

	/* Free allocated data */
	freeTestData(TEST_TYPE_SIG_VERIF_LATENCY);

	/* If test finished as expected */
	if (!loopCount) {
		/* Calculate max/min latency */
		sigVerifMinLatencyMs = nsMinLatency / (float)1000000;
		sigVerifMaxLatencyMs = nsMaxLatency / (float)1000000;
		VTEST_LOG("Sig verif latency: %.2f ms min,"
				" %.2f ms max (allow %.2f)\n",
				sigVerifMinLatencyMs, sigVerifMaxLatencyMs,
				SIG_VERIF_LATENCY_THRESHOLD);

		/* Compare to requirement */
		VTEST_CHECK_RESULT(sigVerifMaxLatencyMs >
					SIG_VERIF_LATENCY_THRESHOLD, 0);
	}

	/* Go back to init to leave system in known state after test */
	if (testType == LOADED_TEST) {
		/* Delete key after use */
		VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(SLOT_ZERO,
						&statusCode), V2XSE_SUCCESS);
		VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	}
}

/**
 *
 * @brief Test latency of signature verification in loaded system
 *
 * This function tests the latency of signature verification.  To simulate
 * the loading of a normal system, constant signature generations are performed
 * in parallel with the signature verifications.
 *
 */
void test_sigVerifLatencyLoaded(void)
{
	test_sigVerifLatency(LOADED_TEST);
}

/**
 *
 * @brief Test latency of signature verification in unloaded system
 *
 * This function tests the latency of signature verification in an unloaded
 * system.  Only the signature verification is running when measuring the
 * latency.
 *
 */
void test_sigVerifLatencyUnloaded(void)
{
	test_sigVerifLatency(UNLOADED_TEST);
}

/**
 *
 * @brief Test latency of signature generation.
 *
 * This function tests the latency of signature generation.  If requested,
 * simulation of a loaded system is done using constant signature verifications
 * in parallel with the signature generations.
 *
 * @param testType indicates whether test should run on loaded system or not
 *
 */
void test_sigGenLatency(uint32_t testType)
{
	TypeSW_t statusCode;
	TypeSignature_t signature;
	int32_t i;
	float sigGenMinLatencyMs;
	float sigGenMaxLatencyMs;
	long nsLatency;

	/* Populate data for test */
	if (populateTestData(TEST_TYPE_SIG_GEN_LATENCY))
		return;

	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);

	if (testType == LOADED_TEST) {
		/* Set up for parallel signature verification */
		VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
		/*
		 * Assume sig verif is not 10 times faster than sig gen,
		 * so loop count below will keep the verifs running during
		 * the whole test.
		 * The count will be forced to 0 at the end to stop the test.
		 */
		loopCount = SIG_LATENCY_GEN_NUM * 10;
		/*
		 * Use canned hash, key & sig for parallel sig verif.
		 * Performance of sig verif operations not measured so don't
		 * care about possible cache effects of always using same data.
		 */
		verif_hash = (ecdsa_hash_t)cannedHash.data;
		verif_pubkey.x = cannedPubkeyNIST256_X;
		verif_pubkey.y = cannedPubkeyNIST256_Y;
		verif_sig.r = cannedSigNIST256_R;
		verif_sig.s = cannedSigNIST256_S;

		/* Start parallel signature verification */
		VTEST_CHECK_RESULT_ASYNC_INC(
			ecdsa_verify_signature(ECDSA_CURVE_NISTP256, verif_pubkey,
				verif_hash, verif_sig, 0,
				signatureVerificationCallback_background, (void *)0),
			ECDSA_NO_ERROR, count_async);
	}

	/* Init max & min before first measurement */
	nsMinLatency = SIG_LATENCY_MIN_INIT;
	nsMaxLatency = SIG_LATENCY_MAX_INIT;

	/* Loop to generate the signatures */
	for (i = 0; i < SIG_LATENCY_GEN_NUM; i++) {
		/* Get start time */
		if (clock_gettime(CLOCK_BOOTTIME, &startTime) == -1) {
			VTEST_FLAG_CONF();
			goto stopGenLatencyTest;
		}
		/* Generate the signature */
		VTEST_CHECK_RESULT(v2xSe_createRtSign(i % NUM_KEYS_PERF_TESTS,
				&hashArray[i],	&statusCode, &signature),
				V2XSE_SUCCESS);
		/* Get end time */
		if (clock_gettime(CLOCK_BOOTTIME, &endTime) == -1) {
			VTEST_FLAG_CONF();
			goto stopGenLatencyTest;
		}

		/* Calculate latency */
		CALCULATE_TIME_DIFF_NS(startTime, endTime, nsLatency);

		/* Update max/min if required */
		if (nsLatency > nsMaxLatency)
			nsMaxLatency = nsLatency;
		if (nsLatency < nsMinLatency)
			nsMinLatency = nsLatency;
	}

	/* Calculate max/min latency */
	sigGenMinLatencyMs = nsMinLatency / (float)1000000;
	sigGenMaxLatencyMs = nsMaxLatency / (float)1000000;
	VTEST_LOG("Sig gen latency: %.2f ms min, %.2f ms max (allow %.2f)\n",
			sigGenMinLatencyMs, sigGenMaxLatencyMs,
			SIG_VERIF_LATENCY_THRESHOLD);

	/* Compare to requirement */
	VTEST_CHECK_RESULT(sigGenMaxLatencyMs > SIG_GEN_LATENCY_THRESHOLD, 0);

stopGenLatencyTest:
	if (testType == LOADED_TEST) {
		/* Stop parallel signature verification */
		loopCount = 0;
		/* Clean up - loops should be finished soon */
		VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
		VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
	}

	/* Free allocated data */
	freeTestData(TEST_TYPE_SIG_GEN_LATENCY);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test latency of signature generation in a loaded system
 *
 * This function tests the latency of signature generation in a loaded
 * system. Simulation of a loaded system is done using constant signature
 * verifications in parallel with the signature generations.
 *
 */
void test_sigGenLatencyLoaded(void)
{
	test_sigGenLatency(LOADED_TEST);
}

/**
 *
 * @brief Test latency of signature generation in an unloaded system
 *
 * This function tests the latency of signature generation in an unloaded
 * system. Only the signature generation is performed when the latency is
 * measured.
 *
 */
void test_sigGenLatencyUnloaded(void)
{
	test_sigGenLatency(UNLOADED_TEST);
}


static uint8_t *message = (uint8_t *)
"To be, or not to be, that is the question,\n"
"Whether 'tis nobler in the mind to suffer\n"
"The slings and arrows of outrageous fortune,\n"
"Or to take arms against a sea of troubles,\n"
"And by opposing end them? To die: to sleep;\n"
"No more; and by a sleep to say we end\n"
"The heart-ache and the thousand natural shoc\n";
/** Length of message used for performance tests */
#define MESSAGE_LEN strlen((char *)message)

static TypeHash_t testHash;
static uint8_t ecdsa_x[V2XSE_384_EC_PUB_KEY_XY_SIZE];
static uint8_t ecdsa_y[V2XSE_384_EC_PUB_KEY_XY_SIZE];
static uint8_t ecdsa_r[V2XSE_384_EC_R_SIGN];
static uint8_t ecdsa_s[V2XSE_384_EC_S_SIGN];
static long nVerifs;	/* number of sig verifs performed */
static long nsSpentVerifs; /* elapsed time since begining of verif test */

/**
 * @brief Test rate of signature verification
 *
 * @param[in]  sequence_number       sequence operation id (not used)
 * @param[out] ret                   returned value by the ECDSA dispatcher
 * @param[out] verification_result   verification result
 *
 */
static void signatureVerificationCallback(void *sequence_number,
	int ret,
	ecdsa_verification_result_t verification_result)
{
	struct timespec currTime;

	/* One more signature verification performed */
	nVerifs++;
	VTEST_CHECK_RESULT_ASYNC_DEC(ret, ECDSA_NO_ERROR, count_async);

	/* Check correctness of the verification operation */
	VTEST_CHECK_RESULT(verification_result, ECDSA_VERIFICATION_SUCCESS);

	/* Check if test duration has been reached */
	if (clock_gettime(CLOCK_BOOTTIME, &currTime) == -1)
		return;
	CALCULATE_TIME_DIFF_NS(startTime, currTime, nsSpentVerifs);
	if (nsSpentVerifs >= SIG_GEN_VERIF_TIME_SECONDS * 1e9) {
		/* Test is over: set loopCount to 0 to terminate the loop */
		loopCount = 0;
		return;
	}

	/* Perform another signature verification */
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature_of_message(ECDSA_CURVE_NISTP256,
			verif_pubkey, message, MESSAGE_LEN, verif_sig, 0,
			signatureVerificationCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
}

/**
 * @brief Test rate of signature verification
 *
 * @param ptr not used
 *
 */
static void *verif_thread(void *ptr)
{
	long sigVerifRate;
	long threshold;

	if (seco_os_abs_has_v2x_hw())
		threshold = SIG_VERIF_RATE_THRESHOLD_V2XFW;
	else
		threshold = SIG_VERIF_RATE_THRESHOLD_SECOFW;

	/*
	 * Count the number of signature verifications that can be perfomed
	 * during the test duration.
	 * Counter variable is incremented in the callback function.
	 */
	nVerifs = 0;
	loopCount = 100000000;
	/*
	 * loopCount: number of signatures high enough not to be reached.
	 *            Time elapsed will be used to stop the verification loop.
	 */
	/* Perform signature verification */
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature_of_message(ECDSA_CURVE_NISTP256,
			verif_pubkey, message, MESSAGE_LEN, verif_sig, 0,
			signatureVerificationCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);

	/* Wait for signature verification loop completion */
	VTEST_CHECK_RESULT_ASYNC_LOOP(count_async, loopCount);

	VTEST_LOG("Elapsed time for %ld signature verifications: %ld ms\n",
			nVerifs, nsSpentVerifs / 1000000);
	sigVerifRate = nVerifs * 1000000000 / nsSpentVerifs;
	VTEST_LOG("Signature verification rate: %ld verifs/sec (expect %d)\n",
			sigVerifRate, threshold);

	/* Compare to signature verification requirement */
	VTEST_CHECK_RESULT(sigVerifRate < threshold, 0);

	return NULL;
}

/**
 *
 * @brief Test rate of signature generation / verification
 *
 * This function starts a thread to test the following in parallel:
 * o signature generation rate
 * o signature verification rate
 *
 */
void test_sigGenVerifRate(void)
{
	int ret;
	long n, nsSpent, sigGenRate;
	pthread_t thread_verif;
	TypeSW_t hsmStatusCode;
	TypePublicKey_t pubKey;
	TypeSignature_t signature;
	struct timespec currTime;

	VTEST_RETURN_CONF_IF_NO_V2X_HW();

	/* Set up pub key and signature structures for ECDSA verifications */
	verif_pubkey.x = ecdsa_x;
	verif_pubkey.y = ecdsa_y;
	verif_sig.r    = ecdsa_r;
	verif_sig.s    = ecdsa_s;

	/* Use ECDSA to verify signature */
	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);

	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);

	/* Generate ECC key pair */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(SLOT_ZERO,
			V2XSE_CURVE_NISTP256, &hsmStatusCode, &pubKey),
		V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert public key for ECSDA verification */
	convertEndianness(pubKey.x, ecdsa_x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	convertEndianness(pubKey.y, ecdsa_y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#else
	memcpy(ecdsa_x, pubKey.x, V2XSE_256_EC_PUB_KEY_XY_SIZE);
	memcpy(ecdsa_y, pubKey.y, V2XSE_256_EC_PUB_KEY_XY_SIZE);
#endif

	/* Calculate digest value of test message */
	VTEST_CHECK_RESULT(ecdsa_sha256(message, MESSAGE_LEN, testHash.data),
			ECDSA_NO_ERROR);

	/* Calculate a signature to feed the verification thread */
	VTEST_CHECK_RESULT(v2xSe_createRtSign(SLOT_ZERO,
			&testHash, &hsmStatusCode, &signature),
			V2XSE_SUCCESS);

#ifndef ECC_PATTERNS_BIG_ENDIAN
	/* Convert signature for ECDSA verification */
	convertEndianness(signature.r, ecdsa_r, V2XSE_256_EC_R_SIGN);
	convertEndianness(signature.s, ecdsa_s, V2XSE_256_EC_S_SIGN);
#else
	memcpy(ecdsa_r, signature.r, V2XSE_256_EC_R_SIGN);
	memcpy(ecdsa_s, signature.s, V2XSE_256_EC_S_SIGN);
#endif

	/* Get test starting time */
	if (clock_gettime(CLOCK_BOOTTIME, &startTime) == -1) {
		VTEST_FLAG_CONF();
		goto end;
	}

	/* Create signature verification thread */
	ret = pthread_create(&thread_verif, NULL, verif_thread, NULL);
	if (ret) {
		VTEST_LOG("Could not create thread for signature verification\n");
		VTEST_FLAG_CONF();
		goto end;
	}

	/*
	 * Count the number of signature generations that can be perfomed during
	 * the test duration.
	 */
	n = 0;
	do {
		/* Perform a signature generation */
		VTEST_CHECK_RESULT(v2xSe_createRtSign(SLOT_ZERO,
				&testHash, &hsmStatusCode, &signature),
				V2XSE_SUCCESS);
		n++;

		if (clock_gettime(CLOCK_BOOTTIME, &currTime) == -1) {
			VTEST_FLAG_CONF();
			goto end;
		}
		CALCULATE_TIME_DIFF_NS(startTime, currTime, nsSpent);
	} while (nsSpent < SIG_GEN_VERIF_TIME_SECONDS * 1e9);

	VTEST_LOG("Elapsed time for %ld signature generations: %ld ms\n",
			n, nsSpent / 1000000);
	sigGenRate = n * 1000000000 / nsSpent;
	VTEST_LOG("Signature generation rate: %ld gens/sec (expect %d)\n",
			sigGenRate, SIG_GEN_RATE_THRESHOLD);

	/* Compare to signature generation requirement */
	VTEST_CHECK_RESULT(sigGenRate < SIG_GEN_RATE_THRESHOLD, 0);

	/* Wait for verification thread's completion */
	pthread_join(thread_verif, NULL);

end:
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(SLOT_ZERO,
				&hsmStatusCode), V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

	/* Close ecdsa session */
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}
