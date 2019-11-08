
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
 * @file SEperformance.c
 *
 * @brief Tests for SE Performance (requirements R13.*)
 *
 */

#include <time.h>
#include <stdlib.h>
#include <v2xSe.h>
#include "vtest.h"
#include "SEmisc.h"
#include "SEperformance.h"

static struct timespec startTime, endTime;
static long nsMinLatency, nsMaxLatency;

static TypePublicKey_t *pubKeyArray;
static TypeHash_t *hashArray;


/**
 * @brief   Create an array of hash values for signature generation
 *
 * @param numHash number of hashes to generate
 *
 * @return pointer to hash array, or NULL on failure
 *
 */
static TypeHash_t *createHashArray(uint32_t numHash)
{
	uint32_t i;
	TypeSW_t hsmStatusCode;
	TypeHash_t *hashArray;

	hashArray = calloc(numHash, sizeof(TypeHash_t));
	if (!hashArray)
		return NULL;

	for (i = 0; i < numHash; i++) {
		if (v2xSe_getRandomNumber(sizeof(TypeHash_t), &hsmStatusCode,
				(TypeRandomNumber_t *)hashArray[i].data)) {
			free(hashArray);
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

	VTEST_CHECK_RESULT((testType != TEST_TYPE_SIG_GEN_LATENCY) &&
				(testType != TEST_TYPE_SIG_GEN_RATE), 0);
	if ((testType != TEST_TYPE_SIG_GEN_LATENCY) &&
				(testType != TEST_TYPE_SIG_GEN_RATE))
		goto fail;

	/* Move to ACTIVATED state, normal operating mode for SE functions */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);

	/* Generate keys to sign with - all tests need this */
	pubKeyArray = createPubKeyArray(NUM_KEYS_PERF_TESTS,
							V2XSE_CURVE_NISTP256);
	VTEST_CHECK_RESULT((pubKeyArray == 0), 0);
	if (!pubKeyArray)
		goto fail;

	/* Determine number of hash/sigs to generate for test type */
	switch (testType) {
	case TEST_TYPE_SIG_GEN_RATE:
		numElements = SIG_RATE_GEN_NUM;
		break;
	case TEST_TYPE_SIG_GEN_LATENCY:
		numElements = SIG_LATENCY_GEN_NUM;
		break;
	default:
		goto fail_hash;
	}

	/* Generate random hashes to sign */
	hashArray = createHashArray(numElements);
	VTEST_CHECK_RESULT((hashArray == 0), 0);
	if (!hashArray)
		goto fail_hash;

	goto exit;

fail_hash:
	free(pubKeyArray);
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
	if ((testType == TEST_TYPE_SIG_GEN_LATENCY) ||
				(testType != TEST_TYPE_SIG_GEN_RATE)) {
		free(pubKeyArray);
		free(hashArray);
	}
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
 * @brief Test latency of signature generation in an unloaded system
 *
 * This function tests the latency of signature generation in an unloaded
 * system. Only the signature generation is performed when the latency is
 * measured.
 *
 */
void test_sigGenLatencyUnloaded(void)
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

	/* Init max & min before first measurement */
	nsMinLatency = SIG_LATENCY_MIN_INIT;
	nsMaxLatency = SIG_LATENCY_MAX_INIT;

	/* Loop to generate the signatures */
	for (i = 0; i < SIG_LATENCY_GEN_NUM; i++) {
		/* Get start time */
		if (clock_gettime(CLOCK_BOOTTIME, &startTime) == -1) {
			VTEST_FLAG_CONF();
			freeTestData(TEST_TYPE_SIG_GEN_LATENCY);
			return;
		}
		/* Generate the signature */
		VTEST_CHECK_RESULT(v2xSe_createRtSign(i % NUM_KEYS_PERF_TESTS,
				&hashArray[i],	&statusCode, &signature),
				V2XSE_SUCCESS);
		/* Get end time */
		if (clock_gettime(CLOCK_BOOTTIME, &endTime) == -1) {
			VTEST_FLAG_CONF();
			freeTestData(TEST_TYPE_SIG_GEN_LATENCY);
			return;
		}

		/* Calculate latency */
		CALCULATE_TIME_DIFF_NS(startTime, endTime, nsLatency);

		/* Update max/min if required */
		if (nsLatency > nsMaxLatency)
			nsMaxLatency = nsLatency;
		if (nsLatency < nsMinLatency)
			nsMinLatency = nsLatency;

	}

	/* Free allocated data */
	freeTestData(TEST_TYPE_SIG_GEN_LATENCY);

	/* Calculate max/min latency */
	sigGenMinLatencyMs = nsMinLatency / (float)1000000;
	sigGenMaxLatencyMs = nsMaxLatency / (float)1000000;
	VTEST_LOG("Sig gen latency: %.2f ms min, %.2f ms max (allow %.2f)\n",
			sigGenMinLatencyMs, sigGenMaxLatencyMs,
			SIG_GEN_LATENCY_THRESHOLD);

	/* Compare to requirement */
	VTEST_CHECK_RESULT(sigGenMaxLatencyMs > SIG_GEN_LATENCY_THRESHOLD, 0);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}
