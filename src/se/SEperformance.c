
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
#include <v2xseapi.h>
#include "vtest.h"
#include "SEmisc.h"
#include "SEperformance.h"

/**
 *
 * @brief Test speed of signature generation
 *
 * This function tests the speed of signature generation
 * The following behaviours are tested:
 *  - signature generated with valid inputs
 * TODO: try different signature types
 *
 */
void test_sigGenSpeed(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeHash_t hash;
	TypeSignature_t signature;
	int i;
	struct timespec startTime, endTime;
	long nsTimeDiff;
	float sigSpeedMs;

/* Measure speed of creating NIST P256 signature in empty slot */
	/* Create dummy hash data */
	hash.data[0] = 16;
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Make sure RT key exists */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(NON_ZERO_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);

	/* Log start time */
	if (clock_gettime(CLOCK_BOOTTIME, &startTime) == -1) {
		VTEST_FLAG_CONF();
		return;
	}

	/* Generate the signatures */
	for (i = 0; i < SIG_SPEED_GEN_NUM; i++)
		VTEST_CHECK_RESULT(v2xSe_createRtSign(NON_ZERO_SLOT, &hash,
				&statusCode, &signature), V2XSE_SUCCESS);

	/* Log end time */
	if (clock_gettime(CLOCK_BOOTTIME, &endTime) == -1) {
		VTEST_FLAG_CONF();
		return;
	}

	/* Calculate elapsed time and sign gen time */
	nsTimeDiff = (endTime.tv_sec - startTime.tv_sec) * 1000000000;
	nsTimeDiff += endTime.tv_nsec;
	nsTimeDiff -= startTime.tv_nsec;
	VTEST_LOG("Elapsed time for %d signatures: %ld ns\n",
					SIG_SPEED_GEN_NUM, nsTimeDiff);
	sigSpeedMs = nsTimeDiff / (float)SIG_SPEED_GEN_NUM / (float)1000000;
	VTEST_LOG("Signature generation time: %.2f ms\n", sigSpeedMs);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

	/* Need to define pass/fail criteria */
	VTEST_FLAG_CONF();
}
