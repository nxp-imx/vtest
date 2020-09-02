
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
 * @file SEmisc.c
 *
 * @brief Miscellaneous support function for SE tests
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <v2xSe.h>
#include "vtest.h"
#include "SEmisc.h"

/**
 *
 * @brief Utility function to remove SE nvm vars and blob
 *
 * @return VTEST_FAIL or VTEST_CONF
 *
 */
int seClean(void)
{
	int error_seen = 0;

	if (removeNvmVariable(EU_PHASE_FILENAME)) {
		printf("Error removing EU state\n");
		error_seen = 1;
	}
	if (removeNvmVariable(US_PHASE_FILENAME)) {
		printf("Error removing US state\n");
		error_seen = 1;
	}
	if (system("rm -f /etc/seco_hsm/*")) {
		printf("Error removing seco blob files\n");
		error_seen = 1;
	}
	sync();
	if (error_seen)
		return VTEST_FAIL;

	printf("Successfully removed NVM state\n");
	return VTEST_CONF;
}

/**
 *
 * @brief Utility function to place system in INIT state
 *
 * @return VTEST_PASS or VTEST_FAIL
 *
 */
int setupInitState(void)
{
	int32_t retVal;

	/* Move to INIT state */
	retVal = v2xSe_reset();
	if (retVal != V2XSE_SUCCESS) {
		return VTEST_FAIL;
	}
	return VTEST_PASS;
}

/**
 *
 * @brief Utility function to place system in CONNECTED state
 *
 * @return VTEST_PASS or VTEST_FAIL
 *
 */
int setupConnectedState(void)
{
	int32_t retVal;

	/* Move to INIT state first as known starting point */
	retVal = v2xSe_reset();
	if (retVal != V2XSE_SUCCESS) {
		return VTEST_FAIL;
	}
	/* Move to CONNECTED state */
	retVal = v2xSe_connect();
	if (retVal != V2XSE_SUCCESS) {
		return VTEST_FAIL;
	}
	return VTEST_PASS;
}

/**
 *
 * @brief Utility function to place system in ACTIVATED state
 *
 * @param appId applet(s) to be selected during activation
 *
 * @return VTEST_PASS or VTEST_FAIL
 *
 */
int setupActivatedState(appletSelection_t appId)
{
	int32_t retVal;
	TypeSW_t statusCode;

	/* Move to INIT state first as known starting point */
	retVal = v2xSe_reset();
	if (retVal != V2XSE_SUCCESS) {
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state */
	retVal = v2xSe_activate(appId, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		return VTEST_FAIL;
	}
	return VTEST_PASS;
}

/**
 *
 * @brief Utility function to place system in ACTIVATED state, normal phase
 *
 * @param appId applet(s) to be selected during activation
 *
 * @return VTEST_PASS or VTEST_FAIL
 *
 */
int setupActivatedNormalState(appletSelection_t appId)
{
	TypeSW_t statusCode;
	uint8_t phase;

	/* Need activated state to query current phase */
	if (setupActivatedState(appId) != V2XSE_SUCCESS)
		return VTEST_FAIL;

	/* Get phase */
	if (v2xSe_getSePhase(&phase, &statusCode) != V2XSE_SUCCESS)
		return VTEST_FAIL;

	/* Move to normal operation phase if not already there */
	if (phase != V2XSE_NORMAL_OPERATING_PHASE)
		if(v2xSe_endKeyInjection(&statusCode) != V2XSE_SUCCESS)
			return VTEST_FAIL;

	/* Set up normal low security level activation */
	if (setupActivatedState(appId) != V2XSE_SUCCESS)
		return VTEST_FAIL;

	return VTEST_PASS;
}

/**
 *
 * @brief Utility function to remove an NVM variable
 *
 * This function is a utility function to remove an NVM variable.  It
 * deletes the variable in the filesystem if it is present.
 *
 * @param filename the filename of the variable to remove
 *
 * @return VTEST_PASS or VTEST_FAIL
 *
 */
int removeNvmVariable(char *filename)
{
	/* Return pass if var does not exist */
	if (access(filename, F_OK))
		return VTEST_PASS;

	/* Error if failure deleting file */
	if (remove(filename))
		return VTEST_FAIL;

	return VTEST_PASS;
}
