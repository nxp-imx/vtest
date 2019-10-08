
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
 * @file SEdevicemanagement.c
 *
 * @brief Tests for SE Device Management (requirements R5.*)
 *
 */

#include <string.h>
#include <v2xSe.h>
#include "vtest.h"
#include "SEmisc.h"
#include "SEdevicemanagement.h"

/**
 *
 * @brief Test v2xSe_connect for expected behaviour
 *
 * This function tests v2xSe_connect for expected behaviour
 *
 * The following conditions are tested:
 *  - v2xSe_connect moves from INIT to CONNECTED state
 *
 */
void test_connect(void)
{

/* Test v2xSe_connect moves from INIT to CONNECTED state */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Verify success when calling v2xSe_connect */
	VTEST_CHECK_RESULT(v2xSe_connect(), VTEST_PASS);
	/* Verify really in CONNECTED state (based on error code) */
	VTEST_CHECK_RESULT(v2xSe_connect(), V2XSE_FAILURE_CONNECTED);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_connect with bad parameters or incorrect state
 *
 * This function tests v2xSe_connect with bad parameters or incorrect state.
 * For the moment this test indicates CONF when tests pass, as not all
 * cases are tested yet - to be changed to PASS when test fully implemented.
 * The following conditions are tested:
 *  - verify failure when called in CONNECTED state
 *  - verify failure when called in ACTIVATED state
 *
 */
void test_connect_negative(void)
{

/* Test failure when called in CONNECTED state */
	/* Move to CONNECTED state */
	VTEST_CHECK_RESULT(setupConnectedState(), VTEST_PASS);
	/* Verify failure in CONNECTED state */
	VTEST_CHECK_RESULT(v2xSe_connect(), V2XSE_FAILURE_CONNECTED);

/* Test failure when called in ACTIVATED state */
	/* Move to ACTIVATED state */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU_AND_GS), VTEST_PASS);
	/* Verify failure in ACTIVATED state */
	VTEST_CHECK_RESULT(v2xSe_connect(), V2XSE_FAILURE_ACTIVATED);

	/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_activate for expected behaviour
 *
 * This function tests v2xSe_activate for expected behaviour
 * The following conditions are tested:
 *  - v2xSe_activate moves from INIT to ACTIVATED state
 *  - v2xSe_activate sets security level to default (5)
 *  - v2xSe_activate works for US applet
 *  - v2xSe_activate works for EU applet
 *  - v2xSe_activate works for US & GS applet
 *  - v2xSe_activate works for EU & GS applet
 */
void test_activate(void)
{
	uint8_t phase;
	uint8_t dummyData = 0;
	TypeSW_t statusCode;

/* Test v2xSe_activate moves from INIT to ACTIVATED state */
/* Test v2xSe_activate sets security level to default (5) */
/* Test v2xSe_activate works for US applet */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Verify success when calling v2xSe_activate */
	VTEST_CHECK_RESULT(v2xSe_activate(e_US, &statusCode), VTEST_PASS);
	/* Verify really in ACTIVATED state (based on error code) */
	VTEST_CHECK_RESULT(v2xSe_connect(), V2XSE_FAILURE_ACTIVATED);
	/* Verify security level is 5 (getSePhase only works then) */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_SUCCESS);
	/* Verify GS applet not activated */
	VTEST_CHECK_RESULT(v2xSe_storeData(SLOT_ZERO, sizeof(dummyData),
				&dummyData, &statusCode), V2XSE_FAILURE);
	VTEST_CHECK_RESULT(statusCode, V2XSE_INS_NOT_SUPPORTED);


/* Test v2xSe_activate works for EU applet */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Verify success when calling v2xSe_activate */
	VTEST_CHECK_RESULT(v2xSe_activate(e_EU, &statusCode), VTEST_PASS);
	/* Verify really in ACTIVATED state (based on error code) */
	VTEST_CHECK_RESULT(v2xSe_connect(), V2XSE_FAILURE_ACTIVATED);
	/* Verify GS applet not activated */
	VTEST_CHECK_RESULT(v2xSe_storeData(SLOT_ZERO, sizeof(dummyData),
				&dummyData, &statusCode), V2XSE_FAILURE);
	VTEST_CHECK_RESULT(statusCode, V2XSE_INS_NOT_SUPPORTED);

/* Test v2xSe_activate works for US & GS applet */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Verify success when calling v2xSe_activate */
	VTEST_CHECK_RESULT(v2xSe_activate(e_US_AND_GS, &statusCode),
								VTEST_PASS);
	/* Verify really in ACTIVATED state (based on error code) */
	VTEST_CHECK_RESULT(v2xSe_connect(), V2XSE_FAILURE_ACTIVATED);
	/* Verify GS applet activated */
	VTEST_CHECK_RESULT(v2xSe_storeData(SLOT_ZERO, sizeof(dummyData),
				&dummyData, &statusCode), V2XSE_SUCCESS);

/* Test v2xSe_activate works for EU & GS applets */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Verify success when calling v2xSe_activate */
	VTEST_CHECK_RESULT(v2xSe_activate(e_EU_AND_GS, &statusCode),
								VTEST_PASS);
	/* Verify really in ACTIVATED state (based on error code) */
	VTEST_CHECK_RESULT(v2xSe_connect(), V2XSE_FAILURE_ACTIVATED);
	/* Verify GS applet activated */
	VTEST_CHECK_RESULT(v2xSe_storeData(SLOT_ZERO, sizeof(dummyData),
				&dummyData, &statusCode), V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_activate with bad parameters or incorrect state
 *
 * This function tests v2xSe_activate with bad parameters or incorrect state.
 * For the moment this test indicates CONF when tests pass, as not all
 * cases are tested yet - to be changed to PASS when test fully implemented.
 * The following conditions are tested:
 *  - verify failure when called in CONNECTED state
 *  - verify failure when called in ACTIVATED state
 *
 */
void test_activate_negative(void)
{
	TypeSW_t statusCode;

/* Test failure when called in CONNECTED state */
	/* Move to CONNECTED state */
	VTEST_CHECK_RESULT(setupConnectedState(), VTEST_PASS);
	/* Verify failure in CONNECTED state */
	VTEST_CHECK_RESULT(v2xSe_activate(e_EU_AND_GS, &statusCode),
						V2XSE_FAILURE_CONNECTED);

/* Test failure when called in ACTIVATED state */
	/* Move to ACTIVATED state */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU_AND_GS), VTEST_PASS);
	/* Verify failure in ACTIVATED state */
	VTEST_CHECK_RESULT(v2xSe_activate(e_EU_AND_GS, &statusCode),
						V2XSE_FAILURE_ACTIVATED);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
}

/**
 *
 * @brief Test v2xSe_activateWithSecurityLevel for expected behaviour
 *
 * This function tests v2xSe_activateWithSecurityLevel for expected behaviour
 * The following conditions are tested:
 *  - v2xSe_activateWithSecurityLevel moves from INIT to ACTIVATED state
 *  - v2xSe_activateWithSecurityLevel can set security level to 5
 *  - v2xSe_activateWithSecurityLevel can set security level to another value
 *  - v2xSe_activateWithSecurityLevel works for US applet
 *  - v2xSe_activateWithSecurityLevel works for EU applet
 *  - v2xSe_activateWithSecurityLevel works for US & GS applet
 *  - v2xSe_activateWithSecurityLevel works for EU & GS applet
 *
 */
void test_activateWithSecurityLevel(void)
{
	uint8_t phase;
	uint8_t dummyData = 0;
	TypeSW_t statusCode;

/* Test v2xSe_activateWithSecurityLevel moves from INIT to ACTIVATED state */
/* Test v2xSe_activateWithSecurityLevel can set security level to 5 */
/* Test v2xSe_activateWithSecurityLevel works for US applet */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Verify success when calling v2xSe_activateWithSecurityLevel */
	VTEST_CHECK_RESULT(v2xSe_activateWithSecurityLevel(e_US,
				e_channelSecLevel_5, &statusCode), VTEST_PASS);
	/* Verify really in ACTIVATED state (based on error code) */
	VTEST_CHECK_RESULT(v2xSe_connect(), V2XSE_FAILURE_ACTIVATED);
	/* Verify security level is 5 (getSePhase only works then) */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_SUCCESS);
	/* Verify GS applet not activated */
	VTEST_CHECK_RESULT(v2xSe_storeData(SLOT_ZERO, sizeof(dummyData),
				&dummyData, &statusCode), V2XSE_FAILURE);
	VTEST_CHECK_RESULT(statusCode, V2XSE_INS_NOT_SUPPORTED);

/* Test v2xSe_activateWithSecurityLevel works for EU applet */
/* Test v2xSe_activateWithSecurityLevel can set security level less than 5 */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Verify success when calling v2xSe_activateWithSecurityLevel */
	VTEST_CHECK_RESULT(v2xSe_activateWithSecurityLevel(e_EU,
				e_channelSecLevel_4, &statusCode), VTEST_PASS);
	/* Verify really in ACTIVATED state (based on error code) */
	VTEST_CHECK_RESULT(v2xSe_connect(), V2XSE_FAILURE_ACTIVATED);
	/* Verify security level < 5 (getSePhase only works for 5) */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_FAILURE);
	/* Verify GS applet not activated */
	VTEST_CHECK_RESULT(v2xSe_storeData(SLOT_ZERO, sizeof(dummyData),
				&dummyData, &statusCode), V2XSE_FAILURE);
	VTEST_CHECK_RESULT(statusCode, V2XSE_INS_NOT_SUPPORTED);

/* Test v2xSe_activateWithSecurityLevel works for US & GS applet */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Verify success when calling v2xSe_activateWithSecurityLevel */
	VTEST_CHECK_RESULT(v2xSe_activateWithSecurityLevel(e_US_AND_GS,
				e_channelSecLevel_3, &statusCode), VTEST_PASS);
	/* Verify really in ACTIVATED state (based on error code) */
	VTEST_CHECK_RESULT(v2xSe_connect(), V2XSE_FAILURE_ACTIVATED);
	/* Verify GS applet activated */
	VTEST_CHECK_RESULT(v2xSe_storeData(SLOT_ZERO, sizeof(dummyData),
				&dummyData, &statusCode), V2XSE_SUCCESS);

/* Test v2xSe_activateWithSecurityLevel works for EU & GS applets */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Verify success when calling v2xSe_activateWithSecurityLevel */
	VTEST_CHECK_RESULT(v2xSe_activateWithSecurityLevel(e_EU_AND_GS,
				e_channelSecLevel_2, &statusCode), VTEST_PASS);
	/* Verify really in ACTIVATED state (based on error code) */
	VTEST_CHECK_RESULT(v2xSe_connect(), V2XSE_FAILURE_ACTIVATED);
	/* Verify GS applet activated */
	VTEST_CHECK_RESULT(v2xSe_storeData(SLOT_ZERO, sizeof(dummyData),
				&dummyData, &statusCode), V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_activateWithSecurityLevel with bad parameters or state
 *
 * This function tests v2xSe_activateWithSecurityLevel with bad parameters or
 * incorrect state.
 * For the moment this test indicates CONF when tests pass, as not all
 * cases are tested yet - to be changed to PASS when test fully implemented.
 * The following conditions are tested:
 *  - verify failure when called in CONNECTED state
 *  - verify failure when called in ACTIVATED state
 *
 */
void test_activateWithSecurityLevel_negative(void)
{
	TypeSW_t statusCode;

/* Test failure when called in CONNECTED state */
	/* Move to CONNECTED state */
	VTEST_CHECK_RESULT(setupConnectedState(), VTEST_PASS);
	/* Verify failure in CONNECTED state */
	VTEST_CHECK_RESULT(v2xSe_activateWithSecurityLevel(e_EU_AND_GS,
			e_channelSecLevel_5, &statusCode),
						V2XSE_FAILURE_CONNECTED);

/* Test failure when called in ACTIVATED state */
	/* Move to ACTIVATED state */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU_AND_GS), VTEST_PASS);
	/* Verify failure in ACTIVATED state */
	VTEST_CHECK_RESULT(v2xSe_activateWithSecurityLevel(e_EU_AND_GS,
			e_channelSecLevel_5, &statusCode),
						V2XSE_FAILURE_ACTIVATED);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
}

/**
 *
 * @brief Test v2xSe_reset for expected behaviour
 *
 * This function tests v2xSe_reset for expected behaviour:
 * The following conditions are tested:
 *  - v2xSe_reset moves from CONNECTED to INIT state
 *  - v2xSe_reset moves from ACTIVATED to INIT state
 *  - v2xSe_reset stays in INIT state when called
 *
 */
void test_reset(void)
{
/* Test v2xSe_reset moves from CONNECTED to INIT state */
	/* Move to CONNECTED state */
	VTEST_CHECK_RESULT(setupConnectedState(), VTEST_PASS);
	/* Verify success when calling v2xSe_reset */
	VTEST_CHECK_RESULT(v2xSe_reset(), VTEST_PASS);
	/* Verify in INIT state (based on return code) */
	VTEST_CHECK_RESULT(v2xSe_deactivate(), V2XSE_FAILURE_INIT);

/* Test v2xSe_reset moves from ACTIVATED to INIT state */
	/* Move to ACTIVATED state */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU_AND_GS), VTEST_PASS);
	/* Verify success when calling v2xSe_reset */
	VTEST_CHECK_RESULT(v2xSe_reset(), VTEST_PASS);
	/* Verify in INIT state (based on return code) */
	VTEST_CHECK_RESULT(v2xSe_deactivate(), V2XSE_FAILURE_INIT);

/* Test v2xSe_reset stays in INIT state when called */
	/* Already in INIT state from last test */
	/* Verify success when calling v2xSe_reset */
	VTEST_CHECK_RESULT(v2xSe_reset(), VTEST_PASS);
	/* Verify in INIT state (based on return code) */
	VTEST_CHECK_RESULT(v2xSe_deactivate(), V2XSE_FAILURE_INIT);
}

/**
 *
 * @brief Test v2xSe_reset with bad parameters or incorrect state
 *
 * This function tests v2xSe_reset with bad parameters or incorrect state.
 * Note that the current definition of this function has no paramaters and
 * can be called from any state, so this test does nothing for the moment.
 *
 */
void test_reset_negative(void)
{
	/* No tests to run - will count as passed test with 0 subtests */
}

/**
 *
 * @brief Test v2xSe_deactivate for expected behaviour
 *
 * This function tests v2xSe_deactivate for expected behaviour:
 * The following conditions are tested:
 *  - v2xSe_deactivate moves from CONNECTED to INIT state
 *  - v2xSe_deactivate moves from ACTIVATED to INIT state
 *
 */
void test_deactivate(void)
{
/* Test v2xSe_deactivate moves from CONNECTED to INIT state */
	/* Move to CONNECTED state */
	VTEST_CHECK_RESULT(setupConnectedState(), VTEST_PASS);
	/* Verify success when calling v2xSe_deactivate */
	VTEST_CHECK_RESULT(v2xSe_deactivate(), VTEST_PASS);
	/* Verify in INIT state (based on return code) */
	VTEST_CHECK_RESULT(v2xSe_deactivate(), V2XSE_FAILURE_INIT);

/* Test v2xSe_deactivate moves from ACTIVATED to INIT state */
	/* Move to ACTIVATED state */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU_AND_GS), VTEST_PASS);
	/* Verify success when calling v2xSe_deactivate */
	VTEST_CHECK_RESULT(v2xSe_deactivate(), VTEST_PASS);
	/* Verify in INIT state (based on return code) */
	VTEST_CHECK_RESULT(v2xSe_deactivate(), V2XSE_FAILURE_INIT);
}

/**
 *
 * @brief Test v2xSe_deactivate with bad parameters or incorrect state
 *
 * This function tests v2xSe_deactivate with bad parameters or incorrect state.
 * Note that the current definition of this function has no paramaters so
 * only the case of incorrect state is tested.
 * The following conditions are tested:
 *  - verify failure when called in INIT state
 *
 */
void test_deactivate_negative(void)
{

/* Test failure when called in INIT state */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Verify failure in INIT state */
	VTEST_CHECK_RESULT(v2xSe_deactivate(), V2XSE_FAILURE_INIT);
}

/**
 *
 * @brief Test v2xSe_disconnect for expected behaviour
 *
 * This function tests v2xSe_disconnect for expected behaviour:
 * The following conditions are tested:
 *  - v2xSe_disconnect moves from CONNECTED to INIT state
 *  - v2xSe_disconnect moves from ACTIVATED to INIT state
 *
 */
void test_disconnect(void)
{
/* Test v2xSe_disconnect moves from CONNECTED to INIT state */
	/* Move to CONNECTED state */
	VTEST_CHECK_RESULT(setupConnectedState(), VTEST_PASS);
	/* Verify success when calling v2xSe_disconnect */
	VTEST_CHECK_RESULT(v2xSe_disconnect(), VTEST_PASS);
	/* Verify in INIT state (based on return code) */
	VTEST_CHECK_RESULT(v2xSe_deactivate(), V2XSE_FAILURE_INIT);

/* Test v2xSe_disconnect moves from ACTIVATED to INIT state */
	/* Move to ACTIVATED state */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU_AND_GS), VTEST_PASS);
	/* Verify success when calling v2xSe_disconnect */
	VTEST_CHECK_RESULT(v2xSe_disconnect(), VTEST_PASS);
	/* Verify in INIT state (based on return code) */
	VTEST_CHECK_RESULT(v2xSe_deactivate(), V2XSE_FAILURE_INIT);
}

/**
 *
 * @brief Test v2xSe_disconnect with bad parameters or incorrect state
 *
 * This function tests v2xSe_disconnect with bad parameters or incorrect state.
 * Note that the current definition of this function has no paramaters so
 * only the case of incorrect state is tested.
 * The following conditions are tested:
 *  - verify failure when called in INIT state
 *
 */
void test_disconnect_negative(void)
{

/* Test failure when called in INIT state */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Verify failure in INIT state */
	VTEST_CHECK_RESULT(v2xSe_disconnect(),V2XSE_FAILURE_INIT);
}

/**
 *
 * @brief Test v2xSe_getAppletVersion for expected behaviour
 *
 * This function tests v2xSe_getAppletVersion for expected behaviour
 * The following behaviours are tested:
 *  - version returned in correct format for EU applet
 *  - version returned in correct format for US applet
 *  - version returned in correct format for storage applet
 *
 */
void test_getAppletVersion(void)
{
	TypeSW_t statusCode;
	TypeVersion_t version;

/* Test correct version format for EU applet */
	/* Move to ACTIVATED state with EU applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);
	/* Retrieve EU applet version */
	VTEST_CHECK_RESULT(v2xSe_getAppletVersion(e_V2X, &statusCode,
								&version),
							V2XSE_SUCCESS);
	VTEST_LOG("EU applet version: %d.%d.%d",version.data[0],
						version.data[1],
						version.data[2]);
	/* Verify format (generation digit) */
	VTEST_CHECK_RESULT(version.data[0], EXPECTED_MAJOR_VERSION);

/* Test correct version format for US applet */
	/* Move to ACTIVATED state with US + storage applets */
	VTEST_CHECK_RESULT(setupActivatedState(e_US_AND_GS), VTEST_PASS);
	/* Retrieve US applet version */
	VTEST_CHECK_RESULT(v2xSe_getAppletVersion(e_V2X, &statusCode,
								&version),
							V2XSE_SUCCESS);
	VTEST_LOG("US applet version: %d.%d.%d",version.data[0],
						version.data[1],
						version.data[2]);
	/* Verify format (generation digit) */
	VTEST_CHECK_RESULT(version.data[0], EXPECTED_MAJOR_VERSION);

/* Test correct version format for storage applet */
	/* Retrieve storage applet version */
	VTEST_CHECK_RESULT(v2xSe_getAppletVersion(e_GS, &statusCode, &version),
								V2XSE_SUCCESS);
	VTEST_LOG("GS applet version: %d.%d.%d",version.data[0],
						version.data[1],
						version.data[2]);
	/* Verify format (generation digit) */
	VTEST_CHECK_RESULT(version.data[0], EXPECTED_MAJOR_VERSION);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_getSeInfo for expected behaviour
 *
 * This function tests v2xSe_getSeInfo for expected behaviour
 * The following behaviours are tested:
 *  - info returned in correct format for EU applet
 *  - info returned in correct format for US applet
 *  - info returned in correct format for EU and GS applet
 *  - info returned in correct format for US and GS applet
 *
 */
void test_getSeInfo(void)
{
	TypeSW_t statusCode;
	TypeInformation_t seInfo;

/* Test info format for EU applet */
	/* Move to ACTIVATED state with EU applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);
	/* Retrieve EU applet SE info */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	VTEST_LOG("EU applet SE Info: %d,%d,%d,%d,%d,%d,%d,%d,%d",
					seInfo.maxRtKeysAllowed,
					seInfo.maxBaKeysAllowed,
					seInfo.numPreparedVal,
					seInfo.fipsModeIndicator,
					seInfo.proofOfPossession,
					seInfo.rollBackProtection,
					seInfo.rtKeyDerivation,
					seInfo.eciesSupport,
					seInfo.maxDataSlots);
	/* Verify format (expected non-zero values are non-zero) */
	VTEST_CHECK_RESULT((!seInfo.maxRtKeysAllowed ||
				!seInfo.maxBaKeysAllowed ||
				seInfo.numPreparedVal ||
				seInfo.fipsModeIndicator ||
				seInfo.proofOfPossession ||
				!seInfo.rollBackProtection ||
				seInfo.rtKeyDerivation ||
				!seInfo.eciesSupport ||
				seInfo.maxDataSlots),
					0);

/* Test info format for US applet */
	/* Move to ACTIVATED state with US applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_US), VTEST_PASS);
	/* Retrieve US applet SE info */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	VTEST_LOG("US applet SE Info: %d,%d,%d,%d,%d,%d,%d,%d,%d",
					seInfo.maxRtKeysAllowed,
					seInfo.maxBaKeysAllowed,
					seInfo.numPreparedVal,
					seInfo.fipsModeIndicator,
					seInfo.proofOfPossession,
					seInfo.rollBackProtection,
					seInfo.rtKeyDerivation,
					seInfo.eciesSupport,
					seInfo.maxDataSlots);
	/* Verify format (expected non-zero values are non-zero) */
	/* Verify format (expected non-zero values are non-zero) */
	VTEST_CHECK_RESULT((!seInfo.maxRtKeysAllowed ||
				!seInfo.maxBaKeysAllowed ||
				seInfo.numPreparedVal ||
				!seInfo.rtKeyDerivation ||
				!seInfo.eciesSupport ||
				seInfo.maxDataSlots),
					0);

/* Test info format for EU applet */
	/* Move to ACTIVATED state with EU and GS applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU_AND_GS), VTEST_PASS);
	/* Retrieve EU applet SE info */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	VTEST_LOG("EU applet SE Info: %d,%d,%d,%d,%d,%d,%d,%d,%d",
					seInfo.maxRtKeysAllowed,
					seInfo.maxBaKeysAllowed,
					seInfo.numPreparedVal,
					seInfo.fipsModeIndicator,
					seInfo.proofOfPossession,
					seInfo.rollBackProtection,
					seInfo.rtKeyDerivation,
					seInfo.eciesSupport,
					seInfo.maxDataSlots);
	/* Verify format (expected non-zero values are non-zero) */
	VTEST_CHECK_RESULT((!seInfo.maxRtKeysAllowed ||
				!seInfo.maxBaKeysAllowed ||
				seInfo.numPreparedVal ||
				seInfo.fipsModeIndicator ||
				seInfo.proofOfPossession ||
				!seInfo.rollBackProtection ||
				seInfo.rtKeyDerivation ||
				!seInfo.eciesSupport ||
				!seInfo.maxDataSlots),
					0);

/* Test info format for US applet */
	/* Move to ACTIVATED state with US and GS applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_US_AND_GS), VTEST_PASS);
	/* Retrieve US applet SE info */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	VTEST_LOG("US applet SE Info: %d,%d,%d,%d,%d,%d,%d,%d,%d",
					seInfo.maxRtKeysAllowed,
					seInfo.maxBaKeysAllowed,
					seInfo.numPreparedVal,
					seInfo.fipsModeIndicator,
					seInfo.proofOfPossession,
					seInfo.rollBackProtection,
					seInfo.rtKeyDerivation,
					seInfo.eciesSupport,
					seInfo.maxDataSlots);
	/* Verify format (expected non-zero values are non-zero) */
	/* Verify format (expected non-zero values are non-zero) */
	VTEST_CHECK_RESULT((!seInfo.maxRtKeysAllowed ||
				!seInfo.maxBaKeysAllowed ||
				seInfo.numPreparedVal ||
				seInfo.fipsModeIndicator ||
				seInfo.proofOfPossession ||
				!seInfo.rollBackProtection ||
				!seInfo.rtKeyDerivation ||
				!seInfo.eciesSupport ||
				!seInfo.maxDataSlots),
					0);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_getCryptoLibVersion for expected behaviour
 *
 * This function tests v2xSe_getCryptoLibVersion for expected behaviour
 * The following behaviours are tested:
 *  - version returned in correct format
 *
 */
void test_getCryptoLibVersion(void)
{
	TypeVersion_t version;

/* Test version returned in correct format */
	VTEST_CHECK_RESULT(v2xSe_getCryptoLibVersion(&version), V2XSE_SUCCESS);
	VTEST_LOG("Crypto Lib version: %d.%d.%d",version.data[0],
						version.data[1],
						version.data[2]);
	/* Verify format (generation digit) */
	VTEST_CHECK_RESULT(version.data[0], EXPECTED_MAJOR_VERSION);
}

/**
 *
 * @brief Test v2xSe_getPlatformInfo for expected behaviour
 *
 * This function tests v2xSe_getPlatformInfo for expected behaviour
 * The following behaviours are tested:
 *  - info returned in correct format
 *
 */
void test_getPlatformInfo(void)
{
	TypeSW_t statusCode;
	TypePlatformIdentity_t platformIdentity;
	char displayString[V2XSE_PLATFORM_IDENTITY+1];

/* Test info returned in correct format */
	/* Move to CONNECTED state */
	VTEST_CHECK_RESULT(setupConnectedState(), VTEST_PASS);
	/* Get platform info */
	VTEST_CHECK_RESULT(v2xSe_getPlatformInfo(&statusCode,
						&platformIdentity),
							V2XSE_SUCCESS);
	memcpy(displayString, platformIdentity.data, V2XSE_PLATFORM_IDENTITY);
	displayString[V2XSE_PLATFORM_IDENTITY] = 0;
	VTEST_LOG("Platform info: %s", displayString);
	/* Verify all 16 bytes filled */
	VTEST_CHECK_RESULT(strnlen(displayString,V2XSE_PLATFORM_IDENTITY),
					V2XSE_PLATFORM_IDENTITY);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_getPlatformConfig for expected behaviour
 *
 * This function tests v2xSe_getPlatformConfig for expected behaviour
 * The following behaviours are tested:
 *  - config returned in correct format
 *
 */
void test_getPlatformConfig(void)
{
	TypeSW_t statusCode;
	TypePlatformConfiguration_t platformConfig;

/* Test config returned in correct format */
	/* Move to CONNECTED state */
	VTEST_CHECK_RESULT(setupConnectedState(), VTEST_PASS);
	/* Get platform config */
	VTEST_CHECK_RESULT(v2xSe_getPlatformConfig(&statusCode,
						&platformConfig),
							V2XSE_SUCCESS);
	VTEST_LOG("Platform config: %x %c%c%c", platformConfig.data[0],
						platformConfig.data[1],
						platformConfig.data[2],
						platformConfig.data[3]);
	/* Verify 1st byte 0, all others non-zero */
	VTEST_CHECK_RESULT((platformConfig.data[0] ||
				!platformConfig.data[1] ||
				!platformConfig.data[2] ||
				!platformConfig.data[3]),
					0);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_getChipInfo for expected behaviour
 *
 * This function tests v2xSe_getChipInfo for expected behaviour
 * The following behaviours are tested:
 *  - info returned in correct format
 *
 */
void test_getChipInfo(void)
{
	TypeSW_t statusCode;
	TypeChipInformation_t chipInfo;
	int i;

/* Test info returned in correct format */
	/* Move to CONNECTED state */
	VTEST_CHECK_RESULT(setupConnectedState(), VTEST_PASS);
	/* Get chip info */
	VTEST_CHECK_RESULT(v2xSe_getChipInfo(&statusCode, &chipInfo),
							V2XSE_SUCCESS);
	VTEST_LOG("Chip Info: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\
%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
							chipInfo.data[0],
							chipInfo.data[1],
							chipInfo.data[2],
							chipInfo.data[3],
							chipInfo.data[4],
							chipInfo.data[5],
							chipInfo.data[6],
							chipInfo.data[7],
							chipInfo.data[8],
							chipInfo.data[9],
							chipInfo.data[10],
							chipInfo.data[11],
							chipInfo.data[12],
							chipInfo.data[13],
							chipInfo.data[14],
							chipInfo.data[15],
							chipInfo.data[16],
							chipInfo.data[17],
							chipInfo.data[18],
							chipInfo.data[19],
							chipInfo.data[20],
							chipInfo.data[21],
							chipInfo.data[22],
							chipInfo.data[23]);
	/* Verify data not all zero */
	for (i = 0; i < V2XSE_SERIAL_NUMBER; i++) {
		if (chipInfo.data[i] != 0)
			break;
	}
	VTEST_CHECK_RESULT((i == V2XSE_SERIAL_NUMBER), 0);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_getAttackLog for expected behaviour
 *
 * This function tests v2xSe_getAttackLog for expected behaviour
 * The following behaviours are tested:
 *  - empty attack log returned
 *
 */
void test_getAttackLog(void)
{
	TypeSW_t statusCode;
	TypeAttackLog_t attackLog;

/* Test empty attack log returned */
	/* Move to CONNECTED state */
	VTEST_CHECK_RESULT(setupConnectedState(), VTEST_PASS);
	/* Get attack log */
	VTEST_CHECK_RESULT(v2xSe_getAttackLog(&statusCode, &attackLog),
								V2XSE_SUCCESS);
	VTEST_LOG("attack log status: %d, length: %d\n",
						attackLog.currAttackCntrStatus,
						attackLog.len);
	/* Verify contents empty */
	VTEST_CHECK_RESULT((attackLog.currAttackCntrStatus !=
				V2XSE_ATTACK_CNT_ZERO) || attackLog.len, 0);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_sendReceive for expected behaviour
 *
 * This function tests v2xSe_sendReceive for expected behaviour
 * For the moment this test indicates CONF when tests pass, as not all
 * cases are tested yet - to be changed to PASS when test fully implemented.
 * The following behaviours are tested:
 *  - failure returned with valid input and correct state
 *
 *
 */
void test_sendReceive(void)
{
	TypeSW_t statusCode;
	uint8_t TxBuf[V2XSE_MAX_TX_RX_SIZE];
	uint8_t RxBuf[V2XSE_MAX_TX_RX_SIZE];
	uint16_t RxLen;

/* Test failure returned */
	/* Move to CONNECTED state */
	VTEST_CHECK_RESULT(setupConnectedState(), VTEST_PASS);
	/* Perform sendRecieve */
	VTEST_CHECK_RESULT(v2xSe_sendReceive(TxBuf, V2XSE_MAX_TX_RX_SIZE,
				&RxLen, RxBuf, &statusCode), V2XSE_FAILURE);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_invokeGarbageCollector for expected behaviour
 *
 * This function tests v2xSe_invokeGarbageCollector for expected behaviour
 * The following behaviours are tested:
 *  - success returned when in correct state
 *
 */
void test_invokeGarbageCollector(void)
{
	TypeSW_t statusCode;

/* Test success returned when in correct state */
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Invoke garbage collector */
	VTEST_CHECK_RESULT(v2xSe_invokeGarbageCollector(&statusCode),
								V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_getRemainingNvm for expected behaviour
 *
 * This function tests v2xSe_getRemainingNvm for expected behaviour
 * The following behaviours are tested:
 *  - non-zero value returned
 *
 */
void test_getRemainingNvm(void)
{
	TypeSW_t statusCode;
	uint32_t remainingNvm;

/* Test non-zero value returned */
	/* Move to CONNECTED state */
	VTEST_CHECK_RESULT(setupConnectedState(), VTEST_PASS);
	/* Get remaining NVM */
	VTEST_CHECK_RESULT(v2xSe_getRemainingNvm(&remainingNvm, &statusCode),
								V2XSE_SUCCESS);
	VTEST_LOG("Remaining NVM: 0x%x bytes\n",remainingNvm);
	/* Verify non-zero value */
	VTEST_CHECK_RESULT(!remainingNvm, 0);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_getSePhase in key injection phase
 *
 * This function tests v2xSe_getSePhase in key injection phase
 * The following behaviours are tested:
 *  - expected value returned in key injection phase for EU applet
 *  - expected value returned in key injection phase for US applet
 *
 */
void test_getSePhase_keyinject(void)
{
	TypeSW_t statusCode;
	uint8_t phase;

/* Test expected value returned in key injection phase for EU applet */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force return to key injection phase */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state with EU applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);
	/* Verify SE phase reading */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_SUCCESS);
	/* Verify value read */
	VTEST_CHECK_RESULT(phase, V2XSE_KEY_INJECTION_PHASE);

/* Test expected value returned in key injection phase for US applet */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force return to key injection phase */
	VTEST_CHECK_RESULT(removeNvmVariable(US_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state with US applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_US), VTEST_PASS);
	/* Verify SE phase reading */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_SUCCESS);
	/* Verify value read */
	VTEST_CHECK_RESULT(phase, V2XSE_KEY_INJECTION_PHASE);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_getSePhase in normal operating phase
 *
 * This function tests v2xSe_getSePhase in normal operating phase
 * The following behaviours are tested:
 *  - expected value returned in normal operating phase for EU applet
 *  - expected value returned in normal operating phase for US applet
 *
 */
void test_getSePhase_normal(void)
{
	TypeSW_t statusCode;
	uint8_t phase;

/* Test expected value returned in normal operating phase for EU applet */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Verify SE phase reading */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_SUCCESS);
	/* Verify value read */
	VTEST_CHECK_RESULT(phase, V2XSE_NORMAL_OPERATING_PHASE);

/* Test expected value returned in normal operating phase for US applet */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_US), VTEST_PASS);
	/* Verify SE phase reading */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_SUCCESS);
	/* Verify value read */
	VTEST_CHECK_RESULT(phase, V2XSE_NORMAL_OPERATING_PHASE);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}
