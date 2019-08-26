
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEdevicemanagement.c
 *
 * @brief Tests for SE Device Management (requirements R5.*)
 *
 */

#include <stdio.h>
#include <string.h>
#include <v2xseapi.h>
#include "vtest.h"
#include "SEdevicemanagement.h"

/**
 *
 * @brief Test v2xSe_connect with bad parameters or incorrect state
 *
 * This function tests v2xSe_connect with bad parameters or incorrect state.
 * For the moment this test returns VTEST_CONF when tests pass, as not all
 * cases are tested yet - to be changed to PASS when test fully implemented.
 * The following conditions are tested:
 *  - verify failure when called in CONNECTED state
 *  - verify failure when called in ACTIVATED state
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_connect_negative(void)
{
	int32_t retVal;
	TypeSW_t statusCode;

/* Test failure when called in CONNECTED state */
	/* Move to CONNECTED state */
	if (setupConnectedState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Verify failure in CONNECTED state */
	retVal = v2xSe_connect();
	if (retVal != V2XSE_FAILURE_CONNECTED) {
		printf("ERROR: v2xSe_connect returned %d in CONNECTED state\n",
								retVal);
		return VTEST_FAIL;
	}

/* Test failure when called in ACTIVATED state */
	/* Move to ACTIVATED state */
	if (setupActivatedState(e_EU_AND_GS) != VTEST_PASS)
		return VTEST_FAIL;
	/* Verify failure in ACTIVATED state */
	retVal = v2xSe_connect();
	if (retVal != V2XSE_FAILURE_ACTIVATED) {
		printf("ERROR: v2xSe_connect returned %d in ACTIVATED state\n",
								retVal);
		return VTEST_FAIL;
	}

	/* Return CONF as not all required tests implemented yet */
	return VTEST_CONF;
}

/**
 *
 * @brief Test v2xSe_activate with bad parameters or incorrect state
 *
 * This function tests v2xSe_activate with bad parameters or incorrect state.
 * For the moment this test returns VTEST_CONF when tests pass, as not all
 * cases are tested yet - to be changed to PASS when test fully implemented.
 * The following conditions are tested:
 *  - verify failure when called in CONNECTED state
 *  - verify failure when called in ACTIVATED state
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_activate_negative(void)
{
	int32_t retVal;
	TypeSW_t statusCode;

/* Test failure when called in CONNECTED state */
	/* Move to CONNECTED state */
	if (setupConnectedState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Verify failure in CONNECTED state */
	retVal = v2xSe_activate(e_EU_AND_GS, &statusCode);
	if (retVal != V2XSE_FAILURE_CONNECTED) {
		printf("ERROR: v2xSe_activate returned %d in CONNECTED state\n",
								retVal);
		return VTEST_FAIL;
	}

/* Test failure when called in ACTIVATED state */
	/* Move to ACTIVATED state */
	if (setupActivatedState(e_EU_AND_GS) != VTEST_PASS)
		return VTEST_FAIL;
	/* Verify failure in ACTIVATED state */
	retVal = v2xSe_activate(e_EU_AND_GS, &statusCode);
	if (retVal != V2XSE_FAILURE_ACTIVATED) {
		printf("ERROR: v2xSe_activate returned %d in ACTIVATED state\n",
								retVal);
		return VTEST_FAIL;
	}

	/* Return CONF as not all required tests implemented yet */
	return VTEST_CONF;
}

/**
 *
 * @brief Test v2xSe_activateWithSecurityLevel with bad parameters or state
 *
 * This function tests v2xSe_activateWithSecurityLevel with bad parameters or
 * incorrect state.
 * For the moment this test returns VTEST_CONF when tests pass, as not all
 * cases are tested yet - to be changed to PASS when test fully implemented.
 * The following conditions are tested:
 *  - verify failure when called in CONNECTED state
 *  - verify failure when called in ACTIVATED state
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_activateWithSecurityLevel_negative(void)
{
	int32_t retVal;
	TypeSW_t statusCode;

/* Test failure when called in CONNECTED state */
	/* Move to CONNECTED state */
	if (setupConnectedState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Verify failure in CONNECTED state */
	retVal = v2xSe_activateWithSecurityLevel(e_EU_AND_GS,
							e_channelSecLevel_5,
							&statusCode);
	if (retVal != V2XSE_FAILURE_CONNECTED) {
		printf("ERROR: v2xSe_activateWithSecurityLevel returned %d"\
						" in CONNECTED state\n",
								retVal);
		return VTEST_FAIL;
	}

/* Test failure when called in ACTIVATED state */
	/* Move to ACTIVATED state */
	if (setupActivatedState(e_EU_AND_GS) != VTEST_PASS)
		return VTEST_FAIL;
	/* Verify failure in ACTIVATED state */
	retVal = v2xSe_activateWithSecurityLevel(e_EU_AND_GS,
							e_channelSecLevel_5,
							&statusCode);
	if (retVal != V2XSE_FAILURE_ACTIVATED) {
		printf("ERROR: v2xSe_activateWithSecurityLevel returned %d"\
						" in ACTIVATED state\n",
								retVal);
		return VTEST_FAIL;
	}

	/* Return CONF as not all required tests implemented yet */
	return VTEST_CONF;
}

/**
 *
 * @brief Test v2xSe_reset with bad parameters or incorrect state
 *
 * This function tests v2xSe_reset with bad parameters or incorrect state.
 * Note that the current definition of this function has no paramaters and
 * can be called from any state, so this test always passes for the moment.
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_reset_negative(void)
{
	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_deactivate_negative(void)
{
	int32_t retVal;

/* Test failure when called in INIT state */
	/* Move to INIT state */
	if (setupInitState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Verify failure in INIT state */
	retVal = v2xSe_deactivate();
	if (retVal != V2XSE_FAILURE_INIT) {
		printf("ERROR: v2xSe_deactivate returned %d in INIT state\n",
								retVal);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_disconnect_negative(void)
{
	int32_t retVal;

/* Test failure when called in INIT state */
	/* Move to INIT state */
	if (setupInitState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Verify failure in INIT state */
	retVal = v2xSe_disconnect();
	if (retVal != V2XSE_FAILURE_INIT) {
		printf("ERROR: v2xSe_deactivate returned %d in INIT state\n",
								retVal);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_getAppletVersion(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypeVersion_t version;

/* Test correct version format for EU applet */
	/* Move to ACTIVATED state with EU applet */
	if (setupActivatedState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Retrieve EU applet version */
	retVal = v2xSe_getAppletVersion(e_V2X, &statusCode, &version);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getAppletVersion returned %d\n", retVal);
		return VTEST_FAIL;
	}
	printf("EU applet version: %d.%d.%d\n",version.data[0],
						version.data[1],
						version.data[2]);
	/* Verify format (generation digit) */
	if (version.data[0] != EXPECTED_VERSION_GENERATION) {
		printf("ERROR: v2xSe_getAppletVersion gave EU generation %d\n",
							version.data[0]);
		return VTEST_FAIL;

	}

/* Test correct version format for US applet */
	/* Move to ACTIVATED state with US + storage applets */
	if (setupActivatedState(e_US_AND_GS) != VTEST_PASS)
		return VTEST_FAIL;
	/* Retrieve US applet version */
	retVal = v2xSe_getAppletVersion(e_V2X, &statusCode, &version);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getAppletVersion returned %d\n", retVal);
		return VTEST_FAIL;
	}
	printf("US applet version: %d.%d.%d\n",version.data[0],
						version.data[1],
						version.data[2]);
	/* Verify format (generation digit) */
	if (version.data[0] != EXPECTED_VERSION_GENERATION) {
		printf("ERROR: v2xSe_getAppletVersion gave US generation %d\n",
							version.data[0]);
		return VTEST_FAIL;
	}

/* Test correct version format for storage applet */
	/* Retrieve storage applet version */
	retVal = v2xSe_getAppletVersion(e_GS, &statusCode, &version);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getAppletVersion returned %d\n", retVal);
		return VTEST_FAIL;
	}
	printf("GS applet version: %d.%d.%d\n",version.data[0],
						version.data[1],
						version.data[2]);
	/* Verify format (generation digit) */
	if (version.data[0] != EXPECTED_VERSION_GENERATION) {
		printf("ERROR: v2xSe_getAppletVersion gave GS generation %d\n",
							version.data[0]);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
}

/**
 *
 * @brief Test v2xSe_getSeInfo for expected behaviour
 *
 * This function tests v2xSe_getSeInfo for expected behaviour
 * The following behaviours are tested:
 *  - info returned in correct format for EU applet
 *  - info returned in correct format for US applet
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_getSeInfo(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypeInformation_t seInfo;

/* Test info format for EU applet */
	/* Move to ACTIVATED state with EU applet */
	if (setupActivatedState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Retrieve EU applet SE info */
	retVal = v2xSe_getSeInfo(&statusCode, &seInfo);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSeInfo returned %d\n", retVal);
		return VTEST_FAIL;
	}
	printf("EU applet SE Info: %d,%d,%d,%d,%d,%d,%d,%d,%d\n",
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
	if (!seInfo.maxRtKeysAllowed || !seInfo.maxBaKeysAllowed ||
			!seInfo.numPreparedVal || !seInfo.rtKeyDerivation ||
			!seInfo.eciesSupport || !seInfo.maxDataSlots) {
		printf("ERROR: v2xSe_getSeInfo gave unexpected 0 values\n");
		return VTEST_FAIL;
	}

/* Test info format for US applet */
	/* Move to ACTIVATED state with US applet */
	if (setupActivatedState(e_US) != VTEST_PASS)
		return VTEST_FAIL;
	/* Retrieve US applet SE info */
	retVal = v2xSe_getSeInfo(&statusCode, &seInfo);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSeInfo returned %d\n", retVal);
		return VTEST_FAIL;
	}
	printf("US applet SE Info: %d,%d,%d,%d,%d,%d,%d,%d,%d\n",
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
	if (!seInfo.maxRtKeysAllowed || !seInfo.maxBaKeysAllowed ||
			!seInfo.numPreparedVal || !seInfo.rtKeyDerivation ||
			!seInfo.eciesSupport || !seInfo.maxDataSlots) {
		printf("ERROR: v2xSe_getSeInfo gave unexpected 0 values\n");
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
}

/**
 *
 * @brief Test v2xSe_getCryptoLibVersion for expected behaviour
 *
 * This function tests v2xSe_getCryptoLibVersion for expected behaviour
 * The following behaviours are tested:
 *  - version returned in correct format

 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_getCryptoLibVersion(void)
{
	int32_t retVal;
	TypeVersion_t version;

/* Test version returned in correct format */
	retVal = v2xSe_getCryptoLibVersion(&version);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getCryptoLibVersion returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	printf("Crypto Lib version: %d.%d.%d\n",version.data[0],
						version.data[1],
						version.data[2]);
	/* Verify format (generation digit) */
	if (version.data[0] != EXPECTED_VERSION_GENERATION) {
		printf("ERROR: v2xSe_getCryptoLibVersion gave generation %d\n",
							version.data[0]);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
}

/**
 *
 * @brief Test v2xSe_getPlatformInfo for expected behaviour
 *
 * This function tests v2xSe_getPlatformInfo for expected behaviour
 * The following behaviours are tested:
 *  - info returned in correct format
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_getPlatformInfo(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePlatformIdentity_t platformIdentity;
	char displayString[V2XSE_PLATFORM_IDENTITY+1];

/* Test info returned in correct format */
	/* Move to CONNECTED state */
	if (setupConnectedState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Get platform info */
	retVal = v2xSe_getPlatformInfo(&statusCode, &platformIdentity);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getPlatformInfo returned %d\n", retVal);
		return VTEST_FAIL;
	}
	memcpy(displayString, platformIdentity.data, V2XSE_PLATFORM_IDENTITY);
	displayString[V2XSE_PLATFORM_IDENTITY] = 0;
	printf("Platform info: %s\n", displayString);
	/* Verify all 16 bytes filled */
	if (strnlen(displayString,V2XSE_PLATFORM_IDENTITY) !=
					V2XSE_PLATFORM_IDENTITY) {
		printf("ERROR: v2xSe_getPlatformInfo output too short\n");
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
}

/**
 *
 * @brief Test v2xSe_getPlatformConfig for expected behaviour
 *
 * This function tests v2xSe_getPlatformConfig for expected behaviour
 * The following behaviours are tested:
 *  - config returned in correct format
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_getPlatformConfig(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePlatformConfiguration_t platformConfig;

/* Test config returned in correct format */
	/* Move to CONNECTED state */
	if (setupConnectedState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Get platform config */
	retVal = v2xSe_getPlatformConfig(&statusCode, &platformConfig);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getPlatformConfig returned %d\n", retVal);
		return VTEST_FAIL;
	}
	printf("Platform config: %x %c%c%c\n", platformConfig.data[0],
						platformConfig.data[1],
						platformConfig.data[2],
						platformConfig.data[3]);
	/* Verify 1st byte 0, all others non-zero */
	if (platformConfig.data[0] || !platformConfig.data[1] ||
			!platformConfig.data[2] || !platformConfig.data[3]) {
		printf("ERROR: v2xSe_getPlatformConfig output bad format\n");
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
}

/**
 *
 * @brief Test v2xSe_getChipInfo for expected behaviour
 *
 * This function tests v2xSe_getChipInfo for expected behaviour
 * The following behaviours are tested:
 *  - info returned in correct format
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_getChipInfo(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypeChipInformation_t chipInfo;
	int i;

/* Test info returned in correct format */
	/* Move to CONNECTED state */
	if (setupConnectedState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Get chip info */
	retVal = v2xSe_getChipInfo(&statusCode, &chipInfo);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getChipInfo returned %d\n", retVal);
		return VTEST_FAIL;
	}
	printf("Chip Info: %02x%02x%02x%02x%02x%02x%02x%02x",
							chipInfo.data[0],
							chipInfo.data[1],
							chipInfo.data[2],
							chipInfo.data[3],
							chipInfo.data[4],
							chipInfo.data[5],
							chipInfo.data[6],
							chipInfo.data[7]);
	printf("%02x%02x%02x%02x%02x%02x%02x%02x",
							chipInfo.data[8],
							chipInfo.data[9],
							chipInfo.data[10],
							chipInfo.data[11],
							chipInfo.data[12],
							chipInfo.data[13],
							chipInfo.data[14],
							chipInfo.data[15]);
	printf("%02x%02x%02x%02x%02x%02x%02x%02x\n",
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
	if (i == V2XSE_SERIAL_NUMBER) {
		printf("ERROR: v2xSe_getChipInfo output all 0\n");
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
}

/**
 *
 * @brief Test v2xSe_getAttackLog for expected behaviour
 *
 * This function tests v2xSe_getAttackLog for expected behaviour
 * The following behaviours are tested:
 *  - empty attack log returned
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_getAttackLog(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypeAttackLog_t attackLog;

/* Test empty attack log returned */
	/* Move to CONNECTED state */
	if (setupConnectedState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Get attack log */
	retVal = v2xSe_getAttackLog(&statusCode, &attackLog);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getAttackLog returned %d\n", retVal);
		return VTEST_FAIL;
	}
	printf("attack log status: %d, length: %d\n",
						attackLog.currAttackCntrStatus,
						attackLog.len);
	/* Verify contents empty */
	if ((attackLog.currAttackCntrStatus != V2XSE_ATTACK_CNT_ZERO) ||
							attackLog.len) {
		printf("ERROR: Attack log not empty\n");
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
}

/**
 *
 * @brief Test v2xSe_sendReceive for expected behaviour
 *
 * This function tests v2xSe_sendReceive for expected behaviour
 * For the moment this test returns VTEST_CONF when tests pass, as not all
 * cases are tested yet - to be changed to PASS when test fully implemented.
 * The following behaviours are tested:
 *  - failure returned with valid input and correct state
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_sendReceive(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	uint8_t TxBuf[V2XSE_MAX_TX_RX_SIZE];
	uint8_t RxBuf[V2XSE_MAX_TX_RX_SIZE];
	uint16_t RxLen;

/* Test failure returned */
	/* Move to CONNECTED state */
	if (setupConnectedState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Perform sendRecieve */
	retVal = v2xSe_sendReceive(TxBuf, V2XSE_MAX_TX_RX_SIZE, &RxLen,
							RxBuf, &statusCode);
	if (retVal != V2XSE_FAILURE) {
		printf("ERROR: v2xSe_sendReceive returned %d\n", retVal);
		return VTEST_FAIL;
	}

	/* Return CONF as not all required tests implemented yet */
	return VTEST_CONF;
}


/**
 *
 * @brief Test v2xSe_invokeGarbageCollector for expected behaviour
 *
 * This function tests v2xSe_invokeGarbageCollector for expected behaviour
 * The following behaviours are tested:
 *  - success returned when in correct state
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_invokeGarbageCollector(void)
{
	int32_t retVal;
	TypeSW_t statusCode;

/* Test success returned when in correct state */
	/* Move to ACTIVATED state, normal operating mode */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Invoke garbage collector */
	retVal = v2xSe_invokeGarbageCollector(&statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_invokeGarbageCollector returned %d\n",
								retVal);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
}

/**
 *
 * @brief Test v2xSe_getRemainingNvm for expected behaviour
 *
 * This function tests v2xSe_getRemainingNvm for expected behaviour
 * The following behaviours are tested:
 *  - non-zero value returned
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_getRemainingNvm(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	uint32_t remainingNvm;

/* Test non-zero value returned */
	/* Move to CONNECTED state */
	if (setupConnectedState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Get remaining NVM */
	retVal = v2xSe_getRemainingNvm(&remainingNvm, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getRemainingNvm returned %d\n", retVal);
		return VTEST_FAIL;
	}
	printf("Remaining NVM: 0x%x bytes\n",remainingNvm);
	/* Verify non-zero value */
	if (!remainingNvm) {
		printf("ERROR: v2xSe_getRemainingNvm indicated no free NVM\n");
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_getSePhase_keyinject(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	uint8_t phase;

/* Test expected value returned in key injection phase for EU applet */
	/* Move to INIT state */
	if (setupInitState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Remove NVM phase variable to force return to key injection phase */
	if (removeNvmVariable(EU_PHASE_FILENAME) != VTEST_PASS) {
		printf("ERROR: Failed to delete EU phase variable\n");
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state with EU applet */
	if (setupActivatedState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Verify SE phase reading */
	retVal = v2xSe_getSePhase(&phase, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSePhase returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify value read */
	if (phase != V2XSE_KEY_INJECTION_PHASE) {
		printf("ERROR: v2xSe_getSePhase read phase %d\n", phase);
		return VTEST_FAIL;
	}

/* Test expected value returned in key injection phase for US applet */
	/* Move to INIT state */
	if (setupInitState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Remove NVM phase variable to force return to key injection phase */
	if (removeNvmVariable(US_PHASE_FILENAME) != VTEST_PASS) {
		printf("ERROR: Failed to delete US phase variable\n");
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state with US applet */
	if (setupActivatedState(e_US) != VTEST_PASS)
		return VTEST_FAIL;
	/* Verify SE phase reading */
	retVal = v2xSe_getSePhase(&phase, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSePhase returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify value read */
	if (phase != V2XSE_KEY_INJECTION_PHASE) {
		printf("ERROR: v2xSe_getSePhase read phase %d\n", phase);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_getSePhase_normal(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	uint8_t phase;

/* Test expected value returned in normal operating phase for EU applet */
	/* Move to ACTIVATED state, normal operating mode, EU applet */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Verify SE phase reading */
	retVal = v2xSe_getSePhase(&phase, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSePhase returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify value read */
	if (phase != V2XSE_NORMAL_OPERATING_PHASE) {
		printf("ERROR: v2xSe_getSePhase read phase %d\n", phase);
		return VTEST_FAIL;
	}

/* Test expected value returned in normal operating phase for US applet */
	/* Move to ACTIVATED state, normal operating mode, US applet */
	if (setupActivatedNormalState(e_US) != VTEST_PASS)
		return VTEST_FAIL;
	/* Verify SE phase reading */
	retVal = v2xSe_getSePhase(&phase, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSePhase returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify value read */
	if (phase != V2XSE_NORMAL_OPERATING_PHASE) {
		printf("ERROR: v2xSe_getSePhase read phase %d\n", phase);
		return VTEST_FAIL;
	}
	/* No tests failed, return PASS */
	return VTEST_PASS;
}
