
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file vtest.c
 *
 * @brief Core implementation of V2X test application
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <v2xseapi.h>
#include "vtest.h"
#include "SEdevicemanagement.h"
#include "SEkeymanagement.h"
#include "SEsignature.h"
#include "SEecies.h"
#include "SEdatastorage.h"
#include "SEutility.h"
#include "SEkeyinjection.h"

testEntry allTests[] = {
	SE_DEVICE_MANAGEMENT_TESTS
	SE_KEY_MANAGEMENT_TESTS
	SE_SIGNATURE_TESTS
	SE_ECIES_TESTS
	SE_DATA_STORAGE_TESTS
	SE_UTILITY_TESTS
	SE_KEY_INJECTION_TESTS
};

int getTestNum(const char *testStr)
{
	long convNum;

	convNum = strtol(testStr, NULL, 10);
	if ((convNum <= BEFORE_FIRST_TEST) ||
		(convNum >= AFTER_LAST_TEST)) {
		printf("ERROR: invalid test number: %s\n",testStr);
		return VTEST_FAIL;
	}

	return (int)convNum;
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
		printf("ERROR: v2xSe_reset returned %d\n", retVal);
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
		printf("ERROR: v2xSe_reset returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Move to CONNECTED state */
	retVal = v2xSe_connect();
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_connect returned %d\n", retVal);
		return VTEST_FAIL;
	}
	return VTEST_PASS;
}

/**
 *
 * @brief Utility function to place system in ACTIVATED state
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
		printf("ERROR: v2xSe_reset returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state */
	retVal = v2xSe_activate(appId, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_activate returned %d\n", retVal);
		return VTEST_FAIL;
	}
	return VTEST_PASS;
}

/**
 *
 * @brief Utility function to place system in ACTIVATED state, normal phase
 *
 * @return VTEST_PASS or VTEST_FAIL
 *
 */
int setupActivatedNormalState(appletSelection_t appId)
{
	int32_t retVal;
	TypeSW_t statusCode;
	uint8_t phase;

	/* Move to INIT state first as known starting point */
	retVal = v2xSe_reset();
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_reset returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state */
	retVal = v2xSe_activate(appId, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_activate returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Check if already normal operating phase */
	retVal = v2xSe_getSePhase(&phase, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSePhase returned %d\n", retVal);
		return VTEST_FAIL;
	}
	if (phase == V2XSE_NORMAL_OPERATING_PHASE)
		return VTEST_PASS;

	/* Need to end key injection */
	retVal = v2xSe_endKeyInjection(&statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_endKeyInjection returned %d\n", retVal);
		return VTEST_FAIL;
	}
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


int main(int argc, char* argv[])
{
	int i;
	int minTest = BEFORE_FIRST_TEST;
	int maxTest = AFTER_LAST_TEST;

	int numTestsRun = 0;
	int numTestsSkipped = 0;
	int numTestsPass = 0;
	int numTestsFail = 0;
	int numTestsConf = 0;
	int numInternalErrors = 0;

	printf("vtest: Start\n");

	if (argc == 1) {
		printf("Running all tests\n");
	} else if (argc == 2) {
		printf("Running single test\n");
		minTest = getTestNum(argv[1]);
		maxTest = minTest;
	} else if (argc == 3) {
		printf("Running range of tests\n");
		minTest = getTestNum(argv[1]);
		maxTest = getTestNum(argv[2]);
	} else {
		printf("ERROR: incorrect number of parameters\n");
		printf("USAGE: vtest\n");
		printf("       vtest [single test num]\n");
		printf("       vtest [first test num] [last test num]\n");
		return -1;
	}

	if ((minTest == VTEST_FAIL) || (maxTest == VTEST_FAIL))
		return VTEST_FAIL;

	for (i = 0; i < (sizeof(allTests)/sizeof(testEntry)); i++) {
		if ((allTests[i].testNum >= minTest) &&
					(allTests[i].testNum <= maxTest)) {
			int result;
			numTestsRun++;
			printf("Running test %06d: %s\n",allTests[i].testNum,
							allTests[i].testName);
			result = allTests[i].testFn();
			switch (result) {
				case VTEST_PASS:
					numTestsPass++;
					printf("Test result: PASS\n");
					break;
				case VTEST_FAIL:
					numTestsFail++;
					printf("Test result: FAIL\n");
					break;
				case VTEST_CONF:
					numTestsConf++;
					printf("Test result: CONF\n");
					break;
				default:
					numInternalErrors++;
					printf("Internal error\n");
					break;
			}
		} else {
			numTestsSkipped++;
		}
	}

	printf("\n\nSUMMARY:\n");
	printf("Tests RUN: %d\n",numTestsRun);
	printf("Tests SKIPPED: %d\n",numTestsSkipped);
	printf("Internal Errors: %d\n",numInternalErrors);
	printf("Tests PASS: %d\n",numTestsPass);
	printf("Tests CONF: %d\n",numTestsConf);
	printf("Tests FAIL: %d\n",numTestsFail);
	printf("vtest: Done\n");
	return VTEST_PASS;
}
