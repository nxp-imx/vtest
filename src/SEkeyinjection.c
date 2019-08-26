
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEkeyinjection.c
 *
 * @brief Tests for SE Key Injection (requirements R11.*)
 *
 */

#include <stdio.h>
#include <v2xseapi.h>
#include "vtest.h"
#include "SEkeyinjection.h"

/**
 *
 * @brief Test v2xSe_endKeyInjection for expected behaviour
 *
 * This function tests v2xSe_endKeyInjection for expected behaviour
 * The following behaviours are tested:
 *  - key injection correctly ended for EU applet
 *  - key injection correctly ended for US applet
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_endKeyInjection(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	uint8_t phase;

/* Test key injection correctly ended for EU applet */
	/* Move to INIT state */
	if (setupInitState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Remove NVM phase variable to force reset of phase */
	if (removeNvmVariable(EU_PHASE_FILENAME) != VTEST_PASS) {
		printf("ERROR: Failed to delete EU phase variable\n");
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state */
	if (setupActivatedState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Verify SE phase is key injection */
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
	/* End key injection */
	retVal = v2xSe_endKeyInjection(&statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_endKeyInjection returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify SE phase is now in */
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

/* Test key injection correctly ended for US applet */
	/* Move to INIT state */
	if (setupInitState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Remove NVM phase variable to force reset of phase */
	if (removeNvmVariable(US_PHASE_FILENAME) != VTEST_PASS) {
		printf("ERROR: Failed to delete US phase variable\n");
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state */
	if (setupActivatedState(e_US) != VTEST_PASS)
		return VTEST_FAIL;
	/* Verify SE phase is key injection */
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
	/* End key injection */
	retVal = v2xSe_endKeyInjection(&statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_endKeyInjection returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify SE phase is now in */
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
