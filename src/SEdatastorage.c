
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEdatastorage.c
 *
 * @brief Tests for SE Generic Data Storage (requirements R9.*)
 *
 */

#include <stdio.h>
#include <string.h>
#include <v2xseapi.h>
#include "vtest.h"
#include "SEdatastorage.h"

/**
 *
 * @brief Test v2xSe_storeData & v2xSe_getData for expected behaviour
 *
 * This function tests v2xSe_storeData & v2xSe_getData for expected behaviour
 * The following behaviours are tested:
 *  - data can be stored and retrieved from slot 0
 *  - data can be stored and retrieved from non-zero slot
 *  - data can be stored and retrieved from max slot
 *  - data not overwritten when storing to different slot
 *  - min size data can be stored and retrieved
 *  - max size data can be stored and retrieved
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_storeData_getData(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	uint8_t dataStorage_write[V2XSE_MAX_DATA_SIZE_GSA];
	uint8_t dataStorage_read[V2XSE_MAX_DATA_SIZE_GSA];
	TypeLen_t size;
	TypeInformation_t seInfo;

	/* Move to ACTIVATED state with GS applet */
	if (setupActivatedState(e_EU_AND_GS) != VTEST_PASS)
		return VTEST_FAIL;

	/* Get SE info, to know max data slot available */
	retVal = v2xSe_getSeInfo(&statusCode, &seInfo);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_getSeInfo returned %d\n", retVal);
		return VTEST_FAIL;
	}
	if (seInfo.maxDataSlots <= NON_ZERO_SLOT) {
		printf("ERROR: Only %d slots, test needs modification\n",
								retVal);
		return VTEST_FAIL;
	}

/* Test data can be stored and received from slot 0 */
	/* Store test string in slot 0 */
	memcpy(dataStorage_write, TEST_STRING_SLOT_0,
						strlen(TEST_STRING_SLOT_0)+1);
	retVal = v2xSe_storeData(SLOT_ZERO, strlen(TEST_STRING_SLOT_0)+1,
					TEST_STRING_SLOT_0, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_storeData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Retrieve stored string from slot 0 */
	retVal = v2xSe_getData(SLOT_ZERO, &size, dataStorage_read,
								&statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_storeData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify retrieved string */
	if ( (size != (strlen(TEST_STRING_SLOT_0)+1)) ||
				strncmp(TEST_STRING_SLOT_0, dataStorage_read,
								size)) {
		printf("ERROR: Retrieved string does not match\n");
		return VTEST_FAIL;
	}

/* Test data can be stored and received from non-zero slot */
	/* Store test string in non-zero slot */
	memcpy(dataStorage_write, TEST_STRING_NON_ZERO,
					strlen(TEST_STRING_NON_ZERO)+1);
	retVal = v2xSe_storeData(NON_ZERO_SLOT, strlen(TEST_STRING_NON_ZERO)+1,
					TEST_STRING_NON_ZERO, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_storeData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Retrieve stored string from non-zero slot */
	retVal = v2xSe_getData(NON_ZERO_SLOT, &size, dataStorage_read,
								&statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_storeData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify retrieved string */
	if ( (size != (strlen(TEST_STRING_NON_ZERO)+1)) ||
				strncmp(TEST_STRING_NON_ZERO, dataStorage_read,
								size)) {
		printf("ERROR: Retrieved string does not match\n");
		return VTEST_FAIL;
	}

/* Test data can be stored and received from max slot */
	/* Store test string in max slot */
	memcpy(dataStorage_write, TEST_STRING_MAX_SLOT,
					strlen(TEST_STRING_MAX_SLOT)+1);
	retVal = v2xSe_storeData(MAX_SLOT, strlen(TEST_STRING_MAX_SLOT)+1,
					TEST_STRING_MAX_SLOT, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_storeData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Retrieve stored string from max slot */
	retVal = v2xSe_getData(MAX_SLOT, &size, dataStorage_read,
								&statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_storeData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify retrieved string */
	if ( (size != (strlen(TEST_STRING_MAX_SLOT)+1)) ||
				strncmp(TEST_STRING_MAX_SLOT, dataStorage_read,
								size)) {
		printf("ERROR: Retrieved string does not match\n");
		return VTEST_FAIL;
	}

/* Test data not overwritting when storing to different slot */
	/* Test slot 0 data valid after writes to non-zero and max slots */
	/* Retrieve stored string from slot 0 */
	retVal = v2xSe_getData(SLOT_ZERO, &size, dataStorage_read,
								&statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_storeData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify retrieved string */
	if ( (size != (strlen(TEST_STRING_SLOT_0)+1)) ||
			strncmp(TEST_STRING_SLOT_0, dataStorage_read, size)) {
		printf("ERROR: Retrieved string was corrupted\n");
		return VTEST_FAIL;
	}
	/* Test non-zero slot data valid after write to max slot */
	/* Retrieve stored string from non-zero slot */
	retVal = v2xSe_getData(NON_ZERO_SLOT, &size, dataStorage_read,
								&statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_storeData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify retrieved string */
	if ( (size != (strlen(TEST_STRING_NON_ZERO)+1)) ||
				strncmp(TEST_STRING_NON_ZERO, dataStorage_read,
								size)) {
		printf("ERROR: Retrieved string was corrupted\n");
		return VTEST_FAIL;
	}

/* Test min size data can be stored and retrieved */
	/* Set up min size data */
	memset(dataStorage_write, TEST_BYTE, V2XSE_MIN_DATA_SIZE_GSA);
	/* Store test string */
	retVal = v2xSe_storeData(SLOT_ZERO, V2XSE_MIN_DATA_SIZE_GSA,
					dataStorage_write, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_storeData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Retrieve stored string */
	retVal = v2xSe_getData(SLOT_ZERO, &size, dataStorage_read,
								&statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_storeData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify retrieved string */
	if ( (size != V2XSE_MIN_DATA_SIZE_GSA) ||
			memcmp(dataStorage_write, dataStorage_read, size)) {
		printf("ERROR: Retrieved string does not match\n");
		return VTEST_FAIL;
	}

/* Test max size data can be stored and retrieved */
	/* Set up min size data */
	memset(dataStorage_write, TEST_BYTE, V2XSE_MAX_DATA_SIZE_GSA);
	/* Store test string */
	retVal = v2xSe_storeData(SLOT_ZERO, V2XSE_MAX_DATA_SIZE_GSA,
					dataStorage_write, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_storeData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Retrieve stored string from slot 0 */
	retVal = v2xSe_getData(SLOT_ZERO, &size, dataStorage_read,
								&statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_storeData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify retrieved string */
	if ( (size != V2XSE_MAX_DATA_SIZE_GSA) ||
			memcmp(dataStorage_write, dataStorage_read, size)) {
		printf("ERROR: Retrieved string does not match\n");
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
}

/**
 *
 * @brief Test v2xSe_deleteData for expected behaviour
 *
 * This function tests v2xSe_storeData & v2xSe_getData for expected behaviour
 * The following behaviours are tested:
 *  - data is present before delete and absent after delete
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_deleteData(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	uint8_t dataStorage_write[V2XSE_MAX_DATA_SIZE_GSA];
	uint8_t dataStorage_read[V2XSE_MAX_DATA_SIZE_GSA];
	TypeLen_t size;

	/* Move to ACTIVATED state with GS applet */
	if (setupActivatedState(e_EU_AND_GS) != VTEST_PASS)
		return VTEST_FAIL;

/* Test data is present before delete and absent after delete */
	/* Set up min size data */
	memset(dataStorage_write, TEST_BYTE, V2XSE_MIN_DATA_SIZE_GSA);
	/* Store test string */
	retVal = v2xSe_storeData(SLOT_ZERO, V2XSE_MIN_DATA_SIZE_GSA,
					dataStorage_write, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_storeData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify slot is occupied */
	retVal = v2xSe_getData(SLOT_ZERO, &size, dataStorage_read,
								&statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_storeData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Delete data in slot */
	retVal = v2xSe_deleteData(SLOT_ZERO, &statusCode);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_deleteData returned %d\n", retVal);
		return VTEST_FAIL;
	}
	/* Verify failure when trying to retrieve deleted data */
	retVal = v2xSe_getData(SLOT_ZERO, &size, dataStorage_read,
								&statusCode);
	if (retVal != V2XSE_FAILURE) {
		printf("ERROR: v2xSe_getData did not fail, returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	if (statusCode != V2XSE_WRONG_DATA) {
		printf("ERROR: v2xSe_getData give incorrec status code %d\n",
								statusCode);
		return VTEST_FAIL;
	}

	/* No tests failed, return PASS */
	return VTEST_PASS;
}
