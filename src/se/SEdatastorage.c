
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

#include <string.h>
#include <v2xseapi.h>
#include "vtest.h"
#include "SEmisc.h"
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
 */
void test_storeData_getData(void)
{
	TypeSW_t statusCode;
	uint8_t dataStorage_write[V2XSE_MAX_DATA_SIZE_GSA];
	uint8_t dataStorage_read[V2XSE_MAX_DATA_SIZE_GSA];
	TypeLen_t size;
	TypeInformation_t seInfo;

	/* Move to ACTIVATED state with GS applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU_AND_GS), VTEST_PASS);
	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxDataSlots <= NON_ZERO_SLOT, 0);

/* Test data can be stored and received from slot 0 */
	/* Store test string in slot 0 */
	memcpy(dataStorage_write, TEST_STRING_SLOT_0,
						strlen(TEST_STRING_SLOT_0)+1);
	VTEST_CHECK_RESULT(v2xSe_storeData(SLOT_ZERO,
		strlen(TEST_STRING_SLOT_0)+1, (uint8_t*)TEST_STRING_SLOT_0,
						&statusCode), V2XSE_SUCCESS);
	/* Retrieve stored string from slot 0 */
	VTEST_CHECK_RESULT(v2xSe_getData(SLOT_ZERO, &size, dataStorage_read,
						&statusCode),V2XSE_SUCCESS);
	/* Verify retrieved string */
	VTEST_CHECK_RESULT( (size != (strlen(TEST_STRING_SLOT_0)+1)) ||
		strncmp(TEST_STRING_SLOT_0, (char*)dataStorage_read, size), 0);

/* Test data can be stored and received from non-zero slot */
	/* Store test string in non-zero slot */
	memcpy(dataStorage_write, TEST_STRING_NON_ZERO,
					strlen(TEST_STRING_NON_ZERO)+1);
	VTEST_CHECK_RESULT(v2xSe_storeData(NON_ZERO_SLOT,
		strlen(TEST_STRING_NON_ZERO)+1, (uint8_t*)TEST_STRING_NON_ZERO,
						&statusCode), V2XSE_SUCCESS);
	/* Retrieve stored string from non-zero slot */
	VTEST_CHECK_RESULT(v2xSe_getData(NON_ZERO_SLOT, &size,
				dataStorage_read, &statusCode), V2XSE_SUCCESS);
	/* Verify retrieved string */
	VTEST_CHECK_RESULT( (size != (strlen(TEST_STRING_NON_ZERO)+1)) ||
		strncmp(TEST_STRING_NON_ZERO, (char*)dataStorage_read,	size),
		 							0);

/* Test data can be stored and received from max slot */
	/* Store test string in max slot */
	memcpy(dataStorage_write, TEST_STRING_MAX_SLOT,
					strlen(TEST_STRING_MAX_SLOT)+1);
	VTEST_CHECK_RESULT(v2xSe_storeData(MAX_SLOT,
		strlen(TEST_STRING_MAX_SLOT)+1,	(uint8_t*)TEST_STRING_MAX_SLOT,
						&statusCode), V2XSE_SUCCESS);
	/* Retrieve stored string from max slot */
	VTEST_CHECK_RESULT(v2xSe_getData(MAX_SLOT, &size, dataStorage_read,
						&statusCode), V2XSE_SUCCESS);
	/* Verify retrieved string */
	VTEST_CHECK_RESULT( (size != (strlen(TEST_STRING_MAX_SLOT)+1)) ||
		strncmp(TEST_STRING_MAX_SLOT, (char*)dataStorage_read,	size),
									0);

/* Test data not overwritting when storing to different slot */
	/* Test slot 0 data valid after writes to non-zero and max slots */
	/* Retrieve stored string from slot 0 */
	VTEST_CHECK_RESULT(v2xSe_getData(SLOT_ZERO, &size, dataStorage_read,
						&statusCode), V2XSE_SUCCESS);
	/* Verify retrieved string */
	VTEST_CHECK_RESULT( (size != (strlen(TEST_STRING_SLOT_0)+1)) ||
		strncmp(TEST_STRING_SLOT_0, (char*)dataStorage_read, size), 0);
	/* Test non-zero slot data valid after write to max slot */
	/* Retrieve stored string from non-zero slot */
	VTEST_CHECK_RESULT(v2xSe_getData(NON_ZERO_SLOT, &size,
				dataStorage_read, &statusCode), V2XSE_SUCCESS);
	/* Verify retrieved string */
	VTEST_CHECK_RESULT( (size != (strlen(TEST_STRING_NON_ZERO)+1)) ||
		strncmp(TEST_STRING_NON_ZERO, (char*)dataStorage_read,	size),
									0);

/* Test min size data can be stored and retrieved */
	/* Set up min size data */
	memset(dataStorage_write, TEST_BYTE, V2XSE_MIN_DATA_SIZE_GSA);
	/* Store test string */
	VTEST_CHECK_RESULT(v2xSe_storeData(SLOT_ZERO, V2XSE_MIN_DATA_SIZE_GSA,
			dataStorage_write, &statusCode), V2XSE_SUCCESS);
	/* Retrieve stored string */
	VTEST_CHECK_RESULT(v2xSe_getData(SLOT_ZERO, &size, dataStorage_read,
						&statusCode), V2XSE_SUCCESS);
	/* Verify retrieved string */
	VTEST_CHECK_RESULT( (size != V2XSE_MIN_DATA_SIZE_GSA) ||
			memcmp(dataStorage_write, dataStorage_read, size), 0);

/* Test max size data can be stored and retrieved */
	/* Set up min size data */
	memset(dataStorage_write, TEST_BYTE, V2XSE_MAX_DATA_SIZE_GSA);
	/* Store test string */
	VTEST_CHECK_RESULT(v2xSe_storeData(SLOT_ZERO, V2XSE_MAX_DATA_SIZE_GSA,
			dataStorage_write, &statusCode), V2XSE_SUCCESS);
	/* Retrieve stored string from slot 0 */
	VTEST_CHECK_RESULT(v2xSe_getData(SLOT_ZERO, &size, dataStorage_read,
						&statusCode), V2XSE_SUCCESS);
	/* Verify retrieved string */
	VTEST_CHECK_RESULT( (size != V2XSE_MAX_DATA_SIZE_GSA) ||
			memcmp(dataStorage_write, dataStorage_read, size), 0);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_deleteData for expected behaviour
 *
 * This function tests v2xSe_storeData & v2xSe_getData for expected behaviour
 * The following behaviours are tested:
 *  - data is present before delete and absent after delete
 *
 */
void test_deleteData(void)
{
	TypeSW_t statusCode;
	uint8_t dataStorage_write[V2XSE_MAX_DATA_SIZE_GSA];
	uint8_t dataStorage_read[V2XSE_MAX_DATA_SIZE_GSA];
	TypeLen_t size;

	/* Move to ACTIVATED state with GS applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU_AND_GS), VTEST_PASS);

/* Test data is present before delete and absent after delete */
	/* Set up min size data */
	memset(dataStorage_write, TEST_BYTE, V2XSE_MIN_DATA_SIZE_GSA);
	/* Store test string */
	VTEST_CHECK_RESULT(v2xSe_storeData(SLOT_ZERO, V2XSE_MIN_DATA_SIZE_GSA,
			dataStorage_write, &statusCode), V2XSE_SUCCESS);
	/* Verify slot is occupied */
	VTEST_CHECK_RESULT(v2xSe_getData(SLOT_ZERO, &size, dataStorage_read,
						&statusCode), V2XSE_SUCCESS);
	/* Delete data in slot */
	VTEST_CHECK_RESULT(v2xSe_deleteData(SLOT_ZERO, &statusCode),
								V2XSE_SUCCESS);
	/* Verify failure when trying to retrieve deleted data */
	VTEST_CHECK_RESULT(v2xSe_getData(SLOT_ZERO, &size, dataStorage_read,
						&statusCode), V2XSE_FAILURE);
	VTEST_CHECK_RESULT(statusCode, V2XSE_WRONG_DATA);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}
