
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file testlist.c
 *
 * @brief Defines list of all tests that can be run
 *
 */

#include "vtest.h"
#include "SEdevicemanagement.h"
#include "SEkeymanagement.h"
#include "SEsignature.h"
#include "SEecies.h"
#include "SEdatastorage.h"
#include "SEutility.h"
#include "SEkeyinjection.h"
#include "ECDSAplaceholder.h"

/**
 * @brief Array containing entries for all avialable tests
 *
 * This array containts an entry for each available test.
 * Tests should be placed in the following array in order of test
 * number
 */
testEntry_t allTests[] = {
	ECDSA_PLACEHOLDER_TESTS
	SE_DEVICE_MANAGEMENT_TESTS
	SE_KEY_MANAGEMENT_TESTS
	SE_SIGNATURE_TESTS
	SE_ECIES_TESTS
	SE_DATA_STORAGE_TESTS
	SE_UTILITY_TESTS
	SE_KEY_INJECTION_TESTS
};

/**
 *
 * @brief Utility function get total number of available tests
 *
 * @return total number of available tests
 *
 */
int getNumTests(void)
{
	return sizeof(allTests)/sizeof(testEntry_t);
}
