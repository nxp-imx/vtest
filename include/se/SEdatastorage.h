
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEdatastorage.h
 *
 * @brief Header file for tests for SE Generic Data Storage (requirements R9.*)
 *
 */

#ifndef SEDATASTORAGE_H
#define SEDATASTORAGE_H

/** Test data stored in nvm slot 0 */
#define TEST_STRING_SLOT_0 	"Hi there slot 0"
/** Test data stored in non-zero nvm slot */
#define TEST_STRING_NON_ZERO 	"Hi there non-zero slot"
/** Test data stored in max nvm slot */
#define TEST_STRING_MAX_SLOT	"Hi there max slot"

/**
 * List of tests from to be run from SEdatastorage.c
 * Tests should be listed in order of incrementing test number
 */
#define SE_DATA_STORAGE_TESTS \
	VTEST_DEFINE_TEST( 90101, &test_storeData_getData, \
		"Test v2xSe_storeData for expected behaviour")\
	VTEST_DEFINE_TEST( 90201, &test_storeData_getData, \
		"Test v2xSe_getData for expected behaviour")\
	VTEST_DEFINE_TEST( 90301, &test_deleteData, \
		"Test v2xSe_deleteData for expected behaviour")\

void test_storeData_getData(void);
void test_deleteData(void);

#endif
