
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEutility.h
 *
 * @brief Header file for tests for SE Utility (requirements R10.*)
 *
 */

#ifndef SEUTILITY_H
#define SEUTILITY_H

/**
 * List of tests from to be run from SEutlity.c
 * Tests should be listed in order of incrementing test number
 */
#define SE_UTILITY_TESTS \
	VTEST_DEFINE_TEST(100101, &test_getRandomNumber, \
		"Test v2xSe_getRandomNumber for expected behaviour")\
	VTEST_DEFINE_TEST(100201, &test_getKeyLenFromCurveID, \
		"Test v2xSe_getKeyLenfromCurveID for expected behaviour")\
	VTEST_DEFINE_TEST(100301, &test_getSigLenFromHashLen, \
		"Test v2xSe_getSigLenFromHashLen for expected behaviour")\

void test_getRandomNumber(void);
void test_getKeyLenFromCurveID(void);
void test_getSigLenFromHashLen(void);

#endif
