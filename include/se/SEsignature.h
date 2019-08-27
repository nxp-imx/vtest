
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEsignature.h
 *
 * @brief Header files for tests for SE Signature (requirements R7.*)
 *
 */

#ifndef SESIGNATURE_H
#define SESIGNATURE_H

/**
 * List of tests from to be run from SEsignature.c
 * Tests should be listed in order of incrementing test number
 */
#define SE_SIGNATURE_TESTS \
	VTEST_DEFINE_TEST( 70101, &test_createBaSign, \
		"Test v2xSe_createBaSign for expected behaviour")\
	VTEST_DEFINE_TEST( 70201, &test_createMaSign, \
		"Test v2xSe_createMaSign for expected behaviour")\
	VTEST_DEFINE_TEST( 70301, &test_createRtSignLowLatency, \
		"Test v2xSe_createRtSignLowLatency for expected behaviour")\
	VTEST_DEFINE_TEST( 70401, &test_createRtSign, \
		"Test v2xSe_createRtSign for expected behaviour")\

void test_createBaSign(void);
void test_createMaSign(void);
void test_createRtSign(void);
void test_createRtSignLowLatency(void);

#endif
