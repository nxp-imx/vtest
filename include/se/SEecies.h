
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEecies.h
 *
 * @brief Header files for tests for SE ECIES (requirements R8.*)
 *
 */

#ifndef SEECIES_H
#define SEECIES_H

/**
 * List of tests from to be run from SEecies.c
 * Tests should be listed in order of incrementing test number
 */
#define SE_ECIES_TESTS \
	VTEST_DEFINE_TEST( 80101, &test_encryptUsingEcies, \
		"Test v2xSe_encryptUsingEcies for expected behaviour")\
	VTEST_DEFINE_TEST( 80201, &test_decryptUsingRtEcies, \
		"Test v2xSe_decryptUsingRtEcies for expected behaviour")\
	VTEST_DEFINE_TEST( 80301, &test_decryptUsingMaEcies, \
		"Test v2xSe_decryptUsingMaEcies for expected behaviour")\
	VTEST_DEFINE_TEST( 80401, &test_decryptUsingBaEcies, \
		"Test v2xSe_decryptUsingBaEcies for expected behaviour")\

void test_encryptUsingEcies(void);
void test_decryptUsingRtEcies(void);
void test_decryptUsingMaEcies(void);
void test_decryptUsingBaEcies(void);

#endif
