
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEkeymanagement.h
 *
 * @brief Header file for tests for SE Key Management (requirements R6.*)
 *
 */

#ifndef SEKEYMANAGEMENT_H
#define SEKEYMANAGEMENT_H

/**
 * List of tests from to be run from SEkeymanagement.c
 * Tests should be listed in order of incrementing test number
 */
#define SE_KEY_MANAGEMENT_TESTS \
	VTEST_DEFINE_TEST( 60101, &test_generateMaEccKeyPair, \
		"Test v2xSe_generateMaEccKeyPair for expected behaviour")\
	VTEST_DEFINE_TEST( 60301, &test_generateRtEccKeyPair_empty, \
		"Test v2xSe_generateRtEccKeyPair for keys in empty slots")\
	VTEST_DEFINE_TEST( 60302, &test_generateRtEccKeyPair_overwrite, \
		"Test v2xSe_generateRtEccKeyPair for keys in full slots")\
	VTEST_DEFINE_TEST( 60401, &test_deleteRtEccPrivateKey, \
		"Test v2xSe_deleteRtEccPrivateKey for existing keys")\
	VTEST_DEFINE_TEST( 60601, &test_generateBaEccKeyPair_empty, \
		"Test v2xSe_generateBaEccKeyPair for keys in empty slots")\
	VTEST_DEFINE_TEST( 60602, &test_generateBaEccKeyPair_overwrite, \
		"Test v2xSe_generateBaEccKeyPair for keys in full slots")\
	VTEST_DEFINE_TEST( 60701, &test_deleteBaEccPrivateKey, \
		"Test v2xSe_deleteBaEccPrivateKey for existing keys")\
	VTEST_DEFINE_TEST( 60901, &test_deriveRtEccKeyPair_empty, \
		"Test v2xSe_deriveRtEccKeyPair for keys in empty slots")\
	VTEST_DEFINE_TEST( 60902, &test_deriveRtEccKeyPair_overwrite, \
		"Test v2xSe_deriveRtEccKeyPair for keys in full slots")\
	VTEST_DEFINE_TEST( 61001, &test_activateRtKeyForSigning, \
		"Test v2xSe_activateRtKeyForSigning for normal operation")\

void test_generateMaEccKeyPair(void);
void test_generateRtEccKeyPair_empty(void);
void test_generateRtEccKeyPair_overwrite(void);
void test_deleteRtEccPrivateKey(void);
void test_generateBaEccKeyPair_empty(void);
void test_generateBaEccKeyPair_overwrite(void);
void test_deleteBaEccPrivateKey(void);
void test_deriveRtEccKeyPair_empty(void);
void test_deriveRtEccKeyPair_overwrite(void);
void test_activateRtKeyForSigning(void);

#endif
