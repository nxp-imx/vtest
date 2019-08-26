
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

#define SE_KEY_MANAGEMENT_TESTS \
	{ 60101, &test_generateMaEccKeyPair, \
		"Test v2xSe_generateMaEccKeyPair for expected behaviour"},\
	{ 60301, &test_generateRtEccKeyPair_empty, \
		"Test v2xSe_generateRtEccKeyPair for keys in empty slots"},\
	{ 60301, &test_generateRtEccKeyPair_overwrite, \
		"Test v2xSe_generateRtEccKeyPair for keys in full slots"},\
	{ 60401, &test_deleteRtEccPrivateKey, \
		"Test v2xSe_deleteRtEccPrivateKey for existing keys"},\
	{ 60601, &test_generateBaEccKeyPair_empty, \
		"Test v2xSe_generateBaEccKeyPair for keys in empty slots"},\
	{ 60601, &test_generateBaEccKeyPair_overwrite, \
		"Test v2xSe_generateBaEccKeyPair for keys in full slots"},\
	{ 60701, &test_deleteBaEccPrivateKey, \
		"Test v2xSe_deleteBaEccPrivateKey for existing keys"},\
	{ 60301, &test_deriveRtEccKeyPair_empty, \
		"Test v2xSe_deriveRtEccKeyPair for keys in empty slots"},\
	{ 60302, &test_deriveRtEccKeyPair_overwrite, \
		"Test v2xSe_deriveRtEccKeyPair for keys in full slots"},\

int test_generateMaEccKeyPair(void);
int test_generateRtEccKeyPair_empty(void);
int test_generateRtEccKeyPair_overwrite(void);
int test_deleteRtEccPrivateKey(void);
int test_generateBaEccKeyPair_empty(void);
int test_generateBaEccKeyPair_overwrite(void);
int test_deleteBaEccPrivateKey(void);
int test_deriveRtEccKeyPair_empty(void);
int test_deriveRtEccKeyPair_overwrite(void);

#endif
