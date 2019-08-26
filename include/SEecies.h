
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

#define SE_ECIES_TESTS \
	{ 80101, &test_encryptUsingEcies, \
		"Test v2xSe_encryptUsingEcies for expected behaviour"},\
	{ 80201, &test_decryptUsingRtEcies, \
		"Test v2xSe_decryptUsingRtEcies for expected behaviour"},\
	{ 80301, &test_decryptUsingMaEcies, \
		"Test v2xSe_decryptUsingMaEcies for expected behaviour"},\
	{ 80401, &test_decryptUsingBaEcies, \
		"Test v2xSe_decryptUsingBaEcies for expected behaviour"},\

int test_encryptUsingEcies(void);
int test_decryptUsingRtEcies(void);
int test_decryptUsingMaEcies(void);
int test_decryptUsingBaEcies(void);

#endif
