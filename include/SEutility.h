
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

#define SE_UTILITY_TESTS \
	{100101, &test_getRandomNumber, \
		"Test v2xSe_getRandomNumber for expected behaviour"},\
	{100201, &test_getKeyLenFromCurveID, \
		"Test v2xSe_getKeyLenfromCurveID for expected behaviour"},\
	{100301, &test_getSigLenFromHashLen, \
		"Test v2xSe_getSigLenFromHashLen for expected behaviour"},\

int test_getRandomNumber(void);
int test_getKeyLenFromCurveID(void);
int test_getSigLenFromHashLen(void);

#endif
