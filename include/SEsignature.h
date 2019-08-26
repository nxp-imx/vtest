
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

#define SE_SIGNATURE_TESTS \
	{ 70101, &test_createBaSign, \
		"Test v2xSe_createBaSign for expected behaviour"},\
	{ 70201, &test_createMaSign, \
		"Test v2xSe_createMaSign for expected behaviour"},\
	{ 70301, &test_createRtSignLowLatency, \
		"Test v2xSe_createRtSignLowLatency for expected behaviour"},\
	{ 70401, &test_createRtSign, \
		"Test v2xSe_createRtSign for expected behaviour"},\

int test_createBaSign(void);
int test_createMaSign(void);
int test_createRtSign(void);
int test_createRtSignLowLatency(void);

#endif
