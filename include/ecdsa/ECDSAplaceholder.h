
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file ECDSAplaceholder.h
 *
 * @brief Dummy file to be replaced by header file for ECDSA tests
 *
 */

#ifndef ECDSAPLACEHOLDER_H
#define ECDSAPLACEHOLDER_H

/**
 * List of tests from to be run from ECDSAplaceholder.c
 * Tests should be listed in order of incrementing test number
 */
#define ECDSA_PLACEHOLDER_TESTS \
	VTEST_DEFINE_TEST(10101, &ECSDA_placeholder, \
		"ECDSA placeholder - to be replaced")\

void ECSDA_placeholder(void);

#endif
