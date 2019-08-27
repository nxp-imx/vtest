
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEkeyinjection.h
 *
 * @brief Header file for tests for SE Key Injection (requirements R11.*)
 *
 */

#ifndef SEKEYINJECTION_H
#define SEKEYINJECTION_H

/**
 * List of tests from to be run from SEkeyinjection.c
 * Tests should be listed in order of incrementing test number
 */
#define SE_KEY_INJECTION_TESTS \
	VTEST_DEFINE_TEST(110101, &test_endKeyInjection, \
		"Test v2xSe_endKeyInjection for expected behaviour")\

void test_endKeyInjection(void);

#endif
