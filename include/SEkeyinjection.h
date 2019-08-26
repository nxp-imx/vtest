
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

#define SE_KEY_INJECTION_TESTS \
	{110101, &test_endKeyInjection, \
		"Test v2xSe_endKeyInjection for expected behaviour"},\

int test_endKeyInjection(void);

#endif
