
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
	{110101, &key_injection_dummy, "Key injection placeholder"},\

int key_injection_dummy(void);

#endif
