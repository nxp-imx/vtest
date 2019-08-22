
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
	{ 60101, &key_management_dummy, "Key management placeholder"},\

int key_management_dummy(void);

#endif
