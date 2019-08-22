
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file vtest.c
 *
 * @brief Header file for V2X test application
 *
 */

#ifndef VTEST_H
#define VTEST_H

#define BEFORE_FIRST_TEST	(0)
#define AFTER_LAST_TEST		(1000000)

#define VTEST_PASS	(1)
#define VTEST_FAIL	(-1)
#define VTEST_CONF	(0)

int legacy_test();
int dummy_test_conf();
int dummy_test_pass();
int dummy_test_fail();
int dummy_test_interr();
#define LEGACY_TESTS_TO_REMOVE \
	{1, &legacy_test, "Legacy test - to be re-written"},\
	{2, &dummy_test_conf, "Dummy conf test - to be removed"},\
	{3, &dummy_test_pass, "Dummy passing test - to be removed"},\
	{4, &dummy_test_fail, "Dummy failing test - to be removed"},\
	{5, &dummy_test_interr, "Dummy int err test - to be removed"},\

typedef struct {
	int testNum;
	int (*testFn)(void);
	char* testName;
} testEntry;


#endif
