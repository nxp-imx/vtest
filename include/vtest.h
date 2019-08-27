
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

#define VTEST_PASS	(0)
#define VTEST_FAIL	(1)
#define VTEST_CONF	(32)

/** Structure describing the status of the currently running test */
typedef struct {
	/** Number of test cases run */
	int numTestsRun;
	/** Number of test cases skipped */
	int numTestsSkipped;
	/** Number of sucessful test cases */
	int numTestsPass;
	/** Number of failing test cases */
	int numTestsFail;
	/** Number of blocked test cases */
	int numTestsConf;
	/** Total number of subtest run */
	int numSubTestsRun;
	/** Total number of subtests that failed */
	int numSubTestsFail;
} overallTestStatus_t;

/** Structure describing the status of the currently running test */
typedef struct {
	/** Number of subtests run so far */
	int currentSubTestsRun;
	/** Number of subtests failed so far */
	int currentSubTestsFail;
	/** Set to 1 if any part of the test is blocked */
	int currentTestConfFlagged;
} currentTestStatus_t;

#define VTEST_DEFINE_TEST(num, fn, name)	{num, fn, name},

void outputLog(const char *const fileName, const int lineNumber,
					const char *const format, ...);

#define VTEST_LOG(format, ...)	\
		outputLog( __FILE__, __LINE__, format, __VA_ARGS__)

void checkResult(const char *const fileName,
		const int lineNumber, int actual, int expected);

#define VTEST_CHECK_RESULT(got, exp) \
	checkResult( __FILE__, __LINE__, got, exp)

#define VTEST_START_TEST_CASE(num, name)			\
do {								\
	currentTestStatus = (currentTestStatus_t){0,0,0};	\
	printf("Running test %06d: %s\n", num, name);		\
} while (0)

#define VTEST_END_TEST_CASE()					\
do {								\
	overallTestStatus.numSubTestsRun +=			\
			currentTestStatus.currentSubTestsRun;	\
	overallTestStatus.numSubTestsFail +=			\
			currentTestStatus.currentSubTestsFail;	\
	overallTestStatus.numTestsRun++;			\
	if (currentTestStatus.currentSubTestsFail) {		\
		overallTestStatus.numTestsFail++;		\
	} else if (currentTestStatus.currentTestConfFlagged){	\
		overallTestStatus.numTestsConf++;		\
	} else {						\
		overallTestStatus.numTestsPass++;		\
	}							\
} while (0)

#define VTEST_SKIP_TEST_CASE()					\
do {								\
	overallTestStatus.numTestsSkipped++;			\
} while (0)

void flagConf(void);
#define VTEST_FLAG_CONF		flagConf

/** Structure describing a test that can be run */
typedef struct {
	/**
	 * Test number, derived from requirements number
	 * Format is XXYYZZ, where requirement number is
	 * RXX.YY, and ZZ is a number that increments for
	 * each test that tests the given requirement (a
	 * requirement can have multiple tests)
	 * Note that XX should be abbreviated to X in the
	 * definition if the requirement only has 1 digit
	 * as entering 0X casts the number as octal
	 */
	int testNum;
	/** Function to call to run the test */
	void (*testFn)(void);
	/** String describing the test */
	char* testName;
} testEntry_t;

#endif
