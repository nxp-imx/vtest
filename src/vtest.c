
/*
 * Copyright 2019 NXP
 */

/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON  ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS  SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 *
 * @file vtest.c
 *
 * @brief Core implementation of V2X test application
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vtest.h"
#include "version.h"

/** Status of the currently running test caes */
currentTestStatus_t currentTestStatus;
/** Combined status of all tests run */
overallTestStatus_t overallTestStatus = {0,0,0,0,0,0,0};

extern testEntry_t allTests[];
int getNumTests(void);
int seClean(void);

/**
 *
 * @brief Extract numerical test number from string
 *
 * Extract numerical test number from string taken from the command line
 * when vtest was started.  Note that test number 1 is not allowed as it
 * corresponds to VTEST_FAIL, but as this would correspond to requirement
 * R0.0 which does not exist, this is acceptable.
 *
 * @param testStr string from command line that should contain test number
 *
 * @return test number, or VTEST_FAIL
 *
 */
int getTestNum(const char *testStr)
{
	long convNum;

	convNum = strtol(testStr, NULL, 10);
	if ((convNum <= BEFORE_FIRST_TEST) ||
		(convNum >= AFTER_LAST_TEST)) {
		printf("ERROR: invalid test number: %s\n",testStr);
		return VTEST_FAIL;
	}

	return (int)convNum;
}

/**
 *
 * @brief Output log message to console
 *
 * This function outputs a log message to the console during test execution.
 * The filename and linenumber generating the log is printed first, followed
 * by the provided log message on the next line.
 *
 * @param fileName name of the source file generating the log message
 * @param lineNumber source line number generating the log message
 * @param format the string to format the log message, in printf style
 *
 */
void outputLog(const char *const fileName, const int lineNumber,
					const char *const format, ...)
{
	va_list ap;

	va_start(ap, format);
	printf("LOG from %s:%d:\n ", fileName, lineNumber);
	vprintf(format, ap);
	printf("\n");
	va_end(ap);
	fflush(stdout);
}

/**
 *
 * @brief Utility function to check the result of a function call
 *
 * This function checks the result of a function call and updates the
 * subtest counter appropriately
 *
 * @param fileName name of source file this function is called from
 * @param lineNumber source line number this function is called from
 * @param actual the result returned by the function call under test
 * @param expected the expected result of the function call under test
 *
 */
void checkResult(const char *const fileName,
		const int lineNumber, int actual, int expected)
{
	currentTestStatus.currentSubTestsRun++;
	if (actual != expected) {
		currentTestStatus.currentSubTestsFail++;
		printf("ERROR: %s:%d expected %d, got %d\n", fileName,
						lineNumber, expected, actual);
	}
}

/**
 *
 * @brief Utility function to flag that a test cannot be completed
 *
 */
void flagConf(void)
{
	currentTestStatus.currentTestConfFlagged = 1;
}

/**
 *
 * @brief The main function of the vtest program
 *
 * This function parses the vtest command line parameters and runs the
 * requested tests
 *
 * @param argc the number of command line arguments, including program name
 * @param argv an array giving the command line arguments
 *
 * @return 1 if any tests failed, else 32 if test blocked, else 0
 *
 */
int main(int argc, char* argv[])
{
	int i;
	int minTest = BEFORE_FIRST_TEST;
	int maxTest = AFTER_LAST_TEST;
	int numDefinedTests = getNumTests();
	char strMinTest[7]; /* 6-digits test number + null byte */
	char strMaxTest[7]; /* 6-digits test number + null byte */

	printf("vtest version "VERSION": Start\n");

	if (argc == 1) {
		printf("Running all tests\n");
	} else if (argc == 2) {
		if (!strcmp(argv[1], "clean"))
			return seClean();
		if (strlen(argv[1]) == 2) {
			/*
			 * If only the test suite prefix is specified (i.e. the
			 * first two digits XX), this will be parsed to run the
			 * full range of tests between XX0101 XX9999.
			 * e.g. "$ vtest 01" will run all the 01 test suite,
			 * from 010101 to 019999.
			 */
			printf("Running test suite %s\n", argv[1]);
			/* Copy first two digits + null byte */
			strncpy(strMinTest, argv[1], 3);
			/*
			 * Concatenate 0101 to have the first possible test of
			 * the test suite. strncat adds a null byte at the end
			 */
			strncat(strMinTest, "0101", 5);
			minTest = getTestNum(strMinTest);
			/* Copy first two digits + null byte */
			strncpy(strMaxTest, argv[1], 3);
			/*
			 * Concatenate 9999 to have the last possible test of
			 * the test suite. strncat adds a null byte at the end
			 */
			strncat(strMaxTest, "9999", 5);
			maxTest = getTestNum(strMaxTest);
		} else {
			printf("Running single test\n");
			minTest = getTestNum(argv[1]);
			maxTest = minTest;
		}
	} else if (argc == 3) {
		printf("Running range of tests\n");
		minTest = getTestNum(argv[1]);
		maxTest = getTestNum(argv[2]);
	} else {
		printf("ERROR: incorrect number of parameters\n");
		printf("USAGE: vtest\n");
		printf("       vtest [single test num]\n");
		printf("       vtest [first test num] [last test num]\n");
		printf("       vtest clean\n");
		return VTEST_FAIL;
	}

	if ((minTest == VTEST_FAIL) || (maxTest == VTEST_FAIL))
		return VTEST_FAIL;

	for (i = 0; i < numDefinedTests; i++) {
		if ((allTests[i].testNum >= minTest) &&
					(allTests[i].testNum <= maxTest)) {
			VTEST_START_TEST_CASE(allTests[i].testNum,
						allTests[i].testName);
			allTests[i].testFn();
			VTEST_END_TEST_CASE(allTests[i].testNum);
		} else {
			VTEST_SKIP_TEST_CASE();
		}
	}

	printf("\n\nSUMMARY:\n");
	printf("Tests RUN: %d\n",overallTestStatus.numTestsRun);
	printf("Tests SKIPPED: %d\n",overallTestStatus.numTestsSkipped);
	printf("Tests PASS: %d\n",overallTestStatus.numTestsPass);
	printf("Tests CONF: %d\n",overallTestStatus.numTestsConf);
	printf("Tests FAIL: %d\n",overallTestStatus.numTestsFail);
	printf("Subtests RUN: %d\n",overallTestStatus.numSubTestsRun);
	printf("Subtests FAIL: %d\n",overallTestStatus.numSubTestsFail);
	printf("vtest: Done\n");

	if (overallTestStatus.numTestsFail) {
		return VTEST_FAIL;
	} else if (overallTestStatus.numTestsConf ||
					(overallTestStatus.numTestsRun == 0)) {
		return VTEST_CONF;
	} else {
		return VTEST_PASS;
	}
}
