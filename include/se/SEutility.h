
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
 * @file SEutility.h
 *
 * @brief Header file for tests for SE Utility (requirements R10.*)
 *
 */

#ifndef SEUTILITY_H
#define SEUTILITY_H

/**
 * List of tests from to be run from SEutlity.c
 * Tests should be listed in order of incrementing test number
 */
#define SE_UTILITY_TESTS \
	VTEST_DEFINE_TEST(100101, &test_getRandomNumber, \
		"Test v2xSe_getRandomNumber for expected behaviour")\
	VTEST_DEFINE_TEST(100201, &test_getKeyLenFromCurveID, \
		"Test v2xSe_getKeyLenfromCurveID for expected behaviour")\
	VTEST_DEFINE_TEST(100301, &test_getSigLenFromHashLen, \
		"Test v2xSe_getSigLenFromHashLen for expected behaviour")\

void test_getRandomNumber(void);
void test_getKeyLenFromCurveID(void);
void test_getSigLenFromHashLen(void);

#endif
