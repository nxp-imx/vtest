
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
 * @file SEperformance.h
 *
 * @brief Header file for tests for SE performance (requirements R13.*)
 *
 */

#ifndef SEPERFORMANCE_H
#define SEPERFORMANCE_H

/**
 * List of tests from to be run from SEperformance.c
 * Tests should be listed in order of incrementing test number
 */
#define SE_PERFORMANCE_TESTS \
	VTEST_DEFINE_TEST(130201, &test_sigVerifRate, \
		"Test rate of signature verification")\
	VTEST_DEFINE_TEST(130301, &test_sigGenRate, \
		"Test rate of signature generation")\
	VTEST_DEFINE_TEST(130401, &test_sigVerifLatencyLoaded, \
		"Test latency of signature verification")\
	VTEST_DEFINE_TEST(130402, &test_sigVerifLatencyUnloaded, \
		"Test latency of signature verification")\
	VTEST_DEFINE_TEST(130501, &test_sigGenLatencyLoaded, \
		"Test latency of signature generation")\
	VTEST_DEFINE_TEST(130502, &test_sigGenLatencyUnloaded, \
		"Test latency of signature generation")\

void test_sigVerifRate(void);
void test_sigGenRate(void);
void test_sigVerifLatencyLoaded(void);
void test_sigVerifLatencyUnloaded(void);
void test_sigGenLatencyLoaded(void);
void test_sigGenLatencyUnloaded(void);

/** Number of keys to use for signing in performance tests */
#define NUM_KEYS_PERF_TESTS	5

/** Number of signatures verified during signature verification rate test */
#define SIG_RATE_VERIF_NUM 5000l
/** Signature verification rate pass/fail threshold */
#define SIG_VERIF_RATE_THRESHOLD	2500

/** Number of signatures generated during signature generation rate test */
#define SIG_RATE_GEN_NUM 400l
/** Signature generation rate pass/fail threshold */
#define SIG_GEN_RATE_THRESHOLD		200

/** Number of signatures verified during signature verification latency test */
#define SIG_LATENCY_VERIF_NUM 1000
/** Number of signatures generated during signature generation latency test */
#define SIG_LATENCY_GEN_NUM 1000
/** Init value for min latency (ns) = 100s, 1st measurement should be lower */
#define SIG_LATENCY_MIN_INIT	100000000000
/** Init value for max latency (ns) = 0s, 1st measurement should be higher */
#define SIG_LATENCY_MAX_INIT	0
/** Signature verification latency pass/fail threshold */
#define SIG_VERIF_LATENCY_THRESHOLD	10.0f
/** Signature generation latency pass/fail threshold */
#define SIG_GEN_LATENCY_THRESHOLD	10.0f

/** Test type - sig verif rate */
#define TEST_TYPE_SIG_VERIF_RATE	0
/** Test type - sig gen rate */
#define TEST_TYPE_SIG_GEN_RATE		1
/** Test type - sig verif rate */
#define TEST_TYPE_SIG_VERIF_LATENCY	2
/** Test type - sig gen rate */
#define TEST_TYPE_SIG_GEN_LATENCY	3

/** Test should be with in loaded system */
#define LOADED_TEST		0
/** Test should be with in unloaded system */
#define UNLOADED_TEST		1

#define SETUP_ECDSA_SIG_VERIF_PTRS(loop)				\
do {									\
	verif_pubKey.x = pubKeyArray[(loop - 1) % NUM_KEYS_PERF_TESTS].x;\
	verif_pubKey.y = pubKeyArray[(loop - 1) % NUM_KEYS_PERF_TESTS].y;\
	verif_hash = hashArray[loop - 1].data;				\
	verif_sig.r = sigArray[loop - 1].r;				\
	verif_sig.s = sigArray[loop - 1].s;				\
} while (0)

#define CALCULATE_TIME_DIFF_NS(start, end, diff)			\
do {									\
	diff = (end.tv_sec - start.tv_sec) * 1000000000;		\
	diff += end.tv_nsec;						\
	diff -= start.tv_nsec;						\
} while (0)

#endif
