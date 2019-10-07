
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
 * @file vtest_async.c
 *
 * @brief Header file for V2X test asynchronous application
 *
 */

#ifndef VTEST_ASYNC_H
#define VTEST_ASYNC_H

#include <stdio.h>
#include <unistd.h>
#include "vtest.h"

/* Count value */
#define ASYNC_COUNT_RESET 0

/* Define time unit in us*/
#define TIME_UNIT_1_MS  1000
#define TIME_UNIT_10_MS 10000

/* This is used to call async API */
#define VTEST_CHECK_RESULT_ASYNC_INC(got, exp, count)                      \
do {                                                                       \
	checkResult( __FILE__, __LINE__, got, exp);                        \
	count++;                                                           \
} while (0)                                                                \

/* This is used to signal a return from async API calls */
#define VTEST_CHECK_RESULT_ASYNC_DEC(got, exp, count)                      \
do {                                                                       \
	checkResult( __FILE__, __LINE__, got, exp);                        \
	count--;                                                           \
} while (0)                                                                \

/* This is used to wait returns from async API calls */
#define VTEST_CHECK_RESULT_ASYNC_WAIT(count, time)                         \
do {                                                                       \
	usleep(time);                                                      \
	if (count > 0)                                                     \
		printf("%d missing responses!\n", count);                  \
	checkResult( __FILE__, __LINE__, count, ASYNC_COUNT_RESET);        \
	count = ASYNC_COUNT_RESET;                                         \
} while (0)                                                                \

#endif
