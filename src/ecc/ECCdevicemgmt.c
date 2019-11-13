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
 * @file ECClifecycle.c
 *
 * @brief Tests for ECC life cycle operations (requirements R2.*)
 *
 */

#include "vtest.h"
#include "ECCdevicemgmt.h"
#include "ecc_dispatcher.h"
#include "vtest_async.h"

static volatile int count_async = ASYNC_COUNT_RESET;

/**
 *
 * @brief Positive test of disp_Activate, disp_Deactivate
 *
 */
void ecc_test_activate(void)
{
	disp_DispatcherVersion_t ver;

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);
	VTEST_CHECK_RESULT(disp_getDispatcherVersion(&ver),
		DISP_RETVAL_NO_ERROR);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Test disp_Deactivate when not active
 *
 */
void ecc_test_deactivate_not_active(void)
{
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Test of disp_Deactivate
 *
 */
void ecc_test_deactivate(void)
{
	disp_DispatcherVersion_t ver;

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);
	VTEST_CHECK_RESULT(disp_getDispatcherVersion(&ver),
		DISP_RETVAL_NO_ERROR);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
	VTEST_CHECK_RESULT(disp_getDispatcherVersion(&ver),
		DISP_RETVAL_NOT_INITIATED);
}

/**
 *
 * @brief Positive test of device management API
 *
 */
void ecc_test_get_versions(void)
{
	disp_DispatcherVersion_t ver;

	/* Activate */
	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);

	/* Check dispatcher version */
	VTEST_CHECK_RESULT(disp_getDispatcherVersion(&ver),
		DISP_RETVAL_NO_ERROR);
	VTEST_LOG("disp_getDispatcherVersion: %u.%u.%u\n",
		ver.version[0], ver.version[1], ver.version[2]);
	VTEST_CHECK_RESULT(ver.version[0], DISP_MAJOR_VERSION);
	VTEST_CHECK_RESULT(ver.version[1], DISP_MINOR_VERSION);
	VTEST_CHECK_RESULT(ver.version[2], DISP_PATCH_VERSION);

	/* Check library version */
	VTEST_CHECK_RESULT(disp_getDispatcherLocalRevision(&ver),
		DISP_RETVAL_NO_ERROR);
	VTEST_LOG("disp_getDispatcherLocalRevision: %u.%u.%u\n",
		ver.version[0], ver.version[1], ver.version[2]);
	VTEST_CHECK_RESULT(ver.version[0], LIB_MAJOR_VERSION);
	VTEST_CHECK_RESULT(ver.version[1], LIB_MINOR_VERSION);
	VTEST_CHECK_RESULT(ver.version[2], LIB_PATCH_VERSION);

	/* Check llc-driver version: must be 0.0.0 since is not required */
	VTEST_CHECK_RESULT(disp_getLlcRevision(&ver),
		DISP_RETVAL_NO_ERROR);
	VTEST_LOG("disp_getLlcRevision: %u.%u.%u\n",
		ver.version[0], ver.version[1], ver.version[2]);
	VTEST_CHECK_RESULT(ver.version[0], LLC_MAJOR_VERSION);
	VTEST_CHECK_RESULT(ver.version[1], LLC_MINOR_VERSION);
	VTEST_CHECK_RESULT(ver.version[2], LLC_PATCH_VERSION);

	/* Deactivate */
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
} 

/**
 *
 * @brief Negative test of get version API
 *
 */
void ecc_test_get_versions_negative(void)
{
	disp_DispatcherVersion_t ver;

	VTEST_CHECK_RESULT(disp_getDispatcherVersion(&ver),
		DISP_RETVAL_NOT_INITIATED);
	VTEST_CHECK_RESULT(disp_getLlcRevision(&ver),
		DISP_RETVAL_NOT_INITIATED);
} 

/**
 *
 * @brief Test disp_Activate call if already active
 *
 */
void ecc_test_activate_twice(void)
{
	disp_DispatcherVersion_t ver;

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);
	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);
	VTEST_CHECK_RESULT(disp_getDispatcherVersion(&ver),
		DISP_RETVAL_NO_ERROR);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Test of cputime API
 *
 * From Verification Engine API document v1.03 Sept 9, 2019:
 * This API is retained for API compatibility with MARS. In EVO all requests
 * are sent to HW Executor. Hence the return value is (0, 0, 100)
 *
 */
void ecc_test_cputime(void)
{
	disp_DispatcherSetMaxCpuTime_t t_got = {0, 0, 0};
	disp_DispatcherSetMaxCpuTime_t t_exp = {0, 0, 100};

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);
	t_got = disp_setMaxCpuTime(t_got);

	VTEST_CHECK_RESULT(t_got.threadA_cpu, t_exp.threadA_cpu);
	VTEST_CHECK_RESULT(t_got.threadB_cpu, t_exp.threadB_cpu);
	VTEST_CHECK_RESULT(t_got.evo_load, t_exp.evo_load);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 * @brief   Test of asynchronous cputime API: callback
 *
 * @param[in]  sequence_number       sequence operation id (not used?)
 * @param[out] ret                   returned value by the dispatcher
 *
 */
void ecc_testCputimeAsync_callback(void *sequence_number,
	disp_DispatcherSetMaxCpuTime_t ret)
{
	/*
	 * Functionality not supported, function only present for MARS
	 * compatibility, so cannot verify returned values.
	 * Async framework requires a test, so compare 0 with 0 (at
	 * least it proves the callback was called)
	 */
	VTEST_CHECK_RESULT_ASYNC_DEC(0, 0, count_async);
}


/**
 *
 * @brief Test of asynchronous cputime API
 *
 * From Verification Engine API document v1.03 Sept 9, 2019:
 * This API is retained for API compatibility with MARS. In EVO all requests
 * are sent to HW Executor. disp_setMaxCpuTimeAsync always returns
 * DISP_RETVAL_UNDEFINED_ERROR.
 *
 */
void ecc_test_cputime_async(void)
{
	disp_DispatcherSetMaxCpuTime_t t = {0};

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);
	VTEST_CHECK_RESULT_ASYNC_INC(disp_setMaxCpuTimeAsync((void *)0, t,
					ecc_testCputimeAsync_callback),
					DISP_RETVAL_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

