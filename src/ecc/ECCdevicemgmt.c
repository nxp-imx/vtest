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
 * @file ECCdevicemgmt.c
 *
 * @brief Tests for ECC device management operations (requirements R1.*)
 *
 */

#include "vtest.h"
#include "ECCdevicemgmt.h"
#include "ecdsa.h"
#include "vtest_async.h"

static volatile int count_async = ASYNC_COUNT_RESET;

/**
 *
 * @brief Positive test of disp_Activate, disp_Deactivate
 *
 */
void ecc_test_activate_deactivate(void)
{

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Test disp_Deactivate when not active
 *
 */
void ecc_test_deactivate_not_active(void)
{
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NOT_INITIATED);
}

/**
 *
 * @brief Test disp_Activate call if already active
 *
 */
void ecc_test_activate_twice(void)
{
	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);
	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NOT_INITIATED);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

