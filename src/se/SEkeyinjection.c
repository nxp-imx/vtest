
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
 * @file SEkeyinjection.c
 *
 * @brief Tests for SE Key Injection (requirements R11.*)
 *
 */

#include <v2xSe.h>
#include "vtest.h"
#include "SEmisc.h"
#include "SEkeyinjection.h"

/**
 *
 * @brief Test v2xSe_endKeyInjection for expected behaviour
 *
 * This function tests v2xSe_endKeyInjection for expected behaviour
 * The following behaviours are tested:
 *  - key injection correctly ended for EU applet
 *  - key injection correctly ended for US applet
 *
 */
void test_endKeyInjection(void)
{
	TypeSW_t statusCode;
	uint8_t phase;

/* Test key injection correctly ended for EU applet */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of phase */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state with security level 5 */
	VTEST_CHECK_RESULT(setupActivatedStateSecurityLevel5(e_EU), VTEST_PASS);
	/* Verify SE phase is key injection */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_SUCCESS);
	/* Verify value read */
	VTEST_CHECK_RESULT(phase, V2XSE_KEY_INJECTION_PHASE);
	/* End key injection */
	VTEST_CHECK_RESULT(v2xSe_endKeyInjection(&statusCode), V2XSE_SUCCESS);
	/* Verify SE phase is now in */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_SUCCESS);
	/* Verify value read */
	VTEST_CHECK_RESULT(phase, V2XSE_NORMAL_OPERATING_PHASE);

/* Test key injection correctly ended for US applet */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of phase */
	VTEST_CHECK_RESULT(removeNvmVariable(US_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state with security level 5 */
	VTEST_CHECK_RESULT(setupActivatedStateSecurityLevel5(e_US), VTEST_PASS);
	/* Verify SE phase is key injection */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_SUCCESS);
	/* Verify value read */
	VTEST_CHECK_RESULT(phase, V2XSE_KEY_INJECTION_PHASE);
	/* End key injection */
	VTEST_CHECK_RESULT(v2xSe_endKeyInjection(&statusCode), V2XSE_SUCCESS);
	/* Verify SE phase is now in */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_SUCCESS);
	/* Verify value read */
	VTEST_CHECK_RESULT(phase, V2XSE_NORMAL_OPERATING_PHASE);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}
