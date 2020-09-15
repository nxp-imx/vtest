/*
 * Copyright 2020 NXP
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
 * @file SEsm2_eces.c
 *
 * @brief Tests for SE SM2 ECES (requirements R18.*)
 *
 */

#include <v2xSe.h>
#include "vtest.h"
#include "SEmisc.h"
#include "SEsm2_eces.h"
#include <stdio.h>

/** SM2 ECES encrypt test vector - input message */
static TypePlainText_t sm2_eces_msg = {
	.data = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
	}
};
/** SM2 ECES input message size */
#define SM2_ECES_MSG_SIZE 16

/** SM2 Public Key */
static TypePublicKey_t sm2_eces_pub_key = {
	.x = {
		0x39, 0x25, 0xf1, 0xf7, 0x82, 0x6e, 0xf5, 0x8e,
		0x37, 0x81, 0x1f, 0xa4, 0xe2, 0xbe, 0xab, 0xd7,
		0xb8, 0x01, 0x21, 0x54, 0x5b, 0x14, 0xdc, 0x97,
		0xc6, 0x3a, 0xd2, 0x0c, 0xc0, 0x23, 0xbb, 0x4a,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	},
	.y = {
		0x4b, 0x4a, 0xbb, 0x18, 0x07, 0xef, 0x36, 0xbf,
		0x25, 0x8c, 0xa5, 0xa3, 0xe4, 0x2e, 0xd3, 0x0f,
		0x1d, 0xe8, 0x69, 0x18, 0x19, 0xac, 0xde, 0xa7,
		0x58, 0xb8, 0x96, 0xd3, 0x5f, 0x78, 0xd4, 0x73,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	}
};

/**
 *
 * @brief Test v2xSe_encryptUsingSm2Eces for expected behaviour
 *
 * This function tests v2xSe_encryptUsingSm2Eces for expected behaviour
 * The following behaviours are tested:
 *  - success returned when valid input provided
 *
 */
void test_encryptUsingSm2Eces(void)
{
	TypeSW_t statusCode;
	TypeEncryptSm2Eces_t enc_sm2_ecesData;
	TypeLen_t size;
	uint8_t encryptedData[SM2_ECES_MSG_SIZE + SM2_PKE_OVERHEAD + 4]
		= { 0 };

	VTEST_RETURN_CONF_IF_NO_V2X_HW();

	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_CN), VTEST_PASS);

	/* Set up SM2 ECES encrypt parameters */
	enc_sm2_ecesData.pEccPublicKey = &sm2_eces_pub_key;
	enc_sm2_ecesData.curveId = V2XSE_CURVE_SM2_256;
	enc_sm2_ecesData.pMsgData = &sm2_eces_msg;
	enc_sm2_ecesData.msgLen = SM2_ECES_MSG_SIZE;
	/* Perform encryption */
	VTEST_CHECK_RESULT(v2xSe_encryptUsingSm2Eces(&enc_sm2_ecesData,
		&statusCode, &size, encryptedData), V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}
