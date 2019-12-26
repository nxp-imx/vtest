
/*
 * Copyright 2019-2020 NXP
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
 * @file SEecies.c
 *
 * @brief Tests for SE ECIES (requirements R8.*)
 *
 */

#include <string.h>
#include <v2xSe.h>
#include "vtest.h"
#include "SEmisc.h"
#include "SEecies.h"

/** ECIES encrypt test vector - input message */
static TypePlainText_t eciesMsg = {
	.data = {	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	};

/** ECIES encrypt test vector - p1 parameter */
static uint8_t eciesP1[32] = {	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
				0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
				};

/** ECIES encrypt test vector - public key */
static TypePublicKey_t eciesPubKey = {
	.x = {	0x82, 0x9f, 0xdd, 0x2b, 0xf5, 0x27, 0x84, 0xf5,
		0xd9, 0x97, 0xf5, 0xa1, 0xc9, 0x0f, 0xad, 0xd3,
		0x51, 0x71, 0x66, 0x32, 0x6d, 0x18, 0xf3, 0x4f,
		0x8b, 0x9a, 0x06, 0x77, 0xdd, 0x7d, 0x17, 0xdc
		},
	.y = {	0x27, 0xad, 0xb3, 0xa4, 0x51, 0xb0, 0x0d, 0x7d,
		0x2d, 0xec, 0x89, 0x41, 0xc7, 0x84, 0x32, 0x95,
		0xd5, 0xae, 0x6f, 0x20, 0x07, 0x18, 0xa7, 0x98,
		0x94, 0x85, 0x8b, 0x5c, 0xc7, 0x7e, 0xc4, 0x83
		}
	};

/**
 *
 * @brief Test v2xSe_encryptUsingEcies for expected behaviour
 *
 * This function tests v2xSe_encryptUsingEcies for expected behaviour
 * The following behaviours are tested:
 *  - success returned when valid input provided
 * TODO!! Verify result, create normal inputs, try different curves, applets...
 *
 */
void test_encryptUsingEcies(void)
{
	TypeSW_t statusCode;
	TypeEncryptEcies_t enc_eciesData;
	uint8_t vct[3*32];
	TypeLen_t size = (uint8_t)sizeof(vct);

	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Set up ECIES encrypt parameters */
	enc_eciesData.pEccPublicKey = &eciesPubKey;
	enc_eciesData.curveId = V2XSE_CURVE_NISTP256;
	enc_eciesData.kdfParamP1Len = 32;
	memcpy(enc_eciesData.kdfParamP1, eciesP1, sizeof(eciesP1));
	enc_eciesData.macLen = 16;
	enc_eciesData.macParamP2Len = 0;
	enc_eciesData.msgLen = 16;
	enc_eciesData.pMsgData = &eciesMsg;
	/* Perform encryption */
	VTEST_CHECK_RESULT(v2xSe_encryptUsingEcies(&enc_eciesData, &statusCode,
		&size, (TypeVCTData_t*)(&vct)), V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
}

/**
 *
 * @brief Test v2xSe_decryptUsingRtEcies for expected behaviour
 *
 * This function tests v2xSe_decryptUsingRtEcies for expected behaviour
 * The following behaviours are tested:
 *  - success returned when random data provided
 * TODO!! Verify result, create normal inputs, try different curves, applets...
 *
 */
void test_decryptUsingRtEcies(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeInt256_t msg;
	TypeEncryptEcies_t enc_eciesData;
	uint8_t vct[3*32];
	TypeLen_t size;
	TypeDecryptEcies_t dec_eciesData;

	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Generate an Rt key to use */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);

	/* Encrypt data with this key */
	enc_eciesData.pEccPublicKey = &pubKey;
	enc_eciesData.curveId = V2XSE_CURVE_NISTP256;
	enc_eciesData.kdfParamP1Len = 32;
	memcpy(enc_eciesData.kdfParamP1, eciesP1, sizeof(eciesP1));
	enc_eciesData.macLen = 16;
	enc_eciesData.macParamP2Len = 0;
	enc_eciesData.msgLen = 16;
	enc_eciesData.pMsgData = &eciesMsg;
	size = (uint8_t)sizeof(vct);
	/* Perform encryption */
	VTEST_CHECK_RESULT(v2xSe_encryptUsingEcies(&enc_eciesData, &statusCode,
		&size, (TypeVCTData_t*)(vct)), V2XSE_SUCCESS);

	/* Set up ECIES decrypt parameters */
	dec_eciesData.kdfParamP1Len = 32;
	memcpy(dec_eciesData.kdfParamP1, eciesP1, sizeof(eciesP1));
	dec_eciesData.macLen = 16;
	dec_eciesData.macParamP2Len = 0;
	dec_eciesData.vctLen = size;
	dec_eciesData.pVctData = (TypeVCTData_t*)vct;
	size = 16;
	/* Perform decryption */
	VTEST_CHECK_RESULT(v2xSe_decryptUsingRtEcies(SLOT_ZERO, &dec_eciesData,
			&statusCode, &size, (TypePlainText_t*)(&(msg.data))),
								V2XSE_SUCCESS);

	/* Verify message is correctly decrypted */
	VTEST_CHECK_RESULT(size, 16);
	VTEST_CHECK_RESULT(memcmp(eciesMsg.data, msg.data, size), 0);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(SLOT_ZERO, &statusCode),
								V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
}

/**
 *
 * @brief Test v2xSe_decryptUsingMaEcies for expected behaviour
 *
 * This function tests v2xSe_decryptUsingMaEcies for expected behaviour
 * The following behaviours are tested:
 *  - success returned when random data provided
 * TODO!! Verify result, create normal inputs, try different curves, applets...
 *
 */
void test_decryptUsingMaEcies(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeInt256_t msg;
	TypeEncryptEcies_t enc_eciesData;
	uint8_t vct[3*32];
	TypeLen_t size;
	TypeDecryptEcies_t dec_eciesData;

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Generate MA key of known curveId */
	VTEST_CHECK_RESULT(v2xSe_generateMaEccKeyPair(V2XSE_CURVE_NISTP256,
		&statusCode, &pubKey), V2XSE_SUCCESS);

	/* Encrypt data with this key */
	enc_eciesData.pEccPublicKey = &pubKey;
	enc_eciesData.curveId = V2XSE_CURVE_NISTP256;
	enc_eciesData.kdfParamP1Len = 32;
	memcpy(enc_eciesData.kdfParamP1, eciesP1, sizeof(eciesP1));
	enc_eciesData.macLen = 16;
	enc_eciesData.macParamP2Len = 0;
	enc_eciesData.msgLen = 16;
	enc_eciesData.pMsgData = &eciesMsg;
	size = (uint8_t)sizeof(vct);
	/* Perform encryption */
	VTEST_CHECK_RESULT(v2xSe_encryptUsingEcies(&enc_eciesData, &statusCode,
		&size, (TypeVCTData_t*)(vct)), V2XSE_SUCCESS);

	/* Set up ECIES decrypt parameters */
	dec_eciesData.kdfParamP1Len = 32;
	memcpy(dec_eciesData.kdfParamP1, eciesP1, sizeof(eciesP1));
	dec_eciesData.macLen = 16;
	dec_eciesData.macParamP2Len = 0;
	dec_eciesData.vctLen = size;
	dec_eciesData.pVctData = (TypeVCTData_t*)vct;
	size = 16;
	/* Perform decryption */
	VTEST_CHECK_RESULT(v2xSe_decryptUsingMaEcies(&dec_eciesData,
			&statusCode, &size, (TypePlainText_t*)(&(msg.data))),
								V2XSE_SUCCESS);
	/* Verify message is correctly decrypted */
	VTEST_CHECK_RESULT(size, 16);
	VTEST_CHECK_RESULT(memcmp(eciesMsg.data, msg.data, size), 0);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
}

/**
 *
 * @brief Test v2xSe_decryptUsingBaEcies for expected behaviour
 *
 * This function tests v2xSe_decryptUsingBaEcies for expected behaviour
 * The following behaviours are tested:
 *  - success returned when random data provided
 * TODO!! Verify result, create normal inputs, try different curves, applets...
 *
 */
void test_decryptUsingBaEcies(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeInt256_t msg;
	TypeEncryptEcies_t enc_eciesData;
	uint8_t vct[3*32];
	TypeLen_t size;
	TypeDecryptEcies_t dec_eciesData;

	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Generate an Ba key to use */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey), V2XSE_SUCCESS);

	/* Encrypt data with this key */
	enc_eciesData.pEccPublicKey = &pubKey;
	enc_eciesData.curveId = V2XSE_CURVE_NISTP256;
	enc_eciesData.kdfParamP1Len = 32;
	memcpy(enc_eciesData.kdfParamP1, eciesP1, sizeof(eciesP1));
	enc_eciesData.macLen = 16;
	enc_eciesData.macParamP2Len = 0;
	enc_eciesData.msgLen = 16;
	enc_eciesData.pMsgData = &eciesMsg;
	size = (uint8_t)sizeof(vct);
	/* Perform encryption */
	VTEST_CHECK_RESULT(v2xSe_encryptUsingEcies(&enc_eciesData, &statusCode,
		&size, (TypeVCTData_t*)(vct)), V2XSE_SUCCESS);

	/* Set up ECIES decrypt parameters */
	dec_eciesData.kdfParamP1Len = 32;
	memcpy(dec_eciesData.kdfParamP1, eciesP1, sizeof(eciesP1));
	dec_eciesData.macLen = 16;
	dec_eciesData.macParamP2Len = 0;
	dec_eciesData.vctLen = size;
	dec_eciesData.pVctData = (TypeVCTData_t*)vct;
	size = 16;
	/* Perform decryption */
	VTEST_CHECK_RESULT(v2xSe_decryptUsingBaEcies(SLOT_ZERO, &dec_eciesData,
			&statusCode, &size, (TypePlainText_t*)(&(msg.data))),
								V2XSE_SUCCESS);
	/* Verify message is correctly decrypted */
	VTEST_CHECK_RESULT(size, 16);
	VTEST_CHECK_RESULT(memcmp(eciesMsg.data, msg.data, size), 0);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode),
								V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
}
