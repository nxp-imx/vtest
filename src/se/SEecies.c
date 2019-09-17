
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
	.data = {	0x91, 0x69, 0x15, 0x5B, 0x08, 0xB0, 0x76, 0x74,
			0xCB, 0xAD, 0xF7, 0x5F, 0xB4, 0x6A, 0x7B, 0x0D}
	};

/** ECIES encrypt test vector - p1 parameter */
static uint8_t eciesP1[32] = {0xA6, 0xB7, 0xB5, 0x25, 0x54, 0xB4, 0x20, 0x3F,
                               0x7E, 0x3A, 0xCF, 0xDB, 0x3A, 0x3E, 0xD8, 0x67,
                               0x4E, 0xE0, 0x86, 0xCE, 0x59, 0x06, 0xA7, 0xCA,
                               0xC2, 0xF8, 0xA3, 0x98, 0x30, 0x6D, 0x3B, 0xE9 };

/** ECIES encrypt test vector - public key */
static TypePublicKey_t eciesPubKey = {
	.x = {	0x1c, 0xcb, 0xe9, 0x1c, 0x07, 0x5f, 0xc7, 0xf4,
		0xf0, 0x33, 0xbf, 0xa2, 0x48, 0xdb, 0x8f, 0xcc,
		0xd3, 0x56, 0x5d, 0xe9, 0x4b, 0xbf, 0xb1, 0x2f,
		0x3c, 0x59, 0xff, 0x46, 0xc2, 0x71, 0xbf, 0x83 },
	.y = {	0xce, 0x40, 0x14, 0xc6, 0x88, 0x11, 0xf9, 0xa2,
		0x1a, 0x1f, 0xdb, 0x2c, 0x0e, 0x61, 0x13, 0xe0,
		0x6d, 0xb7, 0xca, 0x93, 0xb7, 0x40, 0x4e, 0x78,
		0xdc, 0x7c, 0xcd, 0x5c, 0xa8, 0x9a, 0x4c, 0xa9 }
	};

/**
 *
 * @brief Test v2xSe_encryptUsingEcies for expected behaviour
 *
 * This function tests v2xSe_encryptUsingEcies for expected behaviour
 * The following behaviours are tested:
 *  - success returned when hsm test vectors provided
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

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
}
