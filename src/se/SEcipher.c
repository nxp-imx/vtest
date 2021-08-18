
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
 * @file SEcipher.c
 *
 * @brief Tests for SE CIPHER (requirements R17.*)
 *
 */

#include <string.h>
#include <v2xSe.h>
#include "vtest.h"
#include "SEmisc.h"
#include "SEcipher.h"

/** CIPHER encrypt test vector - input message */
static uint8_t some_16byte_data[16] = {
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

static TypePlainText_t sm4_ccm_ptx = {
	.data = {
	0x03, 0x80, 0x14, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xA0, 0xA1, 0xA2,
	0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9
	}
};

static TypePlainText_t cipherMsg = {
	.data = {	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	};

/**
 *
 * @brief Test v2xSe_encryptUsingRtCipher for expected behaviour
 *
 * This function tests v2xSe_encryptUsingRtCipher for expected behaviour
 * The following behaviours are tested:
 *  - success returned when valid input provided
 * TODO!! Verify result, create normal inputs, ...
 *
 */
void test_encryptUsingRtCipher(void)
{
	TypeSW_t statusCode;
	TypeEncryptCipher_t enc_cipherData = {0, };
	uint8_t vct[16];
	TypeLen_t size;

	VTEST_RETURN_CONF_IF_NO_V2X_HW();

/* Test Valid cipher for algo V2XSE_ALGO_SM4_CBC can be generated */
/* Test Valid cipher can be generated using key in slot zero */
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_CN), VTEST_PASS);
	/* Generate an Rt key to use */
	VTEST_CHECK_RESULT(v2xSe_generateRtSymmetricKey(SLOT_ZERO,
		V2XSE_SYMMK_SM4_128, &statusCode), V2XSE_SUCCESS);
	/* Set up CIPHER encrypt parameters */
	memcpy(enc_cipherData.iv, some_16byte_data, sizeof(some_16byte_data));
	enc_cipherData.ivLen = 16;
	enc_cipherData.algoId = V2XSE_ALGO_SM4_CBC;
	enc_cipherData.msgLen = 16;
	enc_cipherData.pMsgData = &cipherMsg;
	size = (uint8_t)sizeof(vct);
	/* Perform encryption */
	VTEST_CHECK_RESULT(v2xSe_encryptUsingRtCipher(SLOT_ZERO, &enc_cipherData,
		&statusCode, &size, (TypeVCTData_t*)(&vct)), V2XSE_SUCCESS);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtSymmetricKey(SLOT_ZERO, &statusCode),
								V2XSE_SUCCESS);

/* Test Valid cipher for algo V2XSE_ALGO_SM4_ECB can be generated */
/* Test Valid cipher can be generated using key in non-zero slot */
	/* Create Rt key in max slot */
	VTEST_CHECK_RESULT(v2xSe_generateRtSymmetricKey(NON_ZERO_SLOT,
		V2XSE_SYMMK_SM4_128, &statusCode), V2XSE_SUCCESS);
	/* Encrypt data with this key */
	memset(enc_cipherData.iv, 0, sizeof(enc_cipherData.iv));
	enc_cipherData.ivLen = 0;
	enc_cipherData.algoId = V2XSE_ALGO_SM4_ECB;
	enc_cipherData.msgLen = 16;
	enc_cipherData.pMsgData = &cipherMsg;
	size = (uint8_t)sizeof(vct);
	/* Perform encryption */
	VTEST_CHECK_RESULT(v2xSe_encryptUsingRtCipher(NON_ZERO_SLOT, &enc_cipherData,
		&statusCode, &size, (TypeVCTData_t*)(&vct)), V2XSE_SUCCESS);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtSymmetricKey(NON_ZERO_SLOT, &statusCode),
								V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
}

/**
 *
 * @brief Test v2xSe_decryptUsingRtCipher for expected behaviour
 *
 * This function tests v2xSe_decryptUsingRtCipher for expected behaviour
 * The following behaviours are tested:
 *  - success returned when random data provided
 * TODO!! Verify result, create normal inputs, ...
 *
 */
void test_decryptUsingRtCipher(void)
{
	TypeSW_t statusCode;
	TypeInt256_t msg;
	TypeEncryptCipher_t enc_cipherData;
	uint8_t vct[16];
	uint8_t vct_ccm[23+16+12];
	TypeLen_t size;
	TypeDecryptCipher_t dec_cipherData;

	VTEST_RETURN_CONF_IF_NO_V2X_HW();

/* Test Valid cipher for algo V2XSE_ALGO_SM4_CBC can be generated */
/* Test Valid cipher can be generated using key in slot zero */
	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_CN), VTEST_PASS);
	/* Generate an Rt key to use */
	VTEST_CHECK_RESULT(v2xSe_generateRtSymmetricKey(SLOT_ZERO,
		V2XSE_SYMMK_SM4_128, &statusCode), V2XSE_SUCCESS);
	/* Encrypt data with this key */
	memcpy(enc_cipherData.iv, some_16byte_data, sizeof(some_16byte_data));
	enc_cipherData.ivLen = 16;
	enc_cipherData.algoId = V2XSE_ALGO_SM4_CBC;
	enc_cipherData.msgLen = 16;
	enc_cipherData.pMsgData = &cipherMsg;
	size = (uint8_t)sizeof(vct);
	/* Perform encryption */
	VTEST_CHECK_RESULT(v2xSe_encryptUsingRtCipher(SLOT_ZERO, &enc_cipherData,
		&statusCode, &size, (TypeVCTData_t*)(&vct)), V2XSE_SUCCESS);
	/* Set up CIPHER decrypt parameters */
	memcpy(dec_cipherData.iv, some_16byte_data, sizeof(some_16byte_data));
	dec_cipherData.ivLen = 16;
	dec_cipherData.algoId = V2XSE_ALGO_SM4_CBC;
	dec_cipherData.vctLen = size;
	dec_cipherData.pVctData = (TypeVCTData_t*)vct;
	size = 16;
	/* Perform decryption */
	VTEST_CHECK_RESULT(v2xSe_decryptUsingRtCipher(SLOT_ZERO, &dec_cipherData,
			&statusCode, &size, (TypePlainText_t*)(&(msg.data))),
								V2XSE_SUCCESS);
	/* Verify message is correctly decrypted */
	VTEST_CHECK_RESULT(size, 16);
	VTEST_CHECK_RESULT(memcmp(cipherMsg.data, msg.data, 16), 0);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtSymmetricKey(SLOT_ZERO, &statusCode),
								V2XSE_SUCCESS);

/* Test Valid cipher for algo V2XSE_ALGO_SM4_ECB can be generated */
/* Test Valid cipher can be generated using key in non-zero slot */
	/* Create Rt key in max slot */
	VTEST_CHECK_RESULT(v2xSe_generateRtSymmetricKey(NON_ZERO_SLOT,
		V2XSE_SYMMK_SM4_128, &statusCode), V2XSE_SUCCESS);
	/* Encrypt data with this key */
	memset(enc_cipherData.iv, 0, sizeof(enc_cipherData.iv));
	enc_cipherData.ivLen = 0;
	enc_cipherData.algoId = V2XSE_ALGO_SM4_ECB;
	enc_cipherData.msgLen = 16;
	enc_cipherData.pMsgData = &cipherMsg;
	size = (uint8_t)sizeof(vct);
	/* Perform encryption */
	VTEST_CHECK_RESULT(v2xSe_encryptUsingRtCipher(NON_ZERO_SLOT, &enc_cipherData,
		&statusCode, &size, (TypeVCTData_t*)(&vct)), V2XSE_SUCCESS);
	/* Set up CIPHER decrypt parameters */
	memset(dec_cipherData.iv, 0, sizeof(enc_cipherData.iv));
	dec_cipherData.ivLen = 0;
	dec_cipherData.algoId = V2XSE_ALGO_SM4_ECB;
	dec_cipherData.vctLen = size;
	dec_cipherData.pVctData = (TypeVCTData_t*)vct;
	size = 16;
	/* Perform decryption */
	VTEST_CHECK_RESULT(v2xSe_decryptUsingRtCipher(NON_ZERO_SLOT, &dec_cipherData,
			&statusCode, &size, (TypePlainText_t*)(&(msg.data))),
								V2XSE_SUCCESS);
	/* Verify message is correctly decrypted */
	VTEST_CHECK_RESULT(size, 16);
	VTEST_CHECK_RESULT(memcmp(cipherMsg.data, msg.data, 16), 0);
	/* Delete key after use */

	/* Test SM4-CCM  */
	memset(enc_cipherData.iv, 0, sizeof(enc_cipherData.iv));
	enc_cipherData.ivLen = 0;
	enc_cipherData.algoId = V2XSE_ALGO_SM4_CCM;
	enc_cipherData.msgLen = 23;
	enc_cipherData.pMsgData = &sm4_ccm_ptx;
	size = (uint8_t)sizeof(vct_ccm);
	VTEST_CHECK_RESULT(v2xSe_encryptUsingRtCipher(NON_ZERO_SLOT, &enc_cipherData,
                &statusCode, &size, (TypeVCTData_t*)(&vct_ccm)), V2XSE_SUCCESS);

	memset(dec_cipherData.iv, 0, sizeof(enc_cipherData.iv));
	dec_cipherData.algoId = V2XSE_ALGO_SM4_CCM;
	dec_cipherData.vctLen = size;
	dec_cipherData.pVctData = (TypeVCTData_t*)vct_ccm;
	VTEST_CHECK_RESULT(v2xSe_decryptUsingRtCipher(NON_ZERO_SLOT, &dec_cipherData,
                        &statusCode, &size, (TypePlainText_t*)(&(msg.data))),
                                                                V2XSE_SUCCESS);


	VTEST_CHECK_RESULT(size, 23);
	VTEST_CHECK_RESULT(memcmp(msg.data, sm4_ccm_ptx.data, 23), 0);


	VTEST_CHECK_RESULT(v2xSe_deleteRtSymmetricKey(NON_ZERO_SLOT, &statusCode),
								V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
}
