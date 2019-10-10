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
 * @file ECCcrypto.c
 *
 * @brief Tests for ECC cryptography operations (requirements R3.*)
 *
 */

#include <string.h>

#include "ECCcrypto.h"
#include "ecc_dispatcher.h"
#include "vtest_async.h"

static volatile int count_async = ASYNC_COUNT_RESET;

#define PUBKEY_COORD_SIZE    32
#define MEMCMP_IDENTICAL      0
#define HASH_MSG_SIZE         7

/* Dataset for signature verification tests */
/* Hash of "message" */
static uint8_t hash_ver[32] = {
	          0x1D, 0x6D, 0x0C, 0x46, 0x2B, 0xF0, 0xFB, 0x1A,
	          0xEA, 0x1C, 0xF7, 0x22, 0xFB, 0xF3, 0xD1, 0xCF,
	          0x94, 0xA9, 0xFB, 0xE3, 0xB7, 0xF9, 0x79, 0x2B,
	          0x98, 0x14, 0x59, 0xE4, 0x13, 0x0A, 0x53, 0xAB
	          };
/* Message is "message" */
static uint8_t msg_ver[HASH_MSG_SIZE] = {
	          0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65
	          };
static uint8_t pubKey_ver_x[32] = {
	          0xC6, 0xA8, 0xBB, 0x62, 0xD9, 0x3E, 0x98, 0x0A,
	          0xC4, 0x67, 0xC4, 0x4D, 0x38, 0x2C, 0xFB, 0x5E,
	          0x7B, 0x40, 0x6A, 0x4E, 0x18, 0x14, 0x93, 0x80,
	          0x1F, 0x4C, 0xCD, 0x68, 0x56, 0x9E, 0x6D, 0x3A
	          };
static uint8_t pubKey_ver_y[32] = {
	          0x05, 0x2A, 0xA2, 0xE6, 0xEB, 0xD1, 0xE7, 0x73,
	          0x7B, 0x9B, 0x79, 0x7C, 0xD4, 0x22, 0xF6, 0x17,
	          0x66, 0x7A, 0x5A, 0xE3, 0x4E, 0xBD, 0xD9, 0xE6,
	          0x52, 0xC0, 0x81, 0x93, 0xC2, 0x5F, 0x2D, 0x97
	          };
static uint8_t sign_ver_r[32] = {
	          0x73, 0x5D, 0x9E, 0x22, 0x83, 0xCE, 0x2B, 0x1D,
	          0xA6, 0xDA, 0x4A, 0x1C, 0x7A, 0x8D, 0x98, 0x21,
	          0x4E, 0x9A, 0x9F, 0xC8, 0x6F, 0xC1, 0x0C, 0x51,
	          0x93, 0x35, 0x52, 0x9D, 0xFF, 0xE9, 0x4B, 0x91
	          };
static uint8_t sign_ver_s[32] = {
	          0x20, 0x14, 0xE4, 0x03, 0x57, 0xA4, 0x6E, 0x39,
	          0xEA, 0x8B, 0x2E, 0xF1, 0xCB, 0x64, 0xE5, 0x6F,
	          0xEF, 0x34, 0xD1, 0xDE, 0x93, 0x6B, 0xC8, 0x39,
	          0x44, 0x86, 0xFD, 0x6F, 0x64, 0x26, 0x7A, 0xE6
	          };
/*
 * Dataset for public key decompression tests
 */
/*
 * X-coordinate of public key
 * this will be the Y input for the test
 */
static uint8_t pubKey_x[32] = {
	          0x3c, 0x23, 0xa9, 0x76, 0x3a, 0x2f, 0x12, 0xbb,
	          0x12, 0xe8, 0xde, 0xee, 0xb2, 0x69, 0x1c, 0x9e,
	          0x79, 0x00, 0x30, 0xb7, 0xfc, 0x2e, 0xcf, 0xad,
	          0xe3, 0x1e, 0x99, 0x51, 0x5b, 0x8b, 0xf1, 0x44
	          };
/*
 * Y-coordinate of public key before decompression test:
 * this will be the Y input for the test.
 * The first byte is:
 *     - 0x00 if LSB of Y-coordinate is 0
 *     - 0x01 if LSB of Y-coordinate is 1
 */
static uint8_t pubKey_y[32] = {
	          0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	          };
/*
 * Y-coordinate of public key: this is the expected output
 */
static uint8_t pubKey_y_exp[32] = {
	          0xed, 0x61, 0x30, 0x99, 0x9e, 0xe0, 0x2f, 0x23,
	          0x10, 0x63, 0xf1, 0x40, 0x0c, 0x0a, 0xd1, 0x8c,
	          0x02, 0x54, 0xbb, 0x24, 0xe8, 0x51, 0xaa, 0x52,
	          0xdc, 0x4b, 0x27, 0x92, 0x4f, 0xcb, 0x06, 0x6d
	          };
/*
 * Y-coordinate of public key before decompression test:
 * this will be the Y input for the negative test.
 */
static uint8_t pubKey_y_neg[32] = {
	          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	          };

/*
 * Dataset for sha256 tests
 */
/* msg is "message" */
static uint8_t sha256_msg[HASH_MSG_SIZE] = {
	          0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65
	          };
/* Expected hash of "message" using SHA256 */
static uint8_t sha256_hash_exp[32] = {
	          0xab, 0x53, 0x0a, 0x13, 0xe4, 0x59, 0x14, 0x98,
	          0x2b, 0x79, 0xf9, 0xb7, 0xe3, 0xfb, 0xa9, 0x94,
	          0xcf, 0xd1, 0xf3, 0xfb, 0x22, 0xf7, 0x1c, 0xea,
	          0x1a, 0xfb, 0xf0, 0x2b, 0x46, 0x0c, 0x6d, 0x1d
	          };
/* msg is "messagg": this is used for negative test */
static uint8_t sha256_msg_neg[HASH_MSG_SIZE] = {
	          0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x67
	          };

/**
 * @brief   Signature verification callback: positive test
 *
 * @param[in]  sequence_number       sequence operation id (not used?)
 * @param[out] ret                   returned value by the dispatcher
 * @param[out] verification_result   verification result
 *
 */

void disp_VerifSigOfHashCallback(void *sequence_number,
	disp_ReturnValue_t ret,
	disp_VerificationResult_t verification_result)
{
	VTEST_CHECK_RESULT_ASYNC_DEC(ret, DISP_RETVAL_NO_ERROR, count_async);
	VTEST_CHECK_RESULT(verification_result, DISP_VERIFRES_SUCCESS);
}

/**
 * @brief   Signature verification callback: negative test
 *
 * @param[in]  sequence_number       sequence operation id (not used?)
 * @param[out] ret                   returned value by the dispatcher
 * @param[out] verification_result   verification result
 *
 */
void disp_VerifSigOfHashCallback_negative(void *sequence_number,
	disp_ReturnValue_t ret,
	disp_VerificationResult_t verification_result)
{
	VTEST_CHECK_RESULT_ASYNC_DEC(ret, DISP_RETVAL_NO_ERROR, count_async);
	VTEST_CHECK_RESULT(verification_result,
		DISP_VERIFRES_ERROR_VERIFICATION);
}

/**
 * @brief   Public key decompression callback: positive test
 *
 * @param[in]  sequence_number       sequence operation id (not used?)
 * @param[out] ret                   returned value by the dispatcher
 * @param[out] pubKey_decompressed   decompressed public key
 *
 */
void my_disp_DecompressPubKeyCallback(void *sequence_number,
	disp_ReturnValue_t ret,
	disp_PubKey_t *pubKey_decompressed)
{
	VTEST_CHECK_RESULT_ASYNC_DEC(ret, DISP_RETVAL_NO_ERROR, count_async);
	/* Compare decompressed and expected Y-coordinate */
	VTEST_CHECK_RESULT(memcmp((const void *) pubKey_decompressed->y,
		(const void *) pubKey_y_exp, PUBKEY_COORD_SIZE),
		MEMCMP_IDENTICAL);
}

/**
 * @brief   Public key decompression callback: negative test
 *
 * @param[in]  sequence_number       sequence operation id (not used?)
 * @param[out] ret                   returned value by the dispatcher
 * @param[out] pubKey_decompressed   decompressed public key
 *
 */
void my_disp_DecompressPubKeyCallback_negative(void *sequence_number,
	disp_ReturnValue_t ret,
	disp_PubKey_t *pubKey_decompressed)
{
	VTEST_CHECK_RESULT_ASYNC_DEC(ret, DISP_RETVAL_NO_ERROR, count_async);
	/*
	 * Compare decompressed and expected Y-coordinate
	 * This time if memcmp is not 0, the test PASS
	 */
	VTEST_CHECK_RESULT(!memcmp((const void *) pubKey_decompressed->y,
		(const void *) pubKey_y_exp, PUBKEY_COORD_SIZE),
		MEMCMP_IDENTICAL);
}

/**
 *
 * @brief Positive test of disp_ecc_verify_signature with NISTP256
 *
 */
void ecc_test_signature_verification(void)
{
	disp_PubKey_t pubKey;
	disp_Hash_t hash;
	disp_Sig_t sig;

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);

	/* Positive verification test */
	pubKey.x = (uint8_t *) pubKey_ver_x;
	pubKey.y = (uint8_t *) pubKey_ver_y;
	sig.r    = (uint8_t *) sign_ver_r;
	sig.s    = (uint8_t *) sign_ver_s;
	hash     = (disp_Hash_t) hash_ver;
	VTEST_CHECK_RESULT_ASYNC_INC(disp_ecc_verify_signature((void *) 0, 0,
		DISP_CURVE_NISTP256, &pubKey, hash, &sig,
		disp_VerifSigOfHashCallback), DISP_RETVAL_NO_ERROR,
		count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Negative test of disp_ecc_verify_signature with NISTP256
 *
 */
void ecc_test_signature_verification_negative(void)
{
	disp_PubKey_t pubKey;
	disp_Hash_t hash;
	disp_Sig_t sig;

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);

	/* Negative verification test */
	pubKey.x = (uint8_t *) pubKey_ver_x;
	pubKey.y = (uint8_t *) pubKey_ver_y;
        sig.r    = (uint8_t *) sign_ver_r;
	/* Using twice r: giving (r,r) instead of (r,s) */
        sig.s    = (uint8_t *) sign_ver_r;
        hash     = (disp_Hash_t) hash_ver;
	VTEST_CHECK_RESULT_ASYNC_INC(disp_ecc_verify_signature((void *) 0, 0,
		DISP_CURVE_NISTP256, &pubKey, hash, &sig,
		disp_VerifSigOfHashCallback_negative), DISP_RETVAL_NO_ERROR,
		count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Positive test of disp_ecc_decompressPublicKey with NISTP256
 *
 */
void ecc_test_pubkey_decompression(void)
{
	disp_PubKey_t pubKey;

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);

	pubKey.x = pubKey_x;
	pubKey.y = pubKey_y;
	VTEST_CHECK_RESULT_ASYNC_INC(disp_ecc_decompressPublicKey((void *)0, 0,
		DISP_CURVE_NISTP256, &pubKey, my_disp_DecompressPubKeyCallback),
		DISP_RETVAL_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Negative test of disp_ecc_decompressPublicKey with NISTP256
 *
 */
void ecc_test_pubkey_decompression_negative(void)
{
	disp_PubKey_t pubKey;

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);

	pubKey.x = pubKey_x;
	pubKey.y = pubKey_y_neg;
	VTEST_CHECK_RESULT_ASYNC_INC(disp_ecc_decompressPublicKey((void *)0, 0,
		DISP_CURVE_NISTP256, &pubKey,
		my_disp_DecompressPubKeyCallback_negative),
		DISP_RETVAL_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Positive test of disp_SHA256
 *
 */
void ecc_test_hash(void)
{
	uint8_t sha256_hash_got[32];

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);
	disp_SHA256((const void *) sha256_msg, HASH_MSG_SIZE, sha256_hash_got);
	VTEST_CHECK_RESULT(memcmp((const void *) sha256_hash_exp,
		(const void *) sha256_hash_got, 32), MEMCMP_IDENTICAL);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Negative test of disp_SHA256
 *
 */
void ecc_test_hash_negative(void)
{
	uint8_t sha256_hash_got[32];

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);
	disp_SHA256((const void *) sha256_msg_neg, HASH_MSG_SIZE,
		sha256_hash_got);
	VTEST_CHECK_RESULT(!memcmp((const void *) sha256_hash_exp,
		(const void *) sha256_hash_got, 32), MEMCMP_IDENTICAL);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Positive test of disp_ecc_verify_signature_of_message
 *
 */
void ecc_test_signature_verification_message(void)
{
	disp_PubKey_t pubKey;
	disp_Sig_t sig;

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);
	pubKey.x = (uint8_t *) pubKey_ver_x;
	pubKey.y = (uint8_t *) pubKey_ver_y;
	sig.r    = (uint8_t *) sign_ver_r;
	sig.s    = (uint8_t *) sign_ver_s;
	VTEST_CHECK_RESULT_ASYNC_INC(
		disp_ecc_verify_signature_of_message((void *) 0, 0,
		DISP_CURVE_NISTP256, &pubKey, (const void *) msg_ver,
		HASH_MSG_SIZE, &sig, disp_VerifSigOfHashCallback),
		DISP_RETVAL_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Positive test of disp_ecc_verify_signature_key
 * Note from API source code:
 * same as disp_ecc_verify_signature_of_message (ignoring key_storage)
 *
 */
void ecc_test_signature_verification_key(void)
{
	disp_PubKey_t pubKey;
	disp_Hash_t hash;
	disp_Sig_t sig;

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);

	/* Positive verification test */
	pubKey.x = (uint8_t *) pubKey_ver_x;
	pubKey.y = (uint8_t *) pubKey_ver_y;
	sig.r    = (uint8_t *) sign_ver_r;
	sig.s    = (uint8_t *) sign_ver_s;
	hash     = (disp_Hash_t) hash_ver;
	/* First parameter of the API is the key storage ID, which is ignored.
	 * See function's description above
	 */
	VTEST_CHECK_RESULT_ASYNC_INC(disp_ecc_verify_signature_key(0,
		(void *) 0, 0, DISP_CURVE_NISTP256, &pubKey, hash, &sig,
		disp_VerifSigOfHashCallback), DISP_RETVAL_NO_ERROR,
		count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Positive test of disp_ecc_verify_signature_key_of_message
 *
 */
void ecc_test_signature_verification_key_of_msg(void)
{
	disp_PubKey_t pubKey;
	disp_Sig_t sig;

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);
	pubKey.x = (uint8_t *) pubKey_ver_x;
	pubKey.y = (uint8_t *) pubKey_ver_y;
	sig.r    = (uint8_t *) sign_ver_r;
	sig.s    = (uint8_t *) sign_ver_s;
	/* First parameter of the API is the key storage ID, which is ignored.
	 * See function's description above
	 */
	VTEST_CHECK_RESULT_ASYNC_INC(
		disp_ecc_verify_signature_key_of_message(0, (void *) 0, 0,
		DISP_CURVE_NISTP256, &pubKey, (const void *) msg_ver,
		HASH_MSG_SIZE, &sig, disp_VerifSigOfHashCallback),
		DISP_RETVAL_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}
