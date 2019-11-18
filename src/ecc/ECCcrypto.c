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
#include "ECCcrypto_data.h"

static volatile int count_async = ASYNC_COUNT_RESET;

/** Size of public key coordinate */
#define PUBKEY_COORD_SIZE    LENGTH_DOMAIN_PARAMS_256
/** Result of memcmp when values match */
#define MEMCMP_IDENTICAL      0
/** Not supported curve */
#define DISP_CURVE_NOT_SUPP   ((disp_CurveId_t)0xFF)

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
		(const void *) test_dec_pubKey_y_exp_nistp256,
		PUBKEY_COORD_SIZE), MEMCMP_IDENTICAL);
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
		(const void *) test_dec_pubKey_y_exp_nistp256,
		PUBKEY_COORD_SIZE), MEMCMP_IDENTICAL);
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

	/* Positive verification test NISTP256 */
	pubKey.x = (uint8_t *) test_ver_pubKey_x_nistp256;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_nistp256;
	sig.r    = (uint8_t *) test_ver_sign_r_nistp256;
	sig.s    = (uint8_t *) test_ver_sign_s_nistp256;
	hash     = (disp_Hash_t) test_ver_hash_256;
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
	pubKey.x = (uint8_t *) test_ver_pubKey_x_nistp256;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_nistp256;
	sig.r    = (uint8_t *) test_ver_sign_r_nistp256;
	/* Using twice r: giving (r,r) instead of (r,s) */
	sig.s    = (uint8_t *) test_ver_sign_r_nistp256;
	hash     = (disp_Hash_t) test_ver_hash_256;
	VTEST_CHECK_RESULT_ASYNC_INC(disp_ecc_verify_signature((void *) 0, 0,
		DISP_CURVE_NISTP256, &pubKey, hash, &sig,
		disp_VerifSigOfHashCallback_negative), DISP_RETVAL_NO_ERROR,
		count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Negative test of disp_ecc_verify_signature with a curve not suppported
 *
 */
void ecc_test_signature_verification_not_supp(void)
{
	disp_PubKey_t pubKey;
	disp_Hash_t hash;
	disp_Sig_t sig;

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);

	/* Not supported curve test */
	pubKey.x = (uint8_t *) test_ver_pubKey_x_nistp256;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_nistp256;
	sig.r    = (uint8_t *) test_ver_sign_r_nistp256;
	sig.s    = (uint8_t *) test_ver_sign_s_nistp256;
	hash     = (disp_Hash_t) test_ver_hash_256;
	VTEST_CHECK_RESULT(disp_ecc_verify_signature((void *) 0, 0,
		DISP_CURVE_NOT_SUPP, &pubKey, hash, &sig,
		disp_VerifSigOfHashCallback),
		DISP_RETVAL_CRYPTO_FUNC_NOT_AVAIL);
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

	pubKey.x = test_dec_pubKey_x_nistp256;
	pubKey.y = test_dec_pubKey_y_nistp256;
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

	pubKey.x = test_dec_pubKey_x_nistp256;
	pubKey.y = test_dec_pubKey_y_neg_nistp256;
	VTEST_CHECK_RESULT_ASYNC_INC(disp_ecc_decompressPublicKey((void *)0, 0,
		DISP_CURVE_NISTP256, &pubKey,
		my_disp_DecompressPubKeyCallback_negative),
		DISP_RETVAL_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Test of disp_ecc_decompressPublicKey with not supported curve
 *
 */
void ecc_test_pubkey_decompression_not_supp(void)
{
	disp_PubKey_t pubKey;

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);

	pubKey.x = test_dec_pubKey_x_nistp256;
	pubKey.y = test_dec_pubKey_y_neg_nistp256;
	VTEST_CHECK_RESULT(disp_ecc_decompressPublicKey((void *)0, 0,
		DISP_CURVE_NOT_SUPP, &pubKey,
		my_disp_DecompressPubKeyCallback),
		DISP_RETVAL_CRYPTO_FUNC_NOT_AVAIL);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Positive test of disp_SHA256
 *
 */
void ecc_test_hash(void)
{
	uint8_t sha256_hash_got[LENGTH_DOMAIN_PARAMS_256];

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);
	disp_SHA256((const void *) test_hash_msg_256, HASH_MSG_SIZE,
		sha256_hash_got);
	VTEST_CHECK_RESULT(memcmp((const void *) test_hash_msg_exp_256,
		(const void *) sha256_hash_got, LENGTH_DOMAIN_PARAMS_256),
		MEMCMP_IDENTICAL);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}

/**
 *
 * @brief Negative test of disp_SHA256
 *
 */
void ecc_test_hash_negative(void)
{
	uint8_t sha256_hash_got[LENGTH_DOMAIN_PARAMS_256];

	VTEST_CHECK_RESULT(disp_Activate(), DISP_RETVAL_NO_ERROR);
	disp_SHA256((const void *) test_hash_msg_neg_256, HASH_MSG_SIZE,
		sha256_hash_got);
	VTEST_CHECK_RESULT(!memcmp((const void *) test_hash_msg_exp_256,
		(const void *) sha256_hash_got, LENGTH_DOMAIN_PARAMS_256),
		MEMCMP_IDENTICAL);
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
	pubKey.x = (uint8_t *) test_ver_pubKey_x_nistp256;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_nistp256;
	sig.r    = (uint8_t *) test_ver_sign_r_nistp256;
	sig.s    = (uint8_t *) test_ver_sign_s_nistp256;
	VTEST_CHECK_RESULT_ASYNC_INC(
		disp_ecc_verify_signature_of_message((void *) 0, 0,
		DISP_CURVE_NISTP256, &pubKey, (const void *) test_ver_msg,
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
	pubKey.x = (uint8_t *) test_ver_pubKey_x_nistp256;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_nistp256;
	sig.r    = (uint8_t *) test_ver_sign_r_nistp256;
	sig.s    = (uint8_t *) test_ver_sign_s_nistp256;
	hash     = (disp_Hash_t) test_ver_hash_256;
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
	pubKey.x = (uint8_t *) test_ver_pubKey_x_nistp256;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_nistp256;
	sig.r    = (uint8_t *) test_ver_sign_r_nistp256;
	sig.s    = (uint8_t *) test_ver_sign_s_nistp256;
	/* First parameter of the API is the key storage ID, which is ignored.
	 * See function's description above
	 */
	VTEST_CHECK_RESULT_ASYNC_INC(
		disp_ecc_verify_signature_key_of_message(0, (void *) 0, 0,
		DISP_CURVE_NISTP256, &pubKey, (const void *) test_ver_msg,
		HASH_MSG_SIZE, &sig, disp_VerifSigOfHashCallback),
		DISP_RETVAL_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);
	VTEST_CHECK_RESULT(disp_Deactivate(), DISP_RETVAL_NO_ERROR);
}
