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
 * @file ECCcrypto.c
 *
 * @brief Tests for ECC cryptography operations (requirements R3.*)
 *
 */

#include <string.h>

#include "ECCcrypto.h"
#include "ecdsa.h"
#include "vtest_async.h"
#include "ECCcrypto_data.h"

static volatile int count_async = ASYNC_COUNT_RESET;

/** Result of memcmp when values match */
#define MEMCMP_IDENTICAL      0
/** Not supported curve */
#define ECDSA_CURVE_NOT_SUPP   ((ecdsa_curveid_t)0xFF)

/**
 * @brief   Signature verification callback: positive test
 *
 * @param[in]  sequence_number       sequence operation id (not used?)
 * @param[out] ret                   returned value by the dispatcher
 * @param[out] verification_result   verification result
 *
 */

void ecdsa_VerifSigOfHashCallback(void *sequence_number,
	int ret,
	ecdsa_verification_result_t verification_result)
{
	VTEST_CHECK_RESULT_ASYNC_DEC(ret, ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT(verification_result, ECDSA_VERIFICATION_SUCCESS);
}

/**
 * @brief   Signature verification callback: negative test
 *
 * @param[in]  sequence_number       sequence operation id (not used?)
 * @param[out] ret                   returned value by the dispatcher
 * @param[out] verification_result   verification result
 *
 */
void ecdsa_VerifSigOfHashCallback_negative(void *sequence_number,
	int ret,
	ecdsa_verification_result_t verification_result)
{
	VTEST_CHECK_RESULT_ASYNC_DEC(ret, ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT(verification_result,
		ECDSA_VERIFICATION_ERROR);
}

/**
 * @brief   Public key decompression callback: positive test
 *
 * @param[in]  callbackData          the curve id
 * @param[out] ret                   returned value by the dispatcher
 * @param[out] pubKey_decompressed   decompressed public key
 *
 */
void my_ecdsa_DecompressPubKeyCallback(void *callbackData,
	int ret,
	ecdsa_pubkey_t *pubKey_decompressed)
{
	ecdsa_curveid_t curveID;

	/* Callback data used to store curve id */
	curveID = *(ecdsa_curveid_t *) callbackData;

	VTEST_CHECK_RESULT_ASYNC_DEC(ret, ECDSA_NO_ERROR, count_async);

	switch (curveID) {
	/*
	 * Compare decompressed and expected Y-coordinate
	 */
	case ECDSA_CURVE_NISTP256:
		VTEST_CHECK_RESULT(memcmp((const void *) pubKey_decompressed->y,
			(const void *) test_dec_pubKey_y_exp_nistp256,
			LENGTH_DOMAIN_PARAMS_256), MEMCMP_IDENTICAL);
		break;
	case ECDSA_CURVE_BP256R1:
		VTEST_CHECK_RESULT(memcmp((const void *) pubKey_decompressed->y,
			(const void *) test_dec_pubKey_y_exp_bp256r1,
			LENGTH_DOMAIN_PARAMS_256), MEMCMP_IDENTICAL);
		break;
	case ECDSA_CURVE_BP384R1:
		VTEST_CHECK_RESULT(memcmp((const void *) pubKey_decompressed->y,
			(const void *) test_dec_pubKey_y_exp_bp384r1,
			LENGTH_DOMAIN_PARAMS_384), MEMCMP_IDENTICAL);
		break;
	default:
		/*
		 * This should be never executed.
		 * If it is executed, it prints an error and the test fails.
		 */
		VTEST_LOG("Curve not supported");
		VTEST_CHECK_RESULT(curveID, ECDSA_CURVE_NOT_SUPP);
		break;
	}
}

/**
 * @brief   Public key decompression callback: negative test
 *
 * @param[in]  callbackData          the curve id
 * @param[out] ret                   returned value by the dispatcher
 * @param[out] pubKey_decompressed   decompressed public key
 *
 */
void my_ecdsa_DecompressPubKeyCallback_negative(void *callbackData,
	int ret,
	ecdsa_pubkey_t *pubKey_decompressed)
{
	ecdsa_curveid_t curveID;

	/* Callback data used to store curve id */
	curveID = *(ecdsa_curveid_t *) callbackData;

	VTEST_CHECK_RESULT_ASYNC_DEC(ret, ECDSA_NO_ERROR,	count_async);

	switch (curveID) {
	/*
	 * Compare decompressed and expected Y. They must be different.
	 * This time if memcmp is not 0, the test PASS
	 */
	case ECDSA_CURVE_NISTP256:
		VTEST_CHECK_RESULT(
			!memcmp((const void *) pubKey_decompressed->y,
			(const void *) test_dec_pubKey_y_exp_nistp256,
			LENGTH_DOMAIN_PARAMS_256), MEMCMP_IDENTICAL);
		break;
	case ECDSA_CURVE_BP256R1:
		VTEST_CHECK_RESULT(
			!memcmp((const void *) pubKey_decompressed->y,
			(const void *) test_dec_pubKey_y_exp_bp256r1,
			LENGTH_DOMAIN_PARAMS_256), MEMCMP_IDENTICAL);
		break;
	case ECDSA_CURVE_BP384R1:
		VTEST_CHECK_RESULT(
			!memcmp((const void *) pubKey_decompressed->y,
			(const void *) test_dec_pubKey_y_exp_bp384r1,
			LENGTH_DOMAIN_PARAMS_384), MEMCMP_IDENTICAL);
		break;
	default:
		/*
		 * This should be never executed.
		 * If it is executed, it prints an error and the test fails.
		 */
		VTEST_LOG("Curve not supported");
		VTEST_CHECK_RESULT(curveID, ECDSA_CURVE_NOT_SUPP);
		break;
	}
}

/**
 * @brief   Public key reconstruction callback: positive test
 *
 * @param[in]  callback data              the curve id
 * @param[out] ret                        returned value by the dispatcher
 * @param[out] reconstructed_public_key   reconstructed public key
 *
 */
static void my_ecdsa_ReconPubKeyCallback(void *callbackData,
	int ret, ecdsa_pubkey_t *reconstructed_public_key)
{
	ecdsa_curveid_t curveID;

	/* Use callback data to store curve id */
	curveID = *(ecdsa_curveid_t *) callbackData;

	VTEST_CHECK_RESULT_ASYNC_DEC(ret, ECDSA_NO_ERROR, count_async);

	switch (curveID) {

	case ECDSA_CURVE_NISTP256:
		VTEST_CHECK_RESULT(memcmp(
			(const void *) reconstructed_public_key->x,
			(const void *) test_rec_pubKey_x_exp_nistp256,
			LENGTH_DOMAIN_PARAMS_256), MEMCMP_IDENTICAL);

		VTEST_CHECK_RESULT(memcmp(
			(const void *) reconstructed_public_key->y,
			(const void *) test_rec_pubKey_y_exp_nistp256,
			LENGTH_DOMAIN_PARAMS_256), MEMCMP_IDENTICAL);
		break;
	case ECDSA_CURVE_BP256R1:
		VTEST_CHECK_RESULT(memcmp(
			(const void *) reconstructed_public_key->x,
			(const void *) test_rec_pubKey_x_exp_bp256r1,
			LENGTH_DOMAIN_PARAMS_256), MEMCMP_IDENTICAL);

		VTEST_CHECK_RESULT(memcmp(
			(const void *) reconstructed_public_key->y,
			(const void *) test_rec_pubKey_y_exp_bp256r1,
			LENGTH_DOMAIN_PARAMS_256), MEMCMP_IDENTICAL);
		break;
	default:
		/*
		 * This should be never executed.
		 * If it is executed, it prints an error and the test fails.
		 */
		VTEST_LOG("Curve not supported");
		VTEST_CHECK_RESULT(curveID, ECDSA_CURVE_NOT_SUPP);
		break;
	}
}

/**
 * @brief   Public key reconstruction callback: negative test
 *
 * @param[in]  callback data              the curve id
 * @param[out] ret                        returned value by the dispatcher
 * @param[out] reconstructed_public_key   reconstructed public key
 *
 */
static void my_ecdsa_ReconPubKeyCallback_negative(void *callbackData,
	int ret, ecdsa_pubkey_t *reconstructed_public_key)
{
	ecdsa_curveid_t curveID;

	/* Use callback data to store curve id */
	curveID = *(ecdsa_curveid_t *) callbackData;

	VTEST_CHECK_RESULT_ASYNC_DEC(ret, ECDSA_NO_ERROR, count_async);

	switch (curveID) {

	case ECDSA_CURVE_NISTP256:
		VTEST_CHECK_RESULT(!memcmp(
			(const void *) reconstructed_public_key->x,
			(const void *) test_rec_pubKey_x_exp_nistp256,
			LENGTH_DOMAIN_PARAMS_256), MEMCMP_IDENTICAL);

		VTEST_CHECK_RESULT(!memcmp(
			(const void *) reconstructed_public_key->y,
			(const void *) test_rec_pubKey_y_exp_nistp256,
			LENGTH_DOMAIN_PARAMS_256), MEMCMP_IDENTICAL);
		break;
	case ECDSA_CURVE_BP256R1:
		VTEST_CHECK_RESULT(!memcmp(
			(const void *) reconstructed_public_key->x,
			(const void *) test_rec_pubKey_x_exp_bp256r1,
			LENGTH_DOMAIN_PARAMS_256), MEMCMP_IDENTICAL);

		VTEST_CHECK_RESULT(!memcmp(
			(const void *) reconstructed_public_key->y,
			(const void *) test_rec_pubKey_y_exp_bp256r1,
			LENGTH_DOMAIN_PARAMS_256), MEMCMP_IDENTICAL);
		break;
	default:
		/*
		 * This should be never executed.
		 * If it is executed, it prints an error and the test fails.
		 */
		VTEST_LOG("Curve not supported");
		VTEST_CHECK_RESULT(curveID, ECDSA_CURVE_NOT_SUPP);
		break;
	}
}

/**
 *
 * @brief Positive test of ecdsa_verify_signature
 *
 */
void ecc_test_signature_verification(void)
{
	ecdsa_pubkey_t pubKey;
	ecdsa_hash_t hash;
	ecdsa_sig_t sig;

	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);

	/* Positive verification test NISTP256 */
	pubKey.x = (uint8_t *) test_ver_pubKey_x_nistp256;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_nistp256;
	sig.r    = (uint8_t *) test_ver_sign_r_nistp256;
	sig.s    = (uint8_t *) test_ver_sign_s_nistp256;
	hash     = (ecdsa_hash_t) test_ver_hash_256;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_NISTP256, pubKey, hash,
			sig, 0, ecdsa_VerifSigOfHashCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	/* Positive verification test BRAINPOOL256R1 */
	pubKey.x = (uint8_t *) test_ver_pubKey_x_bp256r1;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_bp256r1;
	sig.r    = (uint8_t *) test_ver_sign_r_bp256r1;
	sig.s    = (uint8_t *) test_ver_sign_s_bp256r1;
	hash     = (ecdsa_hash_t) test_ver_hash_256;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_BP256R1, pubKey, hash,
			sig, 0, ecdsa_VerifSigOfHashCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	/* Positive verification test BRAINPOOL384R1 */
	pubKey.x = (uint8_t *) test_ver_pubKey_x_bp384r1;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_bp384r1;
	sig.r    = (uint8_t *) test_ver_sign_r_bp384r1;
	sig.s    = (uint8_t *) test_ver_sign_s_bp384r1;
	hash     = (ecdsa_hash_t) test_ver_hash_384;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_BP384R1, pubKey, hash,
			sig, 0, ecdsa_VerifSigOfHashCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Positive test of ecdsa_verify_signature_of_message
 *
 */
void ecc_test_signature_verification_message(void)
{
	ecdsa_pubkey_t pubKey;
	ecdsa_sig_t sig;

	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);

	/* Positive verification test NISTP256 */
	pubKey.x = (uint8_t *) test_ver_pubKey_x_nistp256;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_nistp256;
	sig.r    = (uint8_t *) test_ver_sign_r_nistp256;
	sig.s    = (uint8_t *) test_ver_sign_s_nistp256;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature_of_message(ECDSA_CURVE_NISTP256, pubKey,
			(const void *)test_ver_msg, HASH_MSG_SIZE, sig, 0,
			ecdsa_VerifSigOfHashCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	/* Positive verification test BRAINPOOL256R1 */
	pubKey.x = (uint8_t *) test_ver_pubKey_x_bp256r1;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_bp256r1;
	sig.r    = (uint8_t *) test_ver_sign_r_bp256r1;
	sig.s    = (uint8_t *) test_ver_sign_s_bp256r1;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature_of_message(ECDSA_CURVE_BP256R1, pubKey,
			(const void *)test_ver_msg, HASH_MSG_SIZE, sig, 0,
			ecdsa_VerifSigOfHashCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	/* Positive verification test BRAINPOOL384R1 */
	pubKey.x = (uint8_t *) test_ver_pubKey_x_bp384r1;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_bp384r1;
	sig.r    = (uint8_t *) test_ver_sign_r_bp384r1;
	sig.s    = (uint8_t *) test_ver_sign_s_bp384r1;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature_of_message(ECDSA_CURVE_BP384R1, pubKey,
			(const void *)test_ver_msg, HASH_MSG_SIZE, sig, 0,
			ecdsa_VerifSigOfHashCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Negative test of ecdsa_verify_signature
 *
 */
void ecc_test_signature_verification_negative(void)
{
	ecdsa_pubkey_t pubKey;
	ecdsa_hash_t hash;
	ecdsa_sig_t sig;

	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);

	/* Negative verification test NISTP256 */
	pubKey.x = (uint8_t *) test_ver_pubKey_x_nistp256;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_nistp256;
	sig.r    = (uint8_t *) test_ver_sign_r_nistp256;
	/* Using twice r: giving (r,r) instead of (r,s) */
	sig.s    = (uint8_t *) test_ver_sign_r_nistp256;
	hash     = (ecdsa_hash_t) test_ver_hash_256;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_NISTP256, pubKey, hash,
			sig, 0, ecdsa_VerifSigOfHashCallback_negative, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	/* Negative verification test BRAINPOOL256R1 */
	pubKey.x = (uint8_t *) test_ver_pubKey_x_bp256r1;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_bp256r1;
	sig.r    = (uint8_t *) test_ver_sign_r_bp256r1;
	/* Using twice r: giving (r,r) instead of (r,s) */
	sig.s    = (uint8_t *) test_ver_sign_r_bp256r1;
	hash     = (ecdsa_hash_t) test_ver_hash_256;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_BP256R1, pubKey, hash,
			sig, 0, ecdsa_VerifSigOfHashCallback_negative, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	/* Negative verification test BRAINPOOL384R1 */
	pubKey.x = (uint8_t *) test_ver_pubKey_x_bp384r1;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_bp384r1;
	sig.r    = (uint8_t *) test_ver_sign_r_bp384r1;
	/* Using twice r: giving (r,r) instead of (r,s) */
	sig.s    = (uint8_t *) test_ver_sign_r_bp384r1;
	hash     = (ecdsa_hash_t) test_ver_hash_384;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_BP384R1, pubKey, hash,
			sig, 0, ecdsa_VerifSigOfHashCallback_negative, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Test of ecdsa_verify_signature with a curve not supported
 * and library not active
 *
 */
void ecc_test_signature_verification_invalid(void)
{
	ecdsa_pubkey_t pubKey;
	ecdsa_hash_t hash;
	ecdsa_sig_t sig;


	pubKey.x = (uint8_t *) test_ver_pubKey_x_nistp256;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_nistp256;
	sig.r    = (uint8_t *) test_ver_sign_r_nistp256;
	sig.s    = (uint8_t *) test_ver_sign_s_nistp256;
	hash     = (ecdsa_hash_t) test_ver_hash_256;

	/* Invalid state test */
	VTEST_CHECK_RESULT(
		ecdsa_verify_signature(ECDSA_CURVE_NISTP256, pubKey, hash,
			sig, 0, ecdsa_VerifSigOfHashCallback, (void *)0),
		ECDSA_NOT_INITIALIZED);

	/* Not supported curve test */
	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
	VTEST_CHECK_RESULT(
		ecdsa_verify_signature(ECDSA_CURVE_NOT_SUPP, pubKey, hash,
			sig, 0, ecdsa_VerifSigOfHashCallback, (void *)0),
		ECDSA_EXECUTER_UNSUPPORTED_FUNCTION);
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Positive test of ecdsa_verify_signature (SM2 algo)
 *
 */
void ecc_test_sm2_signature_verification(void)
{
	ecdsa_pubkey_t pubKey;
	ecdsa_hash_t hash;
	ecdsa_sig_t sig;

	VTEST_CHECK_RESULT(ecdsa_open_SMx(), ECDSA_NO_ERROR);

	/* Positive verification test SM2 256 */
	pubKey.x = (uint8_t *) test_ver_pubKey_x_sm2;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_sm2;
	sig.r    = (uint8_t *) test_ver_sign_r_sm2;
	sig.s    = (uint8_t *) test_ver_sign_s_sm2;
	hash     = (ecdsa_hash_t) test_ver_hash_sm2;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_SM2P256, pubKey, hash,
			sig, 0, ecdsa_VerifSigOfHashCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Positive test of ecdsa_verify_signature_of_message (SM2 algo)
 *
 */
void ecc_test_sm2_signature_verification_message(void)
{
	ecdsa_pubkey_t pubKey;
	ecdsa_sig_t sig;

	VTEST_CHECK_RESULT(ecdsa_open_SMx(), ECDSA_NO_ERROR);

	/* Positive verification test SM2 256 */
	pubKey.x = (uint8_t *) test_ver_pubKey_x_sm2;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_sm2;
	sig.r    = (uint8_t *) test_ver_sign_r_sm2;
	sig.s    = (uint8_t *) test_ver_sign_s_sm2;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature_of_message(ECDSA_CURVE_SM2P256, pubKey,
			(const void *)test_ver_msg, HASH_MSG_SIZE, sig, 0,
			ecdsa_VerifSigOfHashCallback, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Negative test of ecdsa_verify_signature (SM2 algo)
 *
 */
void ecc_test_sm2_signature_verification_negative(void)
{
	ecdsa_pubkey_t pubKey;
	ecdsa_hash_t hash;
	ecdsa_sig_t sig;

	VTEST_CHECK_RESULT(ecdsa_open_SMx(), ECDSA_NO_ERROR);

	/* Negative verification test SM2 256 */
	pubKey.x = (uint8_t *) test_ver_pubKey_x_sm2;
	pubKey.y = (uint8_t *) test_ver_pubKey_y_sm2;
	sig.r    = (uint8_t *) test_ver_sign_r_sm2;
	/* Using twice r: giving (r,r) instead of (r,s) */
	sig.s    = (uint8_t *) test_ver_sign_r_sm2;
	hash     = (ecdsa_hash_t) test_ver_hash_sm2;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_verify_signature(ECDSA_CURVE_SM2P256, pubKey, hash,
			sig, 0, ecdsa_VerifSigOfHashCallback_negative, (void *)0),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Positive test of ecdsa_decompress_public_key
 *
 */
void ecc_test_pubkey_decompression(void)
{
	ecdsa_pubkey_t pubKey;
	ecdsa_curveid_t curveID;

	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);

	/* Positive key decompression test NISTP256 */
	curveID = ECDSA_CURVE_NISTP256;
	pubKey.x = test_dec_pubKey_x_nistp256;
	pubKey.y = test_dec_pubKey_y_nistp256;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_decompress_public_key(curveID, pubKey, 0,
			my_ecdsa_DecompressPubKeyCallback, (void *)&curveID),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	/* Positive key decompression test BP256R1 */
	curveID = ECDSA_CURVE_BP256R1;
	pubKey.x = test_dec_pubKey_x_bp256r1;
	pubKey.y = test_dec_pubKey_y_bp256r1;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_decompress_public_key(curveID, pubKey, 0,
			my_ecdsa_DecompressPubKeyCallback, (void *)&curveID),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	/* Positive key decompression test BP384R1 */
	curveID = ECDSA_CURVE_BP384R1;
	pubKey.x = test_dec_pubKey_x_bp384r1;
	pubKey.y = test_dec_pubKey_y_bp384r1;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_decompress_public_key(curveID, pubKey, 0,
			my_ecdsa_DecompressPubKeyCallback, (void *)&curveID),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Negative test of ecdsa_decompress_public_key
 *
 */
void ecc_test_pubkey_decompression_negative(void)
{
	ecdsa_pubkey_t pubKey;
	ecdsa_curveid_t curveID;

	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);

	/* Negative key decompression test NISTP256 */
	curveID = ECDSA_CURVE_NISTP256;
	pubKey.x = test_dec_pubKey_x_nistp256;
	pubKey.y = test_dec_pubKey_y_neg_nistp256;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_decompress_public_key(curveID, pubKey, 0,
			my_ecdsa_DecompressPubKeyCallback_negative, (void *)&curveID),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	/* Negative key decompression test BP256R1 */
	curveID = ECDSA_CURVE_BP256R1;
	pubKey.x = test_dec_pubKey_x_bp256r1;
	pubKey.y = test_dec_pubKey_y_neg_bp256r1;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_decompress_public_key(curveID, pubKey, 0,
			my_ecdsa_DecompressPubKeyCallback_negative, (void *)&curveID),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	/* Negative key decompression test BP384R1 */
	curveID = ECDSA_CURVE_BP384R1;
	pubKey.x = test_dec_pubKey_x_bp384r1;
	pubKey.y = test_dec_pubKey_y_neg_bp384r1;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_decompress_public_key(curveID, pubKey, 0,
			my_ecdsa_DecompressPubKeyCallback_negative, (void *)&curveID),
		ECDSA_NO_ERROR, count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Test of ecdsa_decompress_public_key with not supported curve
 * and library not active
 *
 */
void ecc_test_pubkey_decompression_invalid(void)
{
	ecdsa_pubkey_t pubKey;

	pubKey.x = test_dec_pubKey_x_nistp256;
	pubKey.y = test_dec_pubKey_y_neg_nistp256;

	/* Invalid state test */
	VTEST_CHECK_RESULT(
		ecdsa_decompress_public_key(ECDSA_CURVE_NOT_SUPP, pubKey, 0,
			my_ecdsa_DecompressPubKeyCallback, (void *)0),
		ECDSA_NOT_INITIALIZED);

	/* Not supported curve test */
	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
	VTEST_CHECK_RESULT(
		ecdsa_decompress_public_key(ECDSA_CURVE_NOT_SUPP, pubKey, 0,
			my_ecdsa_DecompressPubKeyCallback, (void *)0),
		ECDSA_EXECUTER_UNSUPPORTED_FUNCTION);
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Positive test of hash APIs
 *
 */
void ecc_test_hash(void)
{
	uint8_t sha256_hash_got[LENGTH_DOMAIN_PARAMS_256];
	uint8_t sha384_hash_got[LENGTH_DOMAIN_PARAMS_384];
	uint8_t sha512_hash_got[LENGTH_DOMAIN_PARAMS_512];

	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
	ecdsa_sha256((const void *) test_hash_msg, HASH_MSG_SIZE,
		sha256_hash_got);
	VTEST_CHECK_RESULT(memcmp((const void *) test_hash_msg_exp_256,
		(const void *) sha256_hash_got, LENGTH_DOMAIN_PARAMS_256),
		MEMCMP_IDENTICAL);
	ecdsa_sha384((const void *) test_hash_msg, HASH_MSG_SIZE,
		sha384_hash_got);
	VTEST_CHECK_RESULT(memcmp((const void *) test_hash_msg_exp_384,
		(const void *) sha384_hash_got, LENGTH_DOMAIN_PARAMS_384),
		MEMCMP_IDENTICAL);
	ecdsa_sha512((const void *) test_hash_msg, HASH_MSG_SIZE,
		sha512_hash_got);
	VTEST_CHECK_RESULT(memcmp((const void *) test_hash_msg_exp_512,
		(const void *) sha512_hash_got, LENGTH_DOMAIN_PARAMS_512),
		MEMCMP_IDENTICAL);
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Negative test of hash APIs
 *
 */
void ecc_test_hash_negative(void)
{
	uint8_t sha256_hash_got[LENGTH_DOMAIN_PARAMS_256];
	uint8_t sha384_hash_got[LENGTH_DOMAIN_PARAMS_384];
	uint8_t sha512_hash_got[LENGTH_DOMAIN_PARAMS_512];

	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
	ecdsa_sha256((const void *) test_hash_msg_neg, HASH_MSG_SIZE,
		sha256_hash_got);
	VTEST_CHECK_RESULT(!memcmp((const void *) test_hash_msg_exp_256,
		(const void *) sha256_hash_got, LENGTH_DOMAIN_PARAMS_256),
		MEMCMP_IDENTICAL);
	ecdsa_sha384((const void *) test_hash_msg_neg, HASH_MSG_SIZE,
		sha384_hash_got);
	VTEST_CHECK_RESULT(!memcmp((const void *) test_hash_msg_exp_384,
		(const void *) sha384_hash_got, LENGTH_DOMAIN_PARAMS_384),
		MEMCMP_IDENTICAL);
	ecdsa_sha512((const void *) test_hash_msg_neg, HASH_MSG_SIZE,
		sha512_hash_got);
	VTEST_CHECK_RESULT(!memcmp((const void *) test_hash_msg_exp_512,
		(const void *) sha512_hash_got, LENGTH_DOMAIN_PARAMS_512),
		MEMCMP_IDENTICAL);
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Positive test of hash APIs
 *
 */
void ecc_test_hash_invalid(void)
{
	uint8_t sha256_hash_got[LENGTH_DOMAIN_PARAMS_256];
	uint8_t sha384_hash_got[LENGTH_DOMAIN_PARAMS_384];
	uint8_t sha512_hash_got[LENGTH_DOMAIN_PARAMS_512];

	/* Invalid state test */
	VTEST_CHECK_RESULT(ecdsa_sha256((const void *) test_hash_msg,
		HASH_MSG_SIZE, sha256_hash_got), ECDSA_NOT_INITIALIZED);
	VTEST_CHECK_RESULT(ecdsa_sha384((const void *) test_hash_msg,
		HASH_MSG_SIZE, sha384_hash_got), ECDSA_NOT_INITIALIZED);
	VTEST_CHECK_RESULT(ecdsa_sha512((const void *) test_hash_msg,
		HASH_MSG_SIZE, sha512_hash_got), ECDSA_NOT_INITIALIZED);
}

/**
 *
 * @brief Positive test of ecdsa_reconstruct_public_key
 *
 */
void ecc_test_pubkey_reconstruction(void)
{
	ecdsa_hash_t hash;
	ecdsa_point_t rec_data;
	ecdsa_point_t caPubKey;
	ecdsa_curveid_t curveID;

	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);

	/* Positive reconstruction test NISTP256 */
	curveID    = ECDSA_CURVE_NISTP256;
	hash       = (uint8_t *) test_rec_hash_256;
	rec_data.x = (uint8_t *) test_rec_pubKey_data_x_nistp256;
	rec_data.y = (uint8_t *) test_rec_pubKey_data_y_nistp256;
	caPubKey.x = (uint8_t *) test_rec_ca_pubKey_x_nistp256;
	caPubKey.y = (uint8_t *) test_rec_ca_pubKey_y_nistp256;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_reconstruct_public_key(curveID, hash, rec_data,
			caPubKey, 0, my_ecdsa_ReconPubKeyCallback,
			(void *)&curveID), ECDSA_NO_ERROR,
		count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	/* Positive reconstruction test BP256R1 */
	curveID    = ECDSA_CURVE_BP256R1;
	hash       = (uint8_t *) test_rec_hash_256;
	rec_data.x = (uint8_t *) test_rec_pubKey_data_x_bp256r1;
	rec_data.y = (uint8_t *) test_rec_pubKey_data_y_bp256r1;
	caPubKey.x = (uint8_t *) test_rec_ca_pubKey_x_bp256r1;
	caPubKey.y = (uint8_t *) test_rec_ca_pubKey_y_bp256r1;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_reconstruct_public_key(curveID, hash, rec_data,
			caPubKey, 0, my_ecdsa_ReconPubKeyCallback,
			(void *)&curveID), ECDSA_NO_ERROR,
		count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Negative test of ecdsa_reconstruct_public_key
 *
 */
void ecc_test_pubkey_reconstruction_negative(void)
{
	ecdsa_hash_t hash;
	ecdsa_point_t rec_data;
	ecdsa_point_t caPubKey;
	ecdsa_curveid_t curveID;

	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);

	/* Negative reconstruction test NISTP256 */
	curveID    = ECDSA_CURVE_NISTP256;
	hash       = (uint8_t *) test_rec_hash_256;
	rec_data.x = (uint8_t *) test_rec_pubKey_data_x_nistp256;
	rec_data.y = (uint8_t *) test_rec_pubKey_data_y_nistp256;
	/* Using y coordinate twice for CA public key */
	caPubKey.x = (uint8_t *) test_rec_ca_pubKey_y_nistp256;
	caPubKey.y = (uint8_t *) test_rec_ca_pubKey_y_nistp256;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_reconstruct_public_key(curveID, hash, rec_data,
			caPubKey, 0, my_ecdsa_ReconPubKeyCallback_negative,
			(void *)&curveID), ECDSA_NO_ERROR,
		count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	/* Negative reconstruction test BP256R1 */
	curveID    = ECDSA_CURVE_BP256R1;
	hash       = (uint8_t *) test_rec_hash_256;
	rec_data.x = (uint8_t *) test_rec_pubKey_data_x_bp256r1;
	rec_data.y = (uint8_t *) test_rec_pubKey_data_y_bp256r1;
	/* Using y coordinate twice for CA public key */
	caPubKey.x = (uint8_t *) test_rec_ca_pubKey_y_bp256r1;
	caPubKey.y = (uint8_t *) test_rec_ca_pubKey_y_bp256r1;
	VTEST_CHECK_RESULT_ASYNC_INC(
		ecdsa_reconstruct_public_key(curveID, hash, rec_data,
			caPubKey, 0, my_ecdsa_ReconPubKeyCallback_negative,
			(void *)&curveID), ECDSA_NO_ERROR,
		count_async);
	VTEST_CHECK_RESULT_ASYNC_WAIT(count_async, TIME_UNIT_10_MS);

	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Test of ecdsa_reconstruct_public_key with a not supported curve and
 * library not active
 *
 */
void ecc_test_pubkey_reconstruction_invalid(void)
{
	ecdsa_hash_t hash;
	ecdsa_point_t rec_data;
	ecdsa_point_t caPubKey;

	hash       = (uint8_t *) test_rec_hash_256;
	rec_data.x = (uint8_t *) test_rec_pubKey_data_x_nistp256;
	rec_data.y = (uint8_t *) test_rec_pubKey_data_y_nistp256;
	caPubKey.x = (uint8_t *) test_rec_ca_pubKey_x_nistp256;
	caPubKey.y = (uint8_t *) test_rec_ca_pubKey_y_nistp256;

	/* Invalid state test */
	VTEST_CHECK_RESULT(
		ecdsa_reconstruct_public_key(ECDSA_CURVE_NISTP256, hash,
			rec_data, caPubKey, 0, my_ecdsa_ReconPubKeyCallback,
			(void *)0),
		ECDSA_NOT_INITIALIZED);

	/* Not supported curve test */
	VTEST_CHECK_RESULT(ecdsa_open(), ECDSA_NO_ERROR);
	VTEST_CHECK_RESULT(
		ecdsa_reconstruct_public_key(ECDSA_CURVE_NOT_SUPP, hash,
			rec_data, caPubKey, 0, my_ecdsa_ReconPubKeyCallback,
			(void *)0),
		ECDSA_EXECUTER_UNSUPPORTED_FUNCTION);

	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Positive test of SM3 hash APIs
 *
 */
void ecc_test_sm3(void)
{
	uint8_t sm3_got[LENGTH_DOMAIN_PARAMS_256];

	VTEST_CHECK_RESULT(ecdsa_open_SMx(), ECDSA_NO_ERROR);
	VTEST_CHECK_RESULT(ecdsa_sm3((const void *) test_hash_msg,
		HASH_MSG_SIZE, sm3_got), ECDSA_NO_ERROR);
	VTEST_CHECK_RESULT(memcmp((const void *) test_sm3_exp,
		(const void *) sm3_got, LENGTH_DOMAIN_PARAMS_256),
		MEMCMP_IDENTICAL);
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Negative test of SM3 hash APIs
 *
 */
void ecc_test_sm3_negative(void)
{
	uint8_t sm3_got[LENGTH_DOMAIN_PARAMS_256];

	VTEST_CHECK_RESULT(ecdsa_open_SMx(), ECDSA_NO_ERROR);
	VTEST_CHECK_RESULT(ecdsa_sm3((const void *) test_hash_msg_neg,
		HASH_MSG_SIZE, sm3_got), ECDSA_NO_ERROR);
	VTEST_CHECK_RESULT(!memcmp((const void *) test_sm3_exp,
		(const void *) sm3_got, LENGTH_DOMAIN_PARAMS_256),
		MEMCMP_IDENTICAL);
	VTEST_CHECK_RESULT(ecdsa_close(), ECDSA_NO_ERROR);
}

/**
 *
 * @brief Positive test of SM3 hash APIs
 *
 */
void ecc_test_sm3_invalid(void)
{
	uint8_t sm3_got[LENGTH_DOMAIN_PARAMS_256];

	/* Invalid state test */
	VTEST_CHECK_RESULT(ecdsa_sm3((const void *) test_hash_msg,
		HASH_MSG_SIZE, sm3_got), ECDSA_NOT_INITIALIZED);
}

