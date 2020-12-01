
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
 * @file SEkeyinjection.c
 *
 * @brief Tests for SE Key Injection (requirements R11.*)
 *
 */

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <v2xSe.h>
#include "vtest.h"
#include "SEmisc.h"
#include "SEkeyinjection.h"

/**
 * Name of the file containing the signed message used for the
 * KEK key exchange operation
 */
#define SIGNED_MESSAGE_KEY_EXCHANGE_FILENAME \
	"/etc/seco_hsm/key_exchange_kek_gen_en_sign_msg.bin"

/** Length in bytes of the signed message for the KEK key exchange operation */
#define SIGNED_MESSAGE_KEY_EXCHANGE_SIZE 0x360

/**
 * Length in bytes of the input key area ; it is equal to the size of:
 *  IV (12 bytes) + ciphertext + Tag (16 bytes).
 */
#define ENCRYPTED_KEY_SIZE	60

/** Common IV used to encrypt keys to be injectedected */
#define ENCRYPTED_KEY_IV	0x00, 0x01, 0x02, 0x03, \
				0x04, 0x05, 0x06, 0x07, \
				0x08, 0x09, 0x0a, 0x0b

/* NIST-P256 */
static uint8_t refPrivKey1[] = {
	0x5d, 0xc4, 0x91, 0xfa, 0x8b, 0xd7, 0xbe, 0x62,
	0xaa, 0x83, 0xa4, 0x2e, 0xf1, 0x1d, 0x80, 0xd8,
	0x47, 0x2c, 0x5d, 0xe1, 0xbb, 0x76, 0x72, 0xef,
	0x5d, 0x54, 0x10, 0xb2, 0x17, 0xd5, 0x8f, 0x78
};

static TypePublicKey_t refPubKey1 = {
	.x = {
		0x06, 0xc4, 0x3f, 0x2d, 0x70, 0x32, 0x85, 0x6a,
		0xbb, 0x2b, 0x23, 0x7e, 0x91, 0x92, 0xba, 0x78,
		0x60, 0xa2, 0x00, 0xcb, 0xb8, 0xb4, 0xfd, 0x90,
		0x6e, 0x06, 0xb0, 0xc9, 0x5b, 0xfb, 0x98, 0xaf,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	},
	.y = {
		0xdb, 0xe7, 0x77, 0x47, 0x86, 0xed, 0xe8, 0x0a,
		0xee, 0x50, 0xf2, 0xaf, 0x84, 0x22, 0x31, 0xd3,
		0x61, 0xa9, 0x30, 0xbf, 0xcb, 0xeb, 0x75, 0x39,
		0xd0, 0x0a, 0xa5, 0x45, 0x27, 0xe3, 0xba, 0x0a,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	}
};

/* NIST-P256 */
static uint8_t refPrivKey2[] = {
	0x59, 0xb2, 0x30, 0xa0, 0x94, 0xee, 0xc2, 0x38,
	0x49, 0xd5, 0x53, 0xce, 0xe6, 0xbe, 0xc5, 0x0f,
	0x3a, 0x82, 0xd2, 0xa2, 0x1d, 0x9f, 0xf4, 0x7a,
	0x6b, 0x43, 0x51, 0xe1, 0xdd, 0x38, 0x35, 0x8c
};

static TypePublicKey_t refPubKey2 = {
	.x = {
		0xc8, 0x91, 0xa4, 0x9a, 0xa3, 0x4f, 0xef, 0x2c,
		0xf1, 0xbb, 0x06, 0x09, 0xa6, 0xc2, 0x03, 0x54,
		0xe5, 0x99, 0x8f, 0x35, 0x55, 0xe5, 0x13, 0x8a,
		0x41, 0xdc, 0xc2, 0xaf, 0x62, 0x09, 0x88, 0x3e,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	},
	.y = {
		0x4e, 0xa1, 0x20, 0x95, 0x45, 0x20, 0x55, 0x0c,
		0x28, 0x79, 0x62, 0x4c, 0x47, 0x38, 0x78, 0x4a,
		0x29, 0xa8, 0xcc, 0x98, 0xe0, 0x95, 0xe7, 0x0f,
		0x74, 0xc9, 0x0b, 0x8e, 0xa0, 0x92, 0xa1, 0x78,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	}
};

/* BP256R1 */
static uint8_t refPrivKey3[] = {
	0x96, 0x90, 0x0c, 0xbd, 0xf7, 0xc1, 0xec, 0xf0,
	0xcd, 0x82, 0x6d, 0x1b, 0x6c, 0xae, 0x13, 0x3a,
	0xd5, 0xf2, 0x68, 0x17, 0xa4, 0x37, 0x1d, 0xcc,
	0x84, 0x4e, 0xd0, 0x42, 0x16, 0x82, 0xaf, 0x76
};

static TypePublicKey_t refPubKey3 = {
	.x = {
		0x6c, 0x83, 0xca, 0x72, 0x28, 0x22, 0x2b, 0xee,
		0x82, 0xea, 0x87, 0xac, 0x43, 0x31, 0xe3, 0x65,
		0xf9, 0x90, 0x93, 0x54, 0x4b, 0x6b, 0x5a, 0x50,
		0x6d, 0x69, 0x13, 0xaf, 0x41, 0x1f, 0xf2, 0xce,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	},
	.y = {
		0x52, 0x62, 0x9a, 0x3d, 0x01, 0x2a, 0xad, 0x18,
		0x48, 0x64, 0x8f, 0x8f, 0x53, 0xad, 0xc7, 0x2a,
		0x1b, 0xe3, 0xf5, 0x85, 0xb8, 0x0f, 0xb7, 0x41,
		0x36, 0x78, 0x2d, 0x15, 0xac, 0x1b, 0x41, 0xf2,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	}
};

/**
 * This structure describes the format that OpenSLL uses to encode
 * public keys for 256 bit curves for POINT_CONVERSION_UNCOMPRESSED/HYBRID
 * formats
 */
typedef struct
{
	/** Z octet */
	uint8_t z;
	/** X coordinate of public key */
	uint8_t x[V2XSE_256_EC_PUB_KEY_XY_SIZE];
	/** Y coordinate of public key */
	uint8_t y[V2XSE_256_EC_PUB_KEY_XY_SIZE];
} sslPubKey256_t;

/**
 *
 * @brief Check whether curveId is 256 bits
 *
 * This function checks whether the ECC curve corresponding the the keyType
 * passed as parameter is 256 bits or not.
 *
 * @param curveId ECC curve identifier
 *
 * @return 1 if ECC curve is 256 bits, 0 if invalid or not 256 bits
 *
 */
static int32_t is256bitCurve(TypeCurveId_t curveId)
{
	int32_t retval = 0;

	switch (curveId) {
		case V2XSE_CURVE_NISTP256:
		case V2XSE_CURVE_BP256R1:
		case V2XSE_CURVE_BP256T1:
		case V2XSE_CURVE_SM2_256:
			retval = 1;
	}
	return retval;
}

/**
 *
 * @brief Convert public key from OpenSSL to v2xSe API format
 *
 * This function converts a public key from OpenSSL to v2xSe API format.
 * The OpenSSL API format is as follows:
 *    - POINT_CONVERSION_COMPRESSED:
 *      the point is encoded as z||x, where the octet z specifies
 *      which solution of the quadratic equation y is
 *    - POINT_CONVERSION_UNCOMPRESSED:
 *      the point is encoded as z||x||y, where z is the octet signifying
 *      the UNCOMPRESSED form has been used
 *    - POINT_CONVERSION_HYBRID:
 *      the point is encoded as z||x||y, where the octet z specifies
 *      which solution of the quadratic equation y is
 * The v2xSe API format is as follows for all curve sizes:
 *  - x in bits 0 - 47, y in bits 48 - 95
 *  - in case of 256 bit curves, bits 32 - 47 of x and y unused
 *
 * @param curveId ECC curve type in V2X SE API format
 * @param pPublicKeyPlain location of the public key in v2xSe API format
 * @param pSslKey location of buffer to place public key in OpenSSL API format
 * @param ssl_conversion controls how an EC_POINT data is encoded
 *
 */
static void convertPublicKeyToV2xApi(TypeCurveId_t curveId,
		TypePublicKey_t *pPublicKeyPlain, uint8_t *pSslKey,
		point_conversion_form_t ssl_conversion)
{
	sslPubKey256_t *sslApiPtr = (sslPubKey256_t*)pSslKey;
	int is_not_supported = -1;

	/* TODO Eventually add support for other algo */
	VTEST_CHECK_RESULT(is256bitCurve(curveId), 1);

	switch (ssl_conversion) {
		case POINT_CONVERSION_UNCOMPRESSED:
			VTEST_CHECK_RESULT(sslApiPtr->z,
						 POINT_CONVERSION_UNCOMPRESSED);
			/* fall through */
		case POINT_CONVERSION_HYBRID:
			memcpy(pPublicKeyPlain->x, sslApiPtr->x,
						sizeof(sslApiPtr->x));
			memcpy(pPublicKeyPlain->y, sslApiPtr->y,
						sizeof(sslApiPtr->y));
			break;
		default:
			/* TODO Eventually add support for compressed point */
			VTEST_CHECK_RESULT(ssl_conversion, is_not_supported);
			break;
	}
}

/**
 *
 * @brief Convert public key from v2xSe to OpenSSL API format
 *
 * This function converts a public key from v2xSe to OpenSSL API format.
 * The v2xSe API format is as follows for all curve sizes:
 *  - x in bits 0 - 47, y in bits 48 - 95
 *  - in case of 256 bit curves, bits 32 - 47 of x and y unused
 * The OpenSSL API format is as follows:
 *    - POINT_CONVERSION_COMPRESSED:
 *      the point is encoded as z||x, where the octet z specifies
 *      which solution of the quadratic equation y is
 *    - POINT_CONVERSION_UNCOMPRESSED:
 *      the point is encoded as z||x||y, where z is the octet signifying
 *      the UNCOMPRESSED form has been used
 *    - POINT_CONVERSION_HYBRID:
 *      the point is encoded as z||x||y, where the octet z specifies
 *      which solution of the quadratic equation y is
 *
 * @param curveId ECC curve type in V2X SE API format
 * @param pPublicKeyPlain location of the public key in v2xSe API format
 * @param pSslKey location of buffer to place public key in OpenSSL API format
 * @param ssl_conversion controls how an EC_POINT data is encoded
 *
 */
static void convertPublicKeyToSslApi(TypeCurveId_t curveId,
		TypePublicKey_t *pPublicKeyPlain, uint8_t *pSslKey,
		point_conversion_form_t ssl_conversion)
{
	sslPubKey256_t *sslApiPtr = (sslPubKey256_t*)pSslKey;
	int is_not_supported = -1;

	/* TODO Eventually add support for other algo */
	VTEST_CHECK_RESULT(is256bitCurve(curveId), 1);

	switch (ssl_conversion) {
		case POINT_CONVERSION_UNCOMPRESSED:
			sslApiPtr->z = POINT_CONVERSION_UNCOMPRESSED;
			memcpy(sslApiPtr->x, pPublicKeyPlain->x,
						sizeof(sslApiPtr->x));
			memcpy(sslApiPtr->y, pPublicKeyPlain->y,
						sizeof(sslApiPtr->y));
			break;
		default:
			/* TODO Eventually add support for other conversion forms */
			VTEST_CHECK_RESULT(ssl_conversion, is_not_supported);
			break;
	}
}

/**
 *
 * @brief Test v2xSe_endKeyInjection for expected behaviour
 *
 * This function tests v2xSe_endKeyInjection for expected behaviour
 * The following behaviours are tested:
 *  - key injection fails for EU applet (deprecated API for HSM implementation)
 *  - key injection fails for US applet (deprecated API for HSM implementation)
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
	/* Move to ACTIVATED state */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);
	/* Verify SE phase is key injection */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_SUCCESS);
	/* Verify value read */
	VTEST_CHECK_RESULT(phase, V2XSE_NORMAL_OPERATING_PHASE);
	/* End key injection must fail */
	VTEST_CHECK_RESULT(v2xSe_endKeyInjection(&statusCode), V2XSE_FAILURE);
	/* Verify SE phase is still in normal operating */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_SUCCESS);
	/* Verify value read */
	VTEST_CHECK_RESULT(phase, V2XSE_NORMAL_OPERATING_PHASE);

/* Test key injection correctly ended for US applet */
	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of phase */
	VTEST_CHECK_RESULT(removeNvmVariable(US_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state */
	VTEST_CHECK_RESULT(setupActivatedState(e_US), VTEST_PASS);
	/* Verify SE phase is key injection */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_SUCCESS);
	/* Verify value read */
	VTEST_CHECK_RESULT(phase, V2XSE_NORMAL_OPERATING_PHASE);
	/* End key injection must fail */
	VTEST_CHECK_RESULT(v2xSe_endKeyInjection(&statusCode), V2XSE_FAILURE);
	/* Verify SE phase is still in normal operating */
	VTEST_CHECK_RESULT(v2xSe_getSePhase(&phase, &statusCode),
								V2XSE_SUCCESS);
	/* Verify value read */
	VTEST_CHECK_RESULT(phase, V2XSE_NORMAL_OPERATING_PHASE);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/*
 * @brief do_createKek Use key exchange to compute a shared KEK on both sides
 *
 * This function performs a key exchange operation between the test application
 * (initiator) and the HSM (responder) for the Key Exchange Key generation use
 * case, as described in the seco_libs HSM API.
 *
 * The KEK is computed on the HSM side and stored in the @kekId RT key slot.
 * The same KEK is computed as well on the test application side in order to
 * encrypt keys to be injected in the HSM.
 *
 * @param[in]  kekId RT slot in which the KEK is saved in the HSM key store
 * @param[out] kek Pointer to the location where the computed KEK
 *             must be stored
 * @param[in]  kek_size Size of the above pointer, in bytes
 */
static void do_createKek(TypeRtKeyId_t kekId,
			uint8_t *kek, uint32_t kek_size)
{
	TypeSW_t statusCode;
	BN_CTX *bn_ctx = NULL;
	const EC_GROUP *curve_group = NULL;
	EC_KEY *local_key = NULL;
	uint8_t *local_pub_key = NULL;
	size_t local_pub_key_len;
	TypePublicKey_t localPubKey = {0, };
	TypePublicKey_t remotePubKey = {0, };
	uint8_t remote_pub_key[65];
	EC_POINT *remote_point = NULL;
	uint8_t *signed_message;
	char *file = SIGNED_MESSAGE_KEY_EXCHANGE_FILENAME;
	FILE *fd;
	int32_t l = 0;
	uint8_t *pSignedMessage = NULL;
	uint16_t signedMessageLength = 0;
	uint8_t shared_secret[32];
	uint8_t kdf_input[63];
	EVP_MD_CTX *kdf_context = NULL;
	char fixedInput[] = "NXP HSM USER KEY DERIVATION";
	uint32_t key_size;

	/* Move to ACTIVATED state */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);

/* Create initiator's keypair with OpenSSL */
	/* Allocate BIGNUM */
	bn_ctx = BN_CTX_new();
	VTEST_CHECK_RESULT(!bn_ctx, 0);
	/* Create NIST P256 ECC key */
	local_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	VTEST_CHECK_RESULT(!local_key, 0);
	/* Get curve group */
	curve_group = EC_KEY_get0_group(local_key);
	VTEST_CHECK_RESULT(!curve_group, 0);
	/* Generate initiator's P256 key pair */
	VTEST_CHECK_RESULT(EC_KEY_generate_key(local_key), 1);

/* Get initiator's public key */
	/* Get public key length */
	local_pub_key_len = EC_KEY_key2buf(local_key,
		       POINT_CONVERSION_UNCOMPRESSED, &local_pub_key, bn_ctx);
	VTEST_CHECK_RESULT(local_pub_key_len, 65);
	convertPublicKeyToV2xApi(V2XSE_CURVE_NISTP256, &localPubKey,
		local_pub_key, POINT_CONVERSION_UNCOMPRESSED);

/* Fetch signed message, if present */
	signed_message = malloc(SIGNED_MESSAGE_KEY_EXCHANGE_SIZE);
	VTEST_CHECK_RESULT(!signed_message , 0);
	fd = fopen(file, "r");
	if (!fd) {
		perror("Error reading signed message from file");
	} else {
		l = (int32_t)fread(signed_message, 1, SIGNED_MESSAGE_KEY_EXCHANGE_SIZE, fd);
		if (l != SIGNED_MESSAGE_KEY_EXCHANGE_SIZE) {
			fprintf(stderr, "%s has the wrong length (%d != %d): ignoring signed message\n",
					file, l, SIGNED_MESSAGE_KEY_EXCHANGE_SIZE);
		} else {
			pSignedMessage = signed_message;
			signedMessageLength = SIGNED_MESSAGE_KEY_EXCHANGE_SIZE;
		}
		VTEST_CHECK_RESULT(fclose(fd), 0);
	}
	if (!pSignedMessage)
		printf("Signed message not sent\n");

/* Perform key exchange with HSM (responder) to get KEK */
	/*
	 * Send out initiator's pubkey and retrieve responder's pubkey,
	 * along with the KEK id that got computed by HSM
	 */
	VTEST_CHECK_RESULT(v2xSe_createKek(pSignedMessage, signedMessageLength,
				&localPubKey, &remotePubKey, kekId, &statusCode),
							V2XSE_SUCCESS);

/* Create SSL object for HSM public key */
	/* Convert HSM public key to OpenSSL format */
	convertPublicKeyToSslApi(V2XSE_CURVE_NISTP256, &remotePubKey,
		remote_pub_key, POINT_CONVERSION_UNCOMPRESSED);
	/* Create remote point */
	remote_point = EC_POINT_new(curve_group);
	VTEST_CHECK_RESULT(!remote_point, 0);
	/* Set remote point */
	VTEST_CHECK_RESULT(EC_POINT_oct2point(curve_group, remote_point,
					remote_pub_key, 65, bn_ctx), 1);

/* Compute KEK locally */
	/* Perform ECDH */
	VTEST_CHECK_RESULT(ECDH_compute_key(shared_secret, sizeof(shared_secret),
					remote_point, local_key, NULL), 32);

	/*
	 * Perform KDF to generate the KEK, using the formula:
	 *
	 *     kek = SHA_256(counter || Z || fixedInput), where:
	 *          - counter is the value 1 expressed in 32 bit and in big endian format
	 *          - Z is the shared secret generated by the DH key-establishment scheme
	 *          - fixedInput is the literral 'NXP HSM USER KEY DERIVATION'
	 *            (27 bytes, no null termination).
	 */
	kdf_context = EVP_MD_CTX_new();
	VTEST_CHECK_RESULT(!kdf_context, 0);
	/* counter: */
	kdf_input[0] = 0;
	kdf_input[1] = 0;
	kdf_input[2] = 0;
	kdf_input[3] = 1;
	/* Z: */
	memcpy(&kdf_input[4], shared_secret, 32);
	/* fixedInput: */
	memcpy(&kdf_input[36], fixedInput, 27);
	/* kek: */
	key_size = kek_size;
	VTEST_CHECK_RESULT(EVP_DigestInit_ex(kdf_context, EVP_sha256(), NULL), 1);
	VTEST_CHECK_RESULT(EVP_DigestUpdate(kdf_context, kdf_input, sizeof(kdf_input)), 1);
	VTEST_CHECK_RESULT(EVP_DigestFinal_ex(kdf_context, kek, &key_size), 1);
	VTEST_CHECK_RESULT(key_size, kek_size);

/* Clean up SSL objects and contexts */
	EVP_MD_CTX_free(kdf_context);
	EC_POINT_free(remote_point);
	OPENSSL_free(local_pub_key);
	BN_CTX_free(bn_ctx);
	EC_KEY_free(local_key);
	free(signed_message);
}

/**
 *
 * @brief Test v2xSe_createKek for expected behaviour
 *
 * This function tests v2xSe_createKek for expected behaviour
 * The following behaviours are tested:
 *  - perform a key exchange with HSM to get a KEK
 *  - KEK can be computed based on shared secret
 *
 */
void test_createKek(void)
{
	uint8_t kek[32];

	VTEST_RETURN_CONF_IF_NO_V2X_HW();

/* Create a KEK to encrypt and inject desired KEK */
	do_createKek(KEK_SLOT, kek, sizeof(kek));

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/*
 * @brief do_encrypt_key Perform a AES-256 encryption
 *
 * This function performs a AES-256 encryption of some data using a AES
 * key encryption key (KEK).
 *
 * @param[in]  kek AES-256 key to be used for the encryption
 * @param[in]  data Pointer to data to be encrypted (key to inject)
 * @param[out] out Pointer to a buffer to store the encrypted data
 * @param[in]  len Pointer to the data lentgh
 */
static void do_encrypt_key(uint8_t *kek, uint8_t *data, uint8_t *out, int *len)
{
	EVP_CIPHER_CTX *cipher_ctx = NULL;

	/* 256-bit keys for now */
	VTEST_CHECK_RESULT(*len, 32);

/* Encrypt key using KEK passed in parameter */
	cipher_ctx = EVP_CIPHER_CTX_new();
	VTEST_CHECK_RESULT(EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, kek, out), 1);
	VTEST_CHECK_RESULT(EVP_EncryptUpdate(cipher_ctx, &out[12], len, data, *len), 1);
	VTEST_CHECK_RESULT(EVP_EncryptFinal_ex(cipher_ctx, &out[44], len), 1);
	VTEST_CHECK_RESULT(EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, &out[44]), 1);

/* Clean up SSL objects and contexts */
	EVP_CIPHER_CTX_free(cipher_ctx);
}

/**
 *
 * @brief Test v2xSe_injectMaEccPrivateKey for expected behaviour
 *
 * This function tests v2xSe_injectMaEccPrivateKey for expected behaviour
 * The following behaviours are tested:
 *  - MA key can be injected, and queried public key matches expected value
 *
 */
void test_injectMaEccPrivateKey(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	uint8_t kek[32];
	uint8_t enc_key[12 + 48] = { ENCRYPTED_KEY_IV, };
	int enc_len;

	VTEST_RETURN_CONF_IF_NO_V2X_HW();

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, EU applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);

	/* Create a KEK to encrypt keys to be injectected */
	do_createKek(KEK_SLOT, kek, sizeof(kek));

	/* Encrypt and inject MA key (NIST-P256) */
	enc_len = sizeof(refPrivKey1);
	do_encrypt_key(kek, refPrivKey1, enc_key, &enc_len);
	VTEST_CHECK_RESULT(v2xSe_injectMaEccPrivateKey(V2XSE_CURVE_NISTP256,
					&statusCode, &pubKey,
					enc_key, sizeof(enc_key),
					KEK_SLOT), V2XSE_SUCCESS);

	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Retrieve stored MA public key */
	VTEST_CHECK_RESULT(v2xSe_getMaEccPublicKey(&statusCode, &curveId,
						&pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, EU applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);

	/* Create a KEK to encrypt keys to be injectected */
	do_createKek(KEK_SLOT, kek, sizeof(kek));

	/* Encrypt and inject MA key (BP256R1) */
	enc_len = sizeof(refPrivKey3);
	do_encrypt_key(kek, refPrivKey3, enc_key, &enc_len);
	VTEST_CHECK_RESULT(v2xSe_injectMaEccPrivateKey(V2XSE_CURVE_BP256R1,
					&statusCode, &pubKey,
					enc_key, sizeof(enc_key),
					KEK_SLOT), V2XSE_SUCCESS);

	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey3,
						sizeof(TypePublicKey_t)), 0);
	/* Retrieve stored MA public key */
	VTEST_CHECK_RESULT(v2xSe_getMaEccPublicKey(&statusCode, &curveId,
						&pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey3,
						sizeof(TypePublicKey_t)), 0);
/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_injectRtEccPrivateKey for keys in empty slots
 *
 * This function tests v2xSe_injectRtEccPrivateKey for keys in empty slots
 * The following behaviours are tested:
 *  - RT key NIST-P256 can be injected in slot 0, public key matches
 *    expected value
 *  - RT key BP256R1 can be injected in slot 0, public key matches
 *    expected value
 *
 */
void test_injectRtEccPrivateKey_empty(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	uint8_t kek[32];
	uint8_t enc_key[12 + 48] = { ENCRYPTED_KEY_IV, };
	int enc_len;

	VTEST_RETURN_CONF_IF_NO_V2X_HW();

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force key injection mode */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, EU applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);

	/* Create a KEK to encrypt keys to be injectected */
	do_createKek(KEK_SLOT, kek, sizeof(kek));

	/* Encrypt and inject RT key (NISTP-256) */
	enc_len = sizeof(refPrivKey1);
	do_encrypt_key(kek, refPrivKey1, enc_key, &enc_len);
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		enc_key, sizeof(enc_key), KEK_SLOT), V2XSE_SUCCESS);

	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Retrieve stored RT public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(SLOT_ZERO, &statusCode),
								V2XSE_SUCCESS);

	/* Encrypt and inject RT key (BP256R1) */
	enc_len = sizeof(refPrivKey3);
	do_encrypt_key(kek, refPrivKey3, enc_key, &enc_len);
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(SLOT_ZERO,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey,
		enc_key, sizeof(enc_key), KEK_SLOT), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey3,
						sizeof(TypePublicKey_t)), 0);

	/* Retrieve stored RT public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey3,
						sizeof(TypePublicKey_t)), 0);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(SLOT_ZERO, &statusCode),
								V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_injectRtEccPrivateKey for keys in full slots
 *
 * This function tests v2xSe_injectRtEccPrivateKey for keys in full slots
 * The following behaviours are tested:
 *  - key can be injected overwriting RT key in non-zero slot, pub key matches
 *  - key can be injected overwriting RT key in max slot, pub key matches
 */
void test_injectRtEccPrivateKey_overwrite(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;
	uint8_t kek[32];
	uint8_t enc_key[12 + 48] = { ENCRYPTED_KEY_IV, };
	int enc_len;

	VTEST_RETURN_CONF_IF_NO_V2X_HW();

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force key injection mode */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, EU applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);

	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxRtKeysAllowed <= NON_ZERO_SLOT, 0);

	/* Create a KEK to encrypt keys to be injectected */
	do_createKek(KEK_SLOT, kek, sizeof(kek));

	/* Inject key to overwrite - same type as injected */
	enc_len = sizeof(refPrivKey1);
	do_encrypt_key(kek, refPrivKey1, enc_key, &enc_len);
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(NON_ZERO_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		enc_key, sizeof(enc_key), KEK_SLOT), V2XSE_SUCCESS);
	/* Verify public key contents doesn't match ref value */
	VTEST_CHECK_RESULT(!memcmp(&pubKey, &refPubKey2,
						sizeof(TypePublicKey_t)), 0);

	/* Inject RT key */
	enc_len = sizeof(refPrivKey2);
	do_encrypt_key(kek, refPrivKey2, enc_key, &enc_len);
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(NON_ZERO_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		enc_key, sizeof(enc_key), KEK_SLOT), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey2,
						sizeof(TypePublicKey_t)), 0);
	/* Retrieve stored RT public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(NON_ZERO_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey2,
						sizeof(TypePublicKey_t)), 0);

	/* Inject key to overwrite - different type to injected */
	enc_len = sizeof(refPrivKey1);
	do_encrypt_key(kek, refPrivKey1, enc_key, &enc_len);
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(MAX_RT_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey,
		enc_key, sizeof(enc_key), KEK_SLOT), V2XSE_SUCCESS);
	/* Verify public key contents doesn't match ref value */
	VTEST_CHECK_RESULT(!memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Inject RT key */
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(MAX_RT_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		enc_key, sizeof(enc_key), KEK_SLOT), V2XSE_SUCCESS);
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Retrieve stored RT public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(MAX_RT_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);

	/* Delete keys after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(NON_ZERO_SLOT,
						&statusCode), V2XSE_SUCCESS);
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(MAX_RT_SLOT,
						&statusCode), V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_injectBaEccPrivateKey for keys in empty slots
 *
 * This function tests v2xSe_injectBaEccPrivateKey for keys in empty slots
 * The following behaviours are tested:
 *  - BA key can be injected in slot 0, pub key matches expected value
 *
 */
void test_injectBaEccPrivateKey_empty(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	uint8_t kek[32];
	uint8_t enc_key[12 + 48] = { ENCRYPTED_KEY_IV, };
	int enc_len;

	VTEST_RETURN_CONF_IF_NO_V2X_HW();

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force key injection mode */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, EU applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);

	/* Create a KEK to encrypt keys to be injectected */
	do_createKek(KEK_SLOT, kek, sizeof(kek));

	/* Inject BA key (NIST-P256) */
	enc_len = sizeof(refPrivKey1);
	do_encrypt_key(kek, refPrivKey1, enc_key, &enc_len);
	VTEST_CHECK_RESULT(v2xSe_injectBaEccPrivateKey(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		enc_key, sizeof(enc_key), KEK_SLOT), V2XSE_SUCCESS);

	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Retrieve stored BA public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode),
								V2XSE_SUCCESS);

	/* Inject RT key (BP256R1) */
	enc_len = sizeof(refPrivKey3);
	do_encrypt_key(kek, refPrivKey3, enc_key, &enc_len);
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(SLOT_ZERO,
		V2XSE_CURVE_BP256R1, &statusCode, &pubKey,
		enc_key, sizeof(enc_key), KEK_SLOT), V2XSE_SUCCESS);

	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey3,
						sizeof(TypePublicKey_t)), 0);

	/* Retrieve stored RT public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey3,
						sizeof(TypePublicKey_t)), 0);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteRtEccPrivateKey(SLOT_ZERO, &statusCode),
								V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

/**
 *
 * @brief Test v2xSe_injectBaEccPrivateKey for keys in full slots
 *
 * This function tests v2xSe_injectBaEccPrivateKey for keys in full slots
 * The following behaviours are tested:
 *  - key can be injected overwriting BA key in non-zero slot, pub key matches
 *  - key can be injected overwriting BA key in max slot, pub key matches
 *
 */
void test_injectBaEccPrivateKey_overwrite(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	TypeInformation_t seInfo;
	uint8_t kek[32];
	uint8_t enc_key[12 + 48] = { ENCRYPTED_KEY_IV, };
	int enc_len;

	VTEST_RETURN_CONF_IF_NO_V2X_HW();

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force key injection mode */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, EU applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);

	/* Create a KEK to encrypt keys to be injectected */
	do_createKek(KEK_SLOT, kek, sizeof(kek));

	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxRtKeysAllowed <= NON_ZERO_SLOT, 0);

	/* Inject key to overwrite - same type as injected */
	enc_len = sizeof(refPrivKey1);
	do_encrypt_key(kek, refPrivKey1, enc_key, &enc_len);
	VTEST_CHECK_RESULT(v2xSe_injectBaEccPrivateKey(NON_ZERO_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		enc_key, sizeof(enc_key), KEK_SLOT), V2XSE_SUCCESS);
	/* Verify public key contents doesn't match ref value */
	VTEST_CHECK_RESULT(!memcmp(&pubKey, &refPubKey2,
						sizeof(TypePublicKey_t)), 0);
	/* Inject BA key */
	enc_len = sizeof(refPrivKey2);
	do_encrypt_key(kek, refPrivKey2, enc_key, &enc_len);
	VTEST_CHECK_RESULT(v2xSe_injectBaEccPrivateKey(NON_ZERO_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		enc_key, sizeof(enc_key), KEK_SLOT), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey2,
						sizeof(TypePublicKey_t)), 0);
	/* Retrieve stored BA public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(NON_ZERO_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey2,
						sizeof(TypePublicKey_t)), 0);

	/* Inject key to overwrite - different type to injected */
	enc_len = sizeof(refPrivKey2);
	do_encrypt_key(kek, refPrivKey2, enc_key, &enc_len);
	VTEST_CHECK_RESULT(v2xSe_injectBaEccPrivateKey(MAX_BA_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey,
		enc_key, sizeof(enc_key), KEK_SLOT), V2XSE_SUCCESS);
	/* Verify public key contents doesn't match ref value */
	VTEST_CHECK_RESULT(!memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Inject BA key */
	enc_len = sizeof(refPrivKey1);
	do_encrypt_key(kek, refPrivKey1, enc_key, &enc_len);
	VTEST_CHECK_RESULT(v2xSe_injectBaEccPrivateKey(MAX_BA_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		enc_key, sizeof(enc_key), KEK_SLOT), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Retrieve stored BA public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(MAX_BA_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);

	/* Delete keys after use */
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(NON_ZERO_SLOT,
						&statusCode), V2XSE_SUCCESS);
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(MAX_BA_SLOT,
						&statusCode), V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}
