
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

#include <string.h>
#include <v2xSe.h>
#include "vtest.h"
#include "SEmisc.h"
#include "SEkeyinjection.h"

static uint8_t encryptedKey1[] = {
	// IV
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B,
	// CT
	0x35, 0xf6, 0xd2, 0xa2, 0xda, 0x4c, 0x01, 0xb5,
	0x3d, 0x5f, 0xd4, 0x8a, 0xba, 0x80, 0x07, 0xe1,
	0x20, 0x9f, 0xa3, 0x8d, 0x78, 0x2e, 0xee, 0x9c,
	0xc7, 0x5d, 0x1d, 0xcf, 0x94, 0xc5, 0xba, 0x97,
	// Tag
	0x75, 0xd7, 0x2a, 0x90, 0xc7, 0x77, 0xaa, 0x4d,
	0x5f, 0x46, 0x3c, 0x09, 0x9e, 0xc3, 0x45, 0x22,
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
static uint8_t encryptedKey2[] = {
	// IV
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B,
	// CT
	0x31, 0x80, 0x73, 0xf8, 0xc5, 0x75, 0x7d, 0xef,
	0xde, 0x09, 0x23, 0x6a, 0xad, 0x23, 0x42, 0x36,
	0x5d, 0x31, 0x2c, 0xce, 0xde, 0xc7, 0x68, 0x09,
	0xf1, 0x4a, 0x5c, 0x9c, 0x5e, 0x28, 0x00, 0x63,
	// Tag
	0xf3, 0xa5, 0x75, 0x8d, 0xef, 0x16, 0x26, 0x2e,
	0x4a, 0x52, 0xac, 0x96, 0x21, 0x08, 0x1e, 0x6c
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

/**
 *
 * @brief Test v2xSe_getKek for expected behaviour
 *
 * This function tests v2xSe_getKek for expected behaviour
 * The following behaviours are tested:
 *  - common KEK can be retrieved and matches expected value
 *  - unique KEK can be retrieved and does not match common KEK
 *
 */
void test_getKek(void)
{
	uint8_t signedMessage[32] = {13};
	uint8_t commonKek[32];
	uint8_t uniqueKek[32];
	uint16_t kekSize;
	TypeSW_t statusCode;
	uint8_t expectedCommonKek[32] = {
		0x10, 0x2b, 0xcb, 0xe5, 0x4d, 0xd7, 0xb2, 0x33,
		0x94, 0x6a, 0xd9, 0xb0, 0xa8, 0x54, 0x27, 0xaf,
		0xd5, 0x16, 0xf1, 0x8e, 0x6e, 0xa4, 0xf7, 0x4b,
		0xb8, 0x35, 0x1c, 0x37, 0x26, 0x48, 0xc7, 0xfe
	};

	/* Move to ACTIVATED state */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);

/* Test retrieved common KEK matches expected value */
	/* Get common KEK */
	kekSize = sizeof(commonKek);
	VTEST_CHECK_RESULT(v2xSe_getKek(KEK_TYPE_COMMON, signedMessage,
		sizeof(signedMessage), commonKek, &kekSize, &statusCode),
							V2XSE_SUCCESS);
	/* Verify key contents as expected */
	VTEST_CHECK_RESULT(memcmp(expectedCommonKek, commonKek, kekSize),
									0);

/* Test retrieved unique KEK different from common KEK */
	/* Get unique KEK */
	kekSize = sizeof(uniqueKek);
	VTEST_CHECK_RESULT(v2xSe_getKek(KEK_TYPE_UNIQUE, signedMessage,
		sizeof(signedMessage)-1, uniqueKek, &kekSize, &statusCode),
							V2XSE_SUCCESS);
	/* Verify key contents does not match common KEK */
	VTEST_CHECK_RESULT(!memcmp(uniqueKek, commonKek,
					sizeof(expectedCommonKek)), 0);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
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

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, EU applet */
	VTEST_CHECK_RESULT(setupActivatedStateSecurityLevel5(e_EU), VTEST_PASS);

	/* Inject MA key */
	VTEST_CHECK_RESULT(v2xSe_injectMaEccPrivateKey(V2XSE_CURVE_NISTP256,
		&statusCode, &pubKey, encryptedKey1, sizeof(encryptedKey1),
					KEK_TYPE_COMMON), V2XSE_SUCCESS);

	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Retrieve stored MA public key */
	VTEST_CHECK_RESULT(v2xSe_getMaEccPublicKey(&statusCode, &curveId,
						&pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
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
 *  - RT key can be injected in slot 0, public key matches expected value
 *
 */
void test_injectRtEccPrivateKey_empty(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force key injection mode */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, EU applet */
	VTEST_CHECK_RESULT(setupActivatedStateSecurityLevel5(e_EU), VTEST_PASS);

	/* Inject RT key */
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey, encryptedKey1,
			sizeof(encryptedKey1), KEK_TYPE_COMMON), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);

	/* Retrieve stored RT public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Exit key injection to allow key deletion */
	VTEST_CHECK_RESULT(v2xSe_endKeyInjection(&statusCode), V2XSE_SUCCESS);
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

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force key injection mode */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, EU applet */
	VTEST_CHECK_RESULT(setupActivatedStateSecurityLevel5(e_EU), VTEST_PASS);

	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxRtKeysAllowed <= NON_ZERO_SLOT, 0);

	/* Inject key to overwrite - same type as injected */
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(NON_ZERO_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey, encryptedKey1,
		sizeof(encryptedKey1), KEK_TYPE_COMMON), V2XSE_SUCCESS);
	/* Verify public key contents doesn't match ref value */
	VTEST_CHECK_RESULT(!memcmp(&pubKey, &refPubKey2,
						sizeof(TypePublicKey_t)), 0);

	/* Inject RT key */
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(NON_ZERO_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey, encryptedKey2,
		sizeof(encryptedKey2), KEK_TYPE_COMMON), V2XSE_SUCCESS);
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
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(MAX_RT_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey, encryptedKey2,
		sizeof(encryptedKey2), KEK_TYPE_COMMON), V2XSE_SUCCESS);
	/* Verify public key contents doesn't match ref value */
	VTEST_CHECK_RESULT(!memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Inject RT key */
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(MAX_RT_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey, encryptedKey1,
		sizeof(encryptedKey1), KEK_TYPE_COMMON), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Retrieve stored RT public key */
	VTEST_CHECK_RESULT(v2xSe_getRtEccPublicKey(MAX_RT_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);

	/* Exit key injection to allow key deletion */
	VTEST_CHECK_RESULT(v2xSe_endKeyInjection(&statusCode), V2XSE_SUCCESS);
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

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force key injection mode */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, EU applet */
	VTEST_CHECK_RESULT(setupActivatedStateSecurityLevel5(e_EU), VTEST_PASS);

	/* Inject BA key */
	VTEST_CHECK_RESULT(v2xSe_injectBaEccPrivateKey(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey, encryptedKey1,
		sizeof(encryptedKey1), KEK_TYPE_COMMON), V2XSE_SUCCESS);

	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Retrieve stored BA public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(SLOT_ZERO, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Exit key injection to allow key deletion */
	VTEST_CHECK_RESULT(v2xSe_endKeyInjection(&statusCode), V2XSE_SUCCESS);
	/* Delete key after use */
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(SLOT_ZERO, &statusCode),
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

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force key injection mode */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, EU applet */
	VTEST_CHECK_RESULT(setupActivatedStateSecurityLevel5(e_EU), VTEST_PASS);

	/* Get SE info, to know max data slot available */
	VTEST_CHECK_RESULT(v2xSe_getSeInfo(&statusCode, &seInfo),
								V2XSE_SUCCESS);
	/* Check that test constant is in correct range */
	VTEST_CHECK_RESULT(seInfo.maxRtKeysAllowed <= NON_ZERO_SLOT, 0);

	/* Inject key to overwrite - same type as injected */
	VTEST_CHECK_RESULT(v2xSe_injectBaEccPrivateKey(NON_ZERO_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey, encryptedKey1,
		sizeof(encryptedKey1), KEK_TYPE_COMMON), V2XSE_SUCCESS);
	/* Verify public key contents doesn't match ref value */
	VTEST_CHECK_RESULT(!memcmp(&pubKey, &refPubKey2,
						sizeof(TypePublicKey_t)), 0);
	/* Inject BA key */
	VTEST_CHECK_RESULT(v2xSe_injectBaEccPrivateKey(NON_ZERO_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey, encryptedKey2,
		sizeof(encryptedKey2), KEK_TYPE_COMMON), V2XSE_SUCCESS);
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
	VTEST_CHECK_RESULT(v2xSe_injectBaEccPrivateKey(MAX_BA_SLOT,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey, encryptedKey2,
		sizeof(encryptedKey2), KEK_TYPE_COMMON), V2XSE_SUCCESS);
	/* Verify public key contents doesn't match ref value */
	VTEST_CHECK_RESULT(!memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Inject BA key */
	VTEST_CHECK_RESULT(v2xSe_injectBaEccPrivateKey(MAX_BA_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey, encryptedKey1,
		sizeof(encryptedKey1), KEK_TYPE_COMMON), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Retrieve stored BA public key */
	VTEST_CHECK_RESULT(v2xSe_getBaEccPublicKey(MAX_BA_SLOT, &statusCode,
					&curveId, &pubKey), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
	VTEST_CHECK_RESULT(memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);

	/* Exit key injection to allow key deletion */
	VTEST_CHECK_RESULT(v2xSe_endKeyInjection(&statusCode), V2XSE_SUCCESS);
	/* Delete keys after use */
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(NON_ZERO_SLOT,
						&statusCode), V2XSE_SUCCESS);
	VTEST_CHECK_RESULT(v2xSe_deleteBaEccPrivateKey(MAX_BA_SLOT,
						&statusCode), V2XSE_SUCCESS);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}
