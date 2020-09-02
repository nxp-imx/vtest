
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

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <v2xSe.h>
#include "vtest.h"
#include "SEmisc.h"
#include "SEkeyinjection.h"

/** Computes the number of elements that an array contains */
#define NB_ELEM(array) (sizeof((array)) / sizeof((array)[0]))

/** Length in bytes of the root kek. Must be 32 bytes for HSM */
#define COMMON_KEK_SIZE		32

/**
 * Length in bytes of the input key area ; it is equal to the size of:
 *  IV (12 bytes) + ciphertext + Tag (16 bytes).
 */
#define ENCRYPTED_KEY_SIZE	60

/**
 * Known KEK corresponding to the index of the kek_patterns[] array.
 */
enum soc_commonKek_idx {
	SOC_COMMON_KEK_QXP = 0,
	SOC_COMMON_KEK_DXL,
	SOC_COMMON_KEK_DXL_A1,
	SOC_COMMON_KEK_DXLPHANTOM,

	SOC_COMMON_KEK_MAX,
	SOC_COMMON_KEK_UNKOWN = SOC_COMMON_KEK_MAX
};

/**
 * Structure describing test key patterns that can be injected in HSM.
 *
 * To securely inject a key in the HSM key store, the latter is encrypted with
 * a Key Encryption Key (KEK). This KEK can either be common or chip unique.
 * For simplicity of testing, the common KEK is used here. Note that this common
 * KEK is different from a SoC family to another (e.g.: i.MX 8DXL vs. i.MX 8QXP).
 *
 * How to add a new common KEK and associated encrypted keys for a new SoC?
 *
 * 1. Common KEK are retrieved using the test_getKek() function (printed out when
 * 'vtest 110902' fails).
 * 2. This common KEK shall be populated in util/v2xEncryptKey.py to be added
 * in the --kek parameter list.
 * 3. Running the tool with this new KEK generates a couple of encrypted keys.
 * 4. Both these encrypted keys as well as the common KEK shall then be added to
 * the kek_patterns[] table to make 'vtest 11' (key injection tests) successful
 * for this new SoC.
 */
typedef struct {
	/** common KEK retrieved with the above method for a specific SoC */
	uint8_t expectedCommonKek[COMMON_KEK_SIZE];
	/** test key #1 encrypted with expectedCommonKek (refPubKey1 match) */
	uint8_t encryptedKey1[ENCRYPTED_KEY_SIZE];
	/** test key #2 encrypted with expectedCommonKek (refPubKey2 match) */
	uint8_t encryptedKey2[ENCRYPTED_KEY_SIZE];
} testKeyInjection_t;

/**
 * kek_patterns[] contains the KEK and the encrypted test keys for known SoCs.
 * It is possible to add new patterns for new SoCs by following the method
 * described in testKeyInjection_t description.
 */
static testKeyInjection_t kek_patterns[SOC_COMMON_KEK_MAX] = {
	{ /* i.MX8 QXP common kek */
		.expectedCommonKek = {
			0x10, 0x2b, 0xcb, 0xe5, 0x4d, 0xd7, 0xb2, 0x33,
			0x94, 0x6a, 0xd9, 0xb0, 0xa8, 0x54, 0x27, 0xaf,
			0xd5, 0x16, 0xf1, 0x8e, 0x6e, 0xa4, 0xf7, 0x4b,
			0xb8, 0x35, 0x1c, 0x37, 0x26, 0x48, 0xc7, 0xfe
		},
		.encryptedKey1 = {
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
		},
		.encryptedKey2 = {
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
		}
	},
	{ /* i.MX8 DXL common kek */
		.expectedCommonKek = {
			0xda, 0xec, 0x80, 0xc0, 0x0b, 0xbb, 0x02, 0xba,
			0xc8, 0x23, 0x1f, 0x72, 0x40, 0x54, 0x5c, 0x5e,
			0xa4, 0xa8, 0x1d, 0xd9, 0x7d, 0x66, 0x68, 0xf0,
			0x4e, 0x64, 0x41, 0xe1, 0xb1, 0x93, 0x72, 0x8f
		},
		.encryptedKey1 = {
			// IV
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B,
			// CT
			0x83, 0xf, 0x8, 0x37, 0xfb, 0x9, 0x81, 0xbd,
			0x8a, 0xd9, 0xfb, 0x21, 0x3b, 0x5a, 0xd6, 0x8a,
			0x70, 0x51, 0xf1, 0x63, 0xb1, 0xb1, 0xd4, 0xd6,
			0x5a, 0x4c, 0xdf, 0x5d, 0x64, 0x9f, 0x5e, 0x42,
			// Tag
			0x15, 0xb3, 0xed, 0xe2, 0x98, 0xe9, 0xf3, 0x2e,
			0xc4, 0xe4, 0x50, 0xb2, 0xfc, 0x17, 0x17, 0x52,
		},
		.encryptedKey2 = {
			// IV
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B,
			// CT
			0x87, 0x79, 0xa9, 0x6d, 0xe4, 0x30, 0xfd, 0xe7,
			0x69, 0x8f, 0xc, 0xc1, 0x2c, 0xf9, 0x93, 0x5d,
			0xd, 0xff, 0x7e, 0x20, 0x17, 0x58, 0x52, 0x43,
			0x6c, 0x5b, 0x9e, 0xe, 0xae, 0x72, 0xe4, 0xb6,
			// Tag
			0xcc, 0x36, 0x8b, 0x64, 0x7f, 0x58, 0xb9, 0x70,
			0xbf, 0xb6, 0xba, 0x1c, 0xa0, 0xf5, 0x27, 0x32
		}
	},
	{ /* i.MX8 DXL A1 common kek */
		.expectedCommonKek = {
			0xb9, 0xf2, 0x0e, 0xce, 0x04, 0x86, 0x51, 0x88,
			0xa8, 0x1b, 0x8d, 0xd1, 0x34, 0x78, 0x8b, 0x60,
			0x40, 0x22, 0xe0, 0x64, 0x37, 0xef, 0x8a, 0x6f,
			0xa3, 0x2e, 0xe0, 0xec, 0xba, 0xcb, 0xef, 0x62
		},
		.encryptedKey1 = {
			// IV
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B,
			// CT
			0xff, 0xdb, 0x13, 0xc1, 0x1c, 0x7f, 0xc6, 0xbe,
			0x79, 0xba, 0x78, 0xd9, 0x83, 0x36, 0x46, 0xe8,
			0xcc, 0xfd, 0x0b, 0x3e, 0xec, 0x71, 0x6f, 0x1f,
			0x69, 0x5d, 0x04, 0x5e, 0x95, 0x7c, 0xf3, 0x7a,
			// Tag
			0x85, 0x3b, 0x44, 0xae, 0x6f, 0xd2, 0x8e, 0x47,
			0x75, 0x7d, 0x15, 0x79, 0x7f, 0xc9, 0x56, 0xc8

		},
		.encryptedKey2 = {
			// IV
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B,
			// CT
			0xfb, 0xad, 0xb2, 0x9b, 0x03, 0x46, 0xba, 0xe4,
			0x9a, 0xec, 0x8f, 0x39, 0x94, 0x95, 0x03, 0x3f,
			0xb1, 0x53, 0x84, 0x7d, 0x4a, 0x98, 0xe9, 0x8a,
			0x5f, 0x4a, 0x45, 0x0d, 0x5f, 0x91, 0x49, 0x8e,
			// Tag
			0xca, 0xf4, 0xa4, 0x7d, 0x40, 0x9d, 0xf8, 0x8b,
			0x77, 0xf9, 0x61, 0x31, 0x90, 0x7f, 0x49, 0x63
		}
	},
	{ /* i.MX8 DXL EMU C0 common kek */
		.expectedCommonKek = {
			0x07, 0xa0, 0xbe, 0x6a, 0x9b, 0xcc, 0xd9, 0x54,
			0xcf, 0xc7, 0x48, 0xb5, 0xa0, 0xf2, 0x59, 0x2c,
			0x7d, 0x94, 0xb7, 0xa6, 0x1d, 0xf4, 0x9a, 0x8a,
			0xdc, 0x2f, 0x53, 0xc5, 0xbd, 0x1d, 0x34, 0xc6
		},
		.encryptedKey1 = {
			// IV
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B,
			// CT
			0xea, 0xae, 0x64, 0x73, 0x51, 0x6a, 0x33, 0xcd,
			0x13, 0x4c, 0xe4, 0x70, 0x8e, 0x16, 0x01, 0x43,
			0x67, 0x64, 0x03, 0x19, 0x47, 0x90, 0x9d, 0x8c,
			0x53, 0x3e, 0x9a, 0x4d, 0xbc, 0xb0, 0xcc, 0x25,
			// Tag
			0xa3, 0x2d, 0x82, 0x90, 0x0a, 0x2b, 0xdb, 0x3d,
			0x88, 0xf2, 0x96, 0xc4, 0x21, 0x1b, 0x2e, 0x69
		},
		.encryptedKey2 = {
			// IV
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B,
			// CT
			0xee, 0xd8, 0xc5, 0x29, 0x4e, 0x53, 0x4f, 0x97,
			0xf0, 0x1a, 0x13, 0x90, 0x99, 0xb5, 0x44, 0x94,
			0x1a, 0xca, 0x8c, 0x5a, 0xe1, 0x79, 0x1b, 0x19,
			0x65, 0x29, 0xdb, 0x1e, 0x76, 0x5d, 0x76, 0xd1,
			// Tag
			0x85, 0xd9, 0x0d, 0x0f, 0xed, 0xdc, 0xbd, 0x84,
			0x2e, 0xe0, 0x5d, 0x82, 0xb1, 0x3c, 0x8c, 0xe1
		}
	},
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

static enum soc_commonKek_idx which_commonKek(uint8_t kek[], uint16_t kekSize)
{
	enum soc_commonKek_idx k;

	if (kekSize != COMMON_KEK_SIZE)
		return SOC_COMMON_KEK_UNKOWN;

	for (k = 0; k < NB_ELEM(kek_patterns); k++)
		if (!memcmp(kek_patterns[k].expectedCommonKek, kek, kekSize))
			break;

	return k;
}

static bool is_a_valid_commonKek(uint8_t kek[], uint16_t kekSize)
{
	return SOC_COMMON_KEK_UNKOWN != which_commonKek(kek, kekSize);
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
	uint8_t commonKek[32] = {0,};
	uint8_t uniqueKek[32];
	uint16_t kekSize;
	TypeSW_t statusCode;

	/* Move to ACTIVATED state */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);

/* Test retrieved common KEK matches expected value */
	/* Get common KEK */
	kekSize = sizeof(commonKek);
	VTEST_CHECK_RESULT(v2xSe_getKek(KEK_TYPE_COMMON, signedMessage,
		sizeof(signedMessage), commonKek, &kekSize, &statusCode),
							V2XSE_SUCCESS);
	/* Verify key contents as expected */
	VTEST_CHECK_RESULT(is_a_valid_commonKek(commonKek, kekSize), true);
	/* Otherwise print it so it can be easily added for future SoC */
	if (!is_a_valid_commonKek(commonKek, kekSize)) {
		int i;
		printf("ERROR: %s:%d Unknown common KEK (%d bytes):\n",
			       __FILE__, __LINE__, kekSize);
			for (i = 0 ; i < kekSize; i++)
				printf("0x%02x%s", commonKek[i],
						(i + 1) % 8 ? ", " : "\n");
		printf("ERROR: If this test is run on a new SoC revision, please"
			" check testKeyInjection_t comment to add a new KEK and" \
			" encrypted keys in kek_patterns[].\n");
	}

/* Test retrieved unique KEK different from common KEK */
	/* Get unique KEK */
	kekSize = sizeof(uniqueKek);
	VTEST_CHECK_RESULT(v2xSe_getKek(KEK_TYPE_UNIQUE, signedMessage,
		sizeof(signedMessage)-1, uniqueKek, &kekSize, &statusCode),
							V2XSE_SUCCESS);
	/* Verify key contents does not match common KEK */
	VTEST_CHECK_RESULT(is_a_valid_commonKek(uniqueKek, kekSize), false);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
}

static enum soc_commonKek_idx get_soc_commonKek_idx(void)
{
	uint8_t signedMessage[32] = {13};
	uint8_t commonKek[32];
	uint16_t kekSize;
	TypeSW_t statusCode;

	/* Move to ACTIVATED state */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);

/* Test retrieved common KEK matches expected value */
	/* Get common KEK */
	kekSize = sizeof(commonKek);
	VTEST_CHECK_RESULT(v2xSe_getKek(KEK_TYPE_COMMON, signedMessage,
		sizeof(signedMessage), commonKek, &kekSize, &statusCode),
							V2XSE_SUCCESS);
	/* Verify common KEK is valid */
	VTEST_CHECK_RESULT(is_a_valid_commonKek(commonKek, kekSize), true);

/* Go back to init to leave system in known state after test */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);

	return which_commonKek(commonKek, kekSize);
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
	enum soc_commonKek_idx k = get_soc_commonKek_idx();

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force reset of all keys */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, EU applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);

	/* Inject MA key */
	VTEST_CHECK_RESULT(v2xSe_injectMaEccPrivateKey(V2XSE_CURVE_NISTP256,
					&statusCode, &pubKey,
					kek_patterns[k].encryptedKey1,
					sizeof(kek_patterns[k].encryptedKey1),
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
	enum soc_commonKek_idx k = get_soc_commonKek_idx();

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force key injection mode */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, EU applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);

	/* Inject RT key */
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		kek_patterns[k].encryptedKey1,
		sizeof(kek_patterns[k].encryptedKey1),
		KEK_TYPE_COMMON), V2XSE_SUCCESS);
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
	enum soc_commonKek_idx k = get_soc_commonKek_idx();

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

	/* Inject key to overwrite - same type as injected */
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(NON_ZERO_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		kek_patterns[k].encryptedKey1,
		sizeof(kek_patterns[k].encryptedKey1),
		KEK_TYPE_COMMON), V2XSE_SUCCESS);
	/* Verify public key contents doesn't match ref value */
	VTEST_CHECK_RESULT(!memcmp(&pubKey, &refPubKey2,
						sizeof(TypePublicKey_t)), 0);

	/* Inject RT key */
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(NON_ZERO_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		kek_patterns[k].encryptedKey2,
		sizeof(kek_patterns[k].encryptedKey2),
		KEK_TYPE_COMMON), V2XSE_SUCCESS);
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
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey,
		kek_patterns[k].encryptedKey2,
		sizeof(kek_patterns[k].encryptedKey2),
		KEK_TYPE_COMMON), V2XSE_SUCCESS);
	/* Verify public key contents doesn't match ref value */
	VTEST_CHECK_RESULT(!memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Inject RT key */
	VTEST_CHECK_RESULT(v2xSe_injectRtEccPrivateKey(MAX_RT_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		kek_patterns[k].encryptedKey1,
		sizeof(kek_patterns[k].encryptedKey1),
		KEK_TYPE_COMMON), V2XSE_SUCCESS);
	/* Verify public key contents match expected values */
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
	enum soc_commonKek_idx k = get_soc_commonKek_idx();

	/* Move to INIT state */
	VTEST_CHECK_RESULT(setupInitState(), VTEST_PASS);
	/* Remove NVM phase variable to force key injection mode */
	VTEST_CHECK_RESULT(removeNvmVariable(EU_PHASE_FILENAME), VTEST_PASS);
	/* Move to ACTIVATED state, EU applet */
	VTEST_CHECK_RESULT(setupActivatedState(e_EU), VTEST_PASS);

	/* Inject BA key */
	VTEST_CHECK_RESULT(v2xSe_injectBaEccPrivateKey(SLOT_ZERO,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		kek_patterns[k].encryptedKey1,
		sizeof(kek_patterns[k].encryptedKey1),
		KEK_TYPE_COMMON), V2XSE_SUCCESS);

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
	enum soc_commonKek_idx k = get_soc_commonKek_idx();

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

	/* Inject key to overwrite - same type as injected */
	VTEST_CHECK_RESULT(v2xSe_injectBaEccPrivateKey(NON_ZERO_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		kek_patterns[k].encryptedKey1,
		sizeof(kek_patterns[k].encryptedKey1),
		 KEK_TYPE_COMMON), V2XSE_SUCCESS);
	/* Verify public key contents doesn't match ref value */
	VTEST_CHECK_RESULT(!memcmp(&pubKey, &refPubKey2,
						sizeof(TypePublicKey_t)), 0);
	/* Inject BA key */
	VTEST_CHECK_RESULT(v2xSe_injectBaEccPrivateKey(NON_ZERO_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		kek_patterns[k].encryptedKey2,
		sizeof(kek_patterns[k].encryptedKey2),
		KEK_TYPE_COMMON), V2XSE_SUCCESS);
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
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey,
		kek_patterns[k].encryptedKey2,
		sizeof(kek_patterns[k].encryptedKey2),
		KEK_TYPE_COMMON), V2XSE_SUCCESS);
	/* Verify public key contents doesn't match ref value */
	VTEST_CHECK_RESULT(!memcmp(&pubKey, &refPubKey1,
						sizeof(TypePublicKey_t)), 0);
	/* Inject BA key */
	VTEST_CHECK_RESULT(v2xSe_injectBaEccPrivateKey(MAX_BA_SLOT,
		V2XSE_CURVE_NISTP256, &statusCode, &pubKey,
		kek_patterns[k].encryptedKey1,
		sizeof(kek_patterns[k].encryptedKey1),
		KEK_TYPE_COMMON), V2XSE_SUCCESS);
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
