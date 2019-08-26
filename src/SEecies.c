
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEecies.c
 *
 * @brief Tests for SE ECIES (requirements R8.*)
 *
 */

#include <stdio.h>
#include <v2xseapi.h>
#include "vtest.h"
#include "SEecies.h"

/**
 *
 * @brief Test v2xSe_encryptUsingEcies for expected behaviour
 *
 * This function tests v2xSe_encryptUsingEcies for expected behaviour
 * The following behaviours are tested:
 *  - success returned when random data provided
 * TODO!! Verify result, create normal inputs, try different curves, applets...
 *
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_encryptUsingEcies(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeEncryptEcies_t enc_eciesData;
	TypeInt256_t msg;
	TypeInt256_t vct;
	TypeLen_t size;

	/* Move to ACTIVATED state, normal operating mode */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Generate an Rt key to have a public key to use */
	retVal = v2xSe_generateRtEccKeyPair(SLOT_ZERO, V2XSE_CURVE_BP256T1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Set up ECIES encrypt parameters */
	enc_eciesData.pEccPublicKey = &pubKey;
	enc_eciesData.curveId = V2XSE_CURVE_BP256T1;
	enc_eciesData.kdfParamP1Len = 0;
	enc_eciesData.macLen = 0;
	enc_eciesData.macParamP2Len = 0;
	enc_eciesData.msgLen = 1;
	enc_eciesData.pMsgData = (TypePlainText_t*)(&(msg.data));
	msg.data[0]=34;
	/* Perform encryption */
	retVal = v2xSe_encryptUsingEcies(&enc_eciesData, &statusCode, &size,
		(TypeVCTData_t*)(&(vct.data)));
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_encryptUsingEcies returned %d\n",
								retVal);
		return VTEST_FAIL;
	}

	/* Only return pass when all tests implemented */
	return VTEST_CONF;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_decryptUsingRtEcies(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeInt256_t msg;
	TypeInt256_t vct;
	TypeLen_t size;
	TypeDecryptEcies_t dec_eciesData;

	/* Move to ACTIVATED state, normal operating mode */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Generate an Rt key to use */
	retVal = v2xSe_generateRtEccKeyPair(SLOT_ZERO, V2XSE_CURVE_BP256T1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateRtEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Set up ECIES decrypt parameters */
	dec_eciesData.kdfParamP1Len = 0;
	dec_eciesData.macLen = 0;
	dec_eciesData.macParamP2Len = 0;
	dec_eciesData.vctLen = 1;
	dec_eciesData.pVctData = (TypeVCTData_t*)(&(vct.data));
	/* Perform decryption */
	retVal = v2xSe_decryptUsingRtEcies(SLOT_ZERO, &dec_eciesData,
		&statusCode, &size, (TypePlainText_t*)(&(msg.data)));
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_decryptUsingRtEcies returned %d\n",
								retVal);
		return VTEST_FAIL;
	}

	/* Only return pass when all tests implemented */
	return VTEST_CONF;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_decryptUsingMaEcies(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeInt256_t msg;
	TypeInt256_t vct;
	TypeLen_t size;
	TypeDecryptEcies_t dec_eciesData;

	/* Move to INIT state */
	if (setupInitState() != VTEST_PASS)
		return VTEST_FAIL;
	/* Remove NVM phase variable to force reset of all keys */
	if (removeNvmVariable(EU_PHASE_FILENAME) != VTEST_PASS) {
		printf("ERROR: Failed to delete EU phase variable\n");
		return VTEST_FAIL;
	}
	/* Move to ACTIVATED state, normal operating mode */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Generate MA key of known curveId */
	retVal = v2xSe_generateMaEccKeyPair(V2XSE_CURVE_NISTP256, &statusCode,
								&pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateMaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}

	/* Set up ECIES decrypt parameters */
	dec_eciesData.kdfParamP1Len = 0;
	dec_eciesData.macLen = 0;
	dec_eciesData.macParamP2Len = 0;
	dec_eciesData.vctLen = 1;
	dec_eciesData.pVctData = (TypeVCTData_t*)(&(vct.data));
	/* Perform decryption */
	retVal = v2xSe_decryptUsingMaEcies(&dec_eciesData, &statusCode, &size,
					(TypePlainText_t*)(&(msg.data)));
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_decryptUsingMaEcies returned %d\n",
								retVal);
		return VTEST_FAIL;
	}

	/* Only return pass when all tests implemented */
	return VTEST_CONF;
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
 * @return VTEST_PASS, VTEST_FAIL, or VTEST_CONF
 *
 */
int test_decryptUsingBaEcies(void)
{
	int32_t retVal;
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeInt256_t msg;
	TypeInt256_t vct;
	TypeLen_t size;
	TypeDecryptEcies_t dec_eciesData;

	/* Move to ACTIVATED state, normal operating mode */
	if (setupActivatedNormalState(e_EU) != VTEST_PASS)
		return VTEST_FAIL;
	/* Generate an Ba key to use */
	retVal = v2xSe_generateBaEccKeyPair(SLOT_ZERO, V2XSE_CURVE_BP256T1,
							&statusCode, &pubKey);
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_generateBaEccKeyPair returned %d\n",
								retVal);
		return VTEST_FAIL;
	}
	/* Set up ECIES decrypt parameters */
	dec_eciesData.kdfParamP1Len = 0;
	dec_eciesData.macLen = 0;
	dec_eciesData.macParamP2Len = 0;
	dec_eciesData.vctLen = 1;
	dec_eciesData.pVctData = (TypeVCTData_t*)(&(vct.data));
	/* Perform decryption */
	retVal = v2xSe_decryptUsingBaEcies(SLOT_ZERO, &dec_eciesData,
		&statusCode, &size, (TypePlainText_t*)(&(msg.data)));
	if (retVal != V2XSE_SUCCESS) {
		printf("ERROR: v2xSe_decryptUsingBaEcies returned %d\n",
								retVal);
		return VTEST_FAIL;
	}

	/* Only return pass when all tests implemented */
	return VTEST_CONF;
}
