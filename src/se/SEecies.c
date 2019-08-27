
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

#include <v2xseapi.h>
#include "vtest.h"
#include "SEmisc.h"
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
 */
void test_encryptUsingEcies(void)
{
	TypeSW_t statusCode;
	TypePublicKey_t pubKey;
	TypeEncryptEcies_t enc_eciesData;
	TypeInt256_t msg;
	TypeInt256_t vct;
	TypeLen_t size;

	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Generate an Rt key to have a public key to use */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
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
	VTEST_CHECK_RESULT(v2xSe_encryptUsingEcies(&enc_eciesData, &statusCode,
		&size, (TypeVCTData_t*)(&(vct.data))), V2XSE_SUCCESS);

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
	TypeInt256_t vct;
	TypeLen_t size;
	TypeDecryptEcies_t dec_eciesData;

	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Generate an Rt key to use */
	VTEST_CHECK_RESULT(v2xSe_generateRtEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Set up ECIES decrypt parameters */
	dec_eciesData.kdfParamP1Len = 0;
	dec_eciesData.macLen = 0;
	dec_eciesData.macParamP2Len = 0;
	dec_eciesData.vctLen = 1;
	dec_eciesData.pVctData = (TypeVCTData_t*)(&(vct.data));
	/* Perform decryption */
	VTEST_CHECK_RESULT(v2xSe_decryptUsingRtEcies(SLOT_ZERO, &dec_eciesData,
			&statusCode, &size, (TypePlainText_t*)(&(msg.data))),
								V2XSE_SUCCESS);

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
	TypeInt256_t vct;
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
	/* Set up ECIES decrypt parameters */
	dec_eciesData.kdfParamP1Len = 0;
	dec_eciesData.macLen = 0;
	dec_eciesData.macParamP2Len = 0;
	dec_eciesData.vctLen = 1;
	dec_eciesData.pVctData = (TypeVCTData_t*)(&(vct.data));
	/* Perform decryption */
	VTEST_CHECK_RESULT(v2xSe_decryptUsingMaEcies(&dec_eciesData,
			&statusCode, &size, (TypePlainText_t*)(&(msg.data))),
								V2XSE_SUCCESS);

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
	TypeInt256_t vct;
	TypeLen_t size;
	TypeDecryptEcies_t dec_eciesData;

	/* Move to ACTIVATED state, normal operating mode */
	VTEST_CHECK_RESULT(setupActivatedNormalState(e_EU), VTEST_PASS);
	/* Generate an Ba key to use */
	VTEST_CHECK_RESULT(v2xSe_generateBaEccKeyPair(SLOT_ZERO,
		V2XSE_CURVE_BP256T1, &statusCode, &pubKey), V2XSE_SUCCESS);
	/* Set up ECIES decrypt parameters */
	dec_eciesData.kdfParamP1Len = 0;
	dec_eciesData.macLen = 0;
	dec_eciesData.macParamP2Len = 0;
	dec_eciesData.vctLen = 1;
	dec_eciesData.pVctData = (TypeVCTData_t*)(&(vct.data));
	/* Perform decryption */
	VTEST_CHECK_RESULT(v2xSe_decryptUsingBaEcies(SLOT_ZERO, &dec_eciesData,
			&statusCode, &size, (TypePlainText_t*)(&(msg.data))),
								V2XSE_SUCCESS);

	/* Flag CONF as not all required tests implemented yet */
	VTEST_FLAG_CONF();
}
