
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file vtest.c
 *
 * @brief Core implementation of V2X test application
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <v2xseapi.h>
#include "vtest.h"
#include "SEdevicemanagement.h"
#include "SEkeymanagement.h"
#include "SEsignature.h"
#include "SEecies.h"
#include "SEdatastorage.h"
#include "SEutility.h"
#include "SEkeyinjection.h"

testEntry allTests[] = {
	LEGACY_TESTS_TO_REMOVE
	SE_DEVICE_MANAGEMENT_TESTS
	SE_KEY_MANAGEMENT_TESTS
	SE_SIGNATURE_TESTS
	SE_ECIES_TESTS
	SE_DATA_STORAGE_TESTS
	SE_UTILITY_TESTS
	SE_KEY_INJECTION_TESTS
};


static void checkret(char* name, int32_t actual, int32_t expected)
{
	if (actual == expected)
		printf("%s: PASS\n",name);
	else
		printf("%s: FAIL, returned %d\n",name, actual);
}

int legacy_test()
{
	TypeSW_t statusCode;
	TypeVersion_t version;
	TypeInformation_t seInfo;
	TypePlatformIdentity_t platformIdentity;
	char displayString[V2XSE_PLATFORM_IDENTITY+1];
	TypePlatformConfiguration_t platformConfig;
	TypeChipInformation_t chipInfo;
	TypeAttackLog_t attackLog;
	uint8_t phase;
	uint8_t dataStorage_write[V2XSE_MAX_DATA_SIZE_GSA];
	uint8_t dataStorage_read[V2XSE_MAX_DATA_SIZE_GSA];
	TypeLen_t size;
	uint32_t remainingNvm;
	int32_t keyLen;
	int32_t sigLen;
	TypePublicKey_t pubKey;
	TypeCurveId_t curveId;
	uint32_t random_num;
	TypeHash_t hash;
	TypeSignature_t signature;
	TypeLowlatencyIndicator_t fastIndicator;
	TypeInt256_t data1;
	TypeInt256_t data2;
	TypeInt256_t data3;
	TypeEncryptEcies_t enc_eciesData;
	TypeDecryptEcies_t dec_eciesData;

	printf("Test expected fails in init state:\n");
	checkret("v2xSe_reset",
			v2xSe_reset(),
			V2XSE_FAILURE_INIT);
	checkret("v2xSe_deactivate",
			v2xSe_deactivate(),
			V2XSE_FAILURE_INIT);
	checkret("v2xSe_disconnect",
			v2xSe_disconnect(),
			V2XSE_FAILURE_INIT);

	printf("Test expected fails in connected state:\n");
	if (v2xSe_connect() != V2XSE_SUCCESS)
		printf("Error in test sequence: v2xSe_connect\n");
	checkret("v2xSe_connect",
			v2xSe_connect(),
			V2XSE_FAILURE_CONNECTED);
	checkret("v2xSe_activate",
			v2xSe_activate(e_EU_AND_GS, &statusCode),
			V2XSE_FAILURE_CONNECTED);
	checkret("v2xSe_activateWithSecurityLevel",
			v2xSe_activateWithSecurityLevel(e_EU_AND_GS,
							e_channelSecLevel_5,
							&statusCode),
			V2XSE_FAILURE_CONNECTED);

	printf("Test expected fails in activated state:\n");
	if (v2xSe_reset() != V2XSE_SUCCESS)
		printf("Error in test sequence: v2xSe_reset\n");
	if (v2xSe_activate(e_EU_AND_GS, &statusCode) != V2XSE_SUCCESS)
		printf("Error in test sequence: v2xSe_activate\n");
	checkret("v2xSe_connect",
			v2xSe_connect(),
			V2XSE_FAILURE_ACTIVATED);
	checkret("v2xSe_activate",
			v2xSe_activate(e_EU_AND_GS, &statusCode),
			V2XSE_FAILURE_ACTIVATED);
	checkret("v2xSe_activateWithSecurityLevel",
			v2xSe_activateWithSecurityLevel(e_EU_AND_GS,
							e_channelSecLevel_5,
							&statusCode),
			V2XSE_FAILURE_ACTIVATED);

	if (v2xSe_getAppletVersion(e_V2X, &statusCode, &version) ==
							V2XSE_SUCCESS)
		printf("EU applet version: %d.%d.%d\n",version.data[0],
							version.data[1],
							version.data[2]);
	else
		printf("Error getting EU applet version\n");
	if (v2xSe_reset() != V2XSE_SUCCESS)
		printf("Error in test sequence: v2xSe_reset\n");
	if (v2xSe_activate(e_US_AND_GS, &statusCode) != V2XSE_SUCCESS)
		printf("Error in test sequence: v2xSe_activate\n");
	if (v2xSe_getAppletVersion(e_V2X, &statusCode, &version) ==
							V2XSE_SUCCESS)
		printf("US applet version: %d.%d.%d\n",version.data[0],
							version.data[1],
							version.data[2]);
	else
		printf("Error getting US applet version\n");
	if (v2xSe_getAppletVersion(e_GS, &statusCode, &version) ==
							V2XSE_SUCCESS)
		printf("Storage applet version: %d.%d.%d\n",version.data[0],
							version.data[1],
							version.data[2]);
	else
		printf("Error getting storage applet version\n");

	if (v2xSe_getSeInfo(&statusCode, &seInfo) == V2XSE_SUCCESS)
		printf("SE Info: %d,%d,%d,%d,%d,%d,%d,%d,%d\n",
						seInfo.maxRtKeysAllowed,
						seInfo.maxBaKeysAllowed,
					 	seInfo.numPreparedVal,
						seInfo.fipsModeIndicator,
						seInfo.proofOfPossession,
						seInfo.rollBackProtection,
						seInfo.rtKeyDerivation,
						seInfo.eciesSupport,
						seInfo.maxDataSlots);
	else
		printf("Error getting SE info\n");

	if (v2xSe_getCryptoLibVersion(&version) == V2XSE_SUCCESS)
		printf("Crypto lib version: %d.%d.%d\n",version.data[0],
							version.data[1],
							version.data[2]);
	else
		printf("Error getting crypto lib version\n");

	if (v2xSe_getPlatformInfo(&statusCode, &platformIdentity) ==
							V2XSE_SUCCESS) {
		memcpy(displayString, platformIdentity.data,
					V2XSE_PLATFORM_IDENTITY);
		displayString[V2XSE_PLATFORM_IDENTITY] = 0;
		printf("Platform info: %s\n", displayString);
	}
	else
		printf("Error getting platform info\n");

	if (v2xSe_getPlatformConfig(&statusCode, &platformConfig) ==
							V2XSE_SUCCESS)
		printf("Platform config: %x %c%c%c\n", platformConfig.data[0],
							platformConfig.data[1],
							platformConfig.data[2],
							platformConfig.data[3]);
	else
		printf("Error getting platform config\n");

	if (v2xSe_getChipInfo(&statusCode, &chipInfo) ==
							V2XSE_SUCCESS) {
		printf("Serial number: %x%x%x%x%x%x%x%x%x%x%x%x",
							chipInfo.data[0],
							chipInfo.data[1],
							chipInfo.data[2],
							chipInfo.data[3],
							chipInfo.data[4],
							chipInfo.data[5],
							chipInfo.data[6],
							chipInfo.data[7],
							chipInfo.data[8],
							chipInfo.data[9],
							chipInfo.data[10],
							chipInfo.data[11]);
		printf("%x%x%x%x%x%x%x%x%x%x%x%x\n",
							chipInfo.data[12],
							chipInfo.data[13],
							chipInfo.data[14],
							chipInfo.data[15],
							chipInfo.data[16],
							chipInfo.data[17],
							chipInfo.data[18],
							chipInfo.data[19],
							chipInfo.data[20],
							chipInfo.data[21],
							chipInfo.data[22],
							chipInfo.data[23]);
	}
	else
		printf("Error getting serial number\n");

	if (v2xSe_getAttackLog(&statusCode, &attackLog) == V2XSE_SUCCESS)
		printf("attack log status: %d, length: %d\n",
					attackLog.currAttackCntrStatus,
					attackLog.len);
	else
		printf("Error getting attack log\n");

	if (v2xSe_sendReceive(NULL, 0, NULL, NULL, &statusCode) ==
							V2XSE_FAILURE)
		printf("v2xSe_sendReceive failed as expected\n");
	else
		printf("Error: v2xSe_sendReceive did not fail\n");

	if (v2xSe_reset() != V2XSE_SUCCESS)
		printf("Error in test sequence: v2xSe_reset\n");
	if (v2xSe_activate(e_EU_AND_GS, &statusCode) != V2XSE_SUCCESS)
		printf("Error in test sequence: v2xSe_activate\n");

	if (v2xSe_getSePhase(&phase, &statusCode) == V2XSE_SUCCESS)
		printf("Current phase: %d\n",phase);
	else
		printf("Error getting phase\n");

	if (v2xSe_endKeyInjection(&statusCode) == V2XSE_SUCCESS)
		printf("Key injection ended\n");
	else
		printf("Error ending key injection\n");

	if (v2xSe_getSePhase(&phase, &statusCode) == V2XSE_SUCCESS)
		printf("Current phase: %d\n",phase);
	else
		printf("Error getting phase\n");

	if (v2xSe_invokeGarbageCollector(&statusCode) == V2XSE_SUCCESS)
		printf("Garbage collection OK\n");
	else
		printf("Error collecting garbage\n");

	memcpy(dataStorage_write, "Hi there\n", 10);
	printf("Saved str length: %ld\n",strlen((char*)dataStorage_write));
	if (v2xSe_storeData(0, 10, dataStorage_write, &statusCode) == V2XSE_SUCCESS)
		printf("Store index 0 OK\n");
	else
		printf("Error storing in index 0\n");

	if (v2xSe_getData(0, &size, dataStorage_read, &statusCode) == V2XSE_SUCCESS)
		printf("Get index 0 OK, size: %d, strlen: %ld, str: %s\n",size, strlen((char*)dataStorage_read), dataStorage_read);
	else
		printf("Error getting index 0\n");

	if (v2xSe_deleteData(0, &statusCode) == V2XSE_SUCCESS)
		printf("OK deleting index 0\n");
	else
		printf("Error deleting index 0\n");

	if (v2xSe_deleteData(0, &statusCode) != V2XSE_SUCCESS)
		printf("Second delete of index 0 failed as expected\n");
	else
		printf("Error: deleted index 0 twice!\n");

	printf("Saved str length: %ld\n",strlen((char*)dataStorage_write));
	if (v2xSe_storeData(1234, 10, dataStorage_write, &statusCode) == V2XSE_SUCCESS)
		printf("Store index 1234 OK\n");
	else
		printf("Error storing in index 1234\n");

	if (v2xSe_getData(1234, &size, dataStorage_read, &statusCode) == V2XSE_SUCCESS)
		printf("Get index 1234 OK, size: %d, strlen: %ld, str: %s\n",size, strlen((char*)dataStorage_read), dataStorage_read);
	else
		printf("Error getting index 1234\n");

	if (v2xSe_getRemainingNvm(&remainingNvm, &statusCode) == V2XSE_SUCCESS)
		printf("Remaining NVM: %u\n",remainingNvm);
	else
		printf("Error getting remaining NVM\n");

	keyLen = v2xSe_getKeyLenFromCurveID(V2XSE_CURVE_NISTP256);
	if (keyLen != V2XSE_FAILURE)
		printf("Key length for NISTP256: %d\n",keyLen);
	else
		printf("Error getting key length\n");

	sigLen = v2xSe_getSigLenFromHashLen(V2XSE_384_EC_HASH_SIZE);
	if (sigLen != V2XSE_FAILURE)
		printf("Signature length for 384 bit hash: %d\n",sigLen);
	else
		printf("Error getting signature length\n");

	printf("Reset, simulate normal operation\n");
	checkret("v2xSe_reset",
			v2xSe_reset(),
			V2XSE_SUCCESS);
	checkret("v2xSe_activate",
			v2xSe_activate(e_EU_AND_GS, &statusCode),
			V2XSE_SUCCESS);

	checkret("v2xSe_getMaEccPublicKey",
			v2xSe_getMaEccPublicKey(&statusCode, &curveId, &pubKey),
			V2XSE_SUCCESS);
	printf("!!!NOTE: failing above test OK if first run since factory reset\n");
	printf("ma pubkey set to %x, curve %d\n",pubKey.x[0], curveId);

	checkret("v2xSe_generateMaEccKeyPair",
			v2xSe_generateMaEccKeyPair(V2XSE_CURVE_NISTP384, &statusCode, &pubKey),
			V2XSE_FAILURE);
	printf("!!!NOTE: failing above test OK if first run since factory reset\n");

	checkret("v2xSe_generateRtEccKeyPair",
			v2xSe_generateRtEccKeyPair(0, V2XSE_CURVE_NISTP256, &statusCode, &pubKey),
			V2XSE_SUCCESS);
	printf("rt[0] pubkey set to %x\n",pubKey.x[0]);

	checkret("v2xSe_generateRtEccKeyPair",
			v2xSe_generateRtEccKeyPair(4321, V2XSE_CURVE_BP256R1, &statusCode, &pubKey),
			V2XSE_SUCCESS);
	printf("rt[4321] pubkey set to %x\n",pubKey.x[0]);

	checkret("v2xSe_getRtEccPublicKey",
			v2xSe_getRtEccPublicKey(0, &statusCode, &curveId, &pubKey),
			V2XSE_SUCCESS);
	printf("rt[0] pubkey retrieved as %x, curve %d\n",pubKey.x[0], curveId);

	checkret("v2xSe_getRtEccPublicKey",
			v2xSe_getRtEccPublicKey(4321, &statusCode, &curveId, &pubKey),
			V2XSE_SUCCESS);
	printf("rt[4321] pubkey retrieved as %x, curve %d\n",pubKey.x[0], curveId);

	checkret("v2xSe_deleteRtEccPrivateKey",
			v2xSe_deleteRtEccPrivateKey(0, &statusCode),
			V2XSE_SUCCESS);

	checkret("v2xSe_getRtEccPublicKey",
			v2xSe_getRtEccPublicKey(0, &statusCode, &curveId, &pubKey),
			V2XSE_FAILURE);

	checkret("v2xSe_generateBaEccKeyPair",
			v2xSe_generateBaEccKeyPair(0, V2XSE_CURVE_BP256T1, &statusCode, &pubKey),
			V2XSE_SUCCESS);
	printf("ba[0] pubkey set to %x\n",pubKey.x[0]);

	checkret("v2xSe_generateBaEccKeyPair",
			v2xSe_generateBaEccKeyPair(7765, V2XSE_CURVE_BP384T1, &statusCode, &pubKey),
			V2XSE_SUCCESS);
	printf("ba[7765] pubkey set to %x\n",pubKey.x[0]);

	checkret("v2xSe_getBaEccPublicKey",
			v2xSe_getBaEccPublicKey(0, &statusCode, &curveId, &pubKey),
			V2XSE_SUCCESS);
	printf("ba[0] pubkey retrieved as %x, curve %d\n",pubKey.x[0], curveId);

	checkret("v2xSe_getBaEccPublicKey",
			v2xSe_getBaEccPublicKey(7765, &statusCode, &curveId, &pubKey),
			V2XSE_SUCCESS);
	printf("ba[7765] pubkey retrieved as %x, curve %d\n",pubKey.x[0], curveId);

	checkret("v2xSe_deleteBaEccPrivateKey",
			v2xSe_deleteBaEccPrivateKey(7765, &statusCode),
			V2XSE_SUCCESS);

	checkret("v2xSe_getBaEccPublicKey",
			v2xSe_getBaEccPublicKey(7765, &statusCode, &curveId, &pubKey),
			V2XSE_FAILURE);

	checkret("v2xSe_getRandomNumber",
			v2xSe_getRandomNumber(sizeof(random_num), &statusCode, (TypeRandomNumber_t*)&random_num),
			V2XSE_SUCCESS);
	printf("Random num was %x\n", random_num);

	hash.data[0] = 13;
	checkret("v2xSe_createMaSign",
			v2xSe_createMaSign(48, &hash, &statusCode, &signature),
			V2XSE_SUCCESS);
	printf("Sig byte was %d\n",signature.r[0]);

	checkret("v2xSe_createRtSign",
			v2xSe_createRtSign(0, &hash, &statusCode, &signature),
			V2XSE_FAILURE);

	hash.data[0] = 14;
	checkret("v2xSe_createRtSign",
			v2xSe_createRtSign(4321, &hash, &statusCode, &signature),
			V2XSE_SUCCESS);
	printf("Sig byte was %d\n",signature.r[0]);

	checkret("v2xSe_createBaSign",
			v2xSe_createBaSign(7765, 32, &hash, &statusCode, &signature),
			V2XSE_FAILURE);

	hash.data[0] = 12;
	checkret("v2xSe_createBaSign",
			v2xSe_createBaSign(0, 32, &hash, &statusCode, &signature),
			V2XSE_SUCCESS);
	printf("Sig byte was %d\n",signature.r[0]);


	checkret("v2xSe_createRtSignLowLatency",
			v2xSe_createRtSignLowLatency(&hash, &statusCode, &signature, &fastIndicator),
			V2XSE_FAILURE);

	checkret("v2xSe_activateRtKeyForSigning",
			v2xSe_activateRtKeyForSigning(4321, &statusCode),
			V2XSE_SUCCESS);

	hash.data[0] = 15;
	checkret("v2xSe_createRtSignLowLatency",
			v2xSe_createRtSignLowLatency(&hash, &statusCode, &signature, &fastIndicator),
			V2XSE_SUCCESS);
	printf("Sig byte was %d\n",signature.r[0]);

	checkret("v2xSe_deriveRtEccKeyPair",
			v2xSe_deriveRtEccKeyPair(0, &data1, &data2, &data3, 1, V2XSE_RSP_WITH_PUBKEY, &statusCode, &curveId, &pubKey),
			V2XSE_FAILURE);

	/* Switch to US to allow derive key to work */
	checkret("v2xSe_reset",
			v2xSe_reset(),
			V2XSE_SUCCESS);
	checkret("v2xSe_activate",
			v2xSe_activate(e_US_AND_GS, &statusCode),
			V2XSE_SUCCESS);
	checkret("v2xSe_endKeyInjection",
			v2xSe_endKeyInjection(&statusCode),
			V2XSE_FAILURE);
	printf("!!!NOTE: failing above test OK if first run since factory reset\n");

	data1.data[0] = 1;
	data2.data[0] = 2;
	data3.data[0] = 3;
	checkret("v2xSe_deriveRtEccKeyPair",
			v2xSe_deriveRtEccKeyPair(0, &data1, &data2, &data3, 1, V2XSE_RSP_WITH_PUBKEY, &statusCode, &curveId, &pubKey),
			V2XSE_SUCCESS);
	printf("Derived byte was %d, curveId %d\n",pubKey.x[0], curveId);

	/* Test key overwrite */
	checkret("v2xSe_generateBaEccKeyPair",
			v2xSe_generateBaEccKeyPair(0, V2XSE_CURVE_BP256T1, &statusCode, &pubKey),
			V2XSE_SUCCESS);
	printf("ba[0] pubkey set to %x\n",pubKey.x[0]);

	checkret("v2xSe_generateRtEccKeyPair",
			v2xSe_generateRtEccKeyPair(1, V2XSE_CURVE_NISTP256, &statusCode, &pubKey),
			V2XSE_SUCCESS);
	printf("rt[1] pubkey set to %x\n",pubKey.x[0]);

	checkret("v2xSe_deriveRtEccKeyPair",
			v2xSe_deriveRtEccKeyPair(0, &data1, &data2, &data3, 1, V2XSE_RSP_WITH_PUBKEY, &statusCode, &curveId, &pubKey),
			V2XSE_SUCCESS);
	printf("Derived byte was %d, curveId %d\n",pubKey.x[0], curveId);

	enc_eciesData.pEccPublicKey = &pubKey;
	enc_eciesData.curveId = V2XSE_CURVE_BP256T1;
	enc_eciesData.kdfParamP1Len = 0;
	enc_eciesData.macLen = 0;
	enc_eciesData.macParamP2Len = 0;
	enc_eciesData.msgLen = 1;
	enc_eciesData.pMsgData = (TypePlainText_t*)(&(data2.data));
	data2.data[0]=34;
	checkret("v2xSe_encryptUsingEcies",
			v2xSe_encryptUsingEcies(&enc_eciesData, &statusCode, &size, (TypeVCTData_t*)(&(data1.data))),
			V2XSE_SUCCESS);
	printf("MsgData set to %d\n",data1.data[0]);

	checkret("v2xSe_decryptUsingRtEcies",
			v2xSe_decryptUsingRtEcies(5, &dec_eciesData, &statusCode, &size, (TypePlainText_t*)(&(data1.data))),
			V2XSE_FAILURE);

	dec_eciesData.kdfParamP1Len = 0;
	dec_eciesData.macLen = 0;
	dec_eciesData.macParamP2Len = 0;
	dec_eciesData.vctLen = 1;
	dec_eciesData.pVctData = (TypeVCTData_t*)(&(data2.data));
	checkret("v2xSe_decryptUsingRtEcies",
			v2xSe_decryptUsingRtEcies(1, &dec_eciesData, &statusCode, &size, (TypePlainText_t*)(&(data1.data))),
			V2XSE_SUCCESS);
	printf("VctData set to %d\n",data1.data[0]);

	checkret("v2xSe_decryptUsingBaEcies",
			v2xSe_decryptUsingBaEcies(5, &dec_eciesData, &statusCode, &size, (TypePlainText_t*)(&(data1.data))),
			V2XSE_FAILURE);

	data2.data[0]=5;
	checkret("v2xSe_decryptUsingBaEcies",
			v2xSe_decryptUsingBaEcies(0, &dec_eciesData, &statusCode, &size, (TypePlainText_t*)(&(data1.data))),
			V2XSE_SUCCESS);
	printf("VctData set to %d\n",data1.data[0]);

	checkret("v2xSe_generateMaEccKeyPair",
			v2xSe_generateMaEccKeyPair(V2XSE_CURVE_NISTP384, &statusCode, &pubKey),
			V2XSE_FAILURE);
	printf("!!!NOTE: failing above test OK if first run since factory reset\n");

	data2.data[0]=9;
	checkret("v2xSe_decryptUsingMaEcies",
			v2xSe_decryptUsingMaEcies(&dec_eciesData, &statusCode, &size, (TypePlainText_t*)(&(data1.data))),
			V2XSE_SUCCESS);
	printf("VctData set to %d\n",data1.data[0]);

	printf("Final teardown\n");
	checkret("v2xSe_deactivate",
			v2xSe_deactivate(),
			V2XSE_SUCCESS);

	return VTEST_CONF;
}

int dummy_test_conf(void)
{
	return VTEST_CONF;
}
int dummy_test_pass(void)
{
	return VTEST_PASS;
}
int dummy_test_fail(void)
{
	return VTEST_FAIL;
}
int dummy_test_interr(void)
{
	return 13;
}

int getTestNum(const char *testStr)
{
	long convNum;

	convNum = strtol(testStr, NULL, 10);
	if ((convNum <= BEFORE_FIRST_TEST) ||
		(convNum >= AFTER_LAST_TEST)) {
		printf("ERROR: invalid test number: %s\n",testStr);
		return VTEST_FAIL;
	}

	return (int)convNum;
}

int main(int argc, char* argv[])
{
	int i;
	int minTest = BEFORE_FIRST_TEST;
	int maxTest = AFTER_LAST_TEST;

	int numTestsRun = 0;
	int numTestsSkipped = 0;
	int numTestsPass = 0;
	int numTestsFail = 0;
	int numTestsConf = 0;
	int numInternalErrors = 0;

	printf("vtest: Start\n");

	if (argc == 1) {
		printf("Running all tests\n");
	} else if (argc == 2) {
		printf("Running single test\n");
		minTest = getTestNum(argv[1]);
		maxTest = minTest;
	} else if (argc == 3) {
		printf("Running range of tests\n");
		minTest = getTestNum(argv[1]);
		maxTest = getTestNum(argv[2]);
	} else {
		printf("ERROR: incorrect number of parameters\n");
		printf("USAGE: vtest\n");
		printf("       vtest [single test num]\n");
		printf("       vtest [first test num] [last test num]\n");
		return -1;
	}

	if ((minTest == VTEST_FAIL) || (maxTest == VTEST_FAIL))
		return VTEST_FAIL;

	for (i = 0; i < (sizeof(allTests)/sizeof(testEntry)); i++) {
		if ((allTests[i].testNum >= minTest) &&
					(allTests[i].testNum <= maxTest)) {
			int result;
			numTestsRun++;
			printf("Running test %06d: %s\n",allTests[i].testNum,
							allTests[i].testName);
			result = allTests[i].testFn();
			switch (result) {
				case VTEST_PASS:
					numTestsPass++;
					printf("Test result: PASS\n");
					break;
				case VTEST_FAIL:
					numTestsFail++;
					printf("Test result: FAIL\n");
					break;
				case VTEST_CONF:
					numTestsConf++;
					printf("Test result: CONF\n");
					break;
				default:
					numInternalErrors++;
					printf("Internal error\n");
					break;
			}
		} else {
			numTestsSkipped++;
		}
	}

	printf("\n\nSUMMARY:\n");
	printf("Tests RUN: %d\n",numTestsRun);
	printf("Tests SKIPPED: %d\n",numTestsSkipped);
	printf("Internal Errors: %d\n",numInternalErrors);
	printf("Tests PASS: %d\n",numTestsPass);
	printf("Tests CONF: %d\n",numTestsConf);
	printf("Tests FAIL: %d\n",numTestsFail);
	printf("vtest: Done\n");
	return VTEST_PASS;
}
