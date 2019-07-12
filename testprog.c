#include <stdio.h>
#include <string.h>
#include <v2xSe.h>

void checkret(char* name, int32_t actual, int32_t expected)
{
	if (actual == expected)
		printf("%s: PASS\n",name);
	else
		printf("%s: FAIL, returned %d\n",name, actual);
}

int main()
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

	printf("testprog: start\n");

	printf("Test expected fails in init state:\n");
	checkret("v2xSe_reset",
			v2xSe_reset(),
			V2XSE_FAILURE_INIT);
	checkret("v2xSe_deactivate",
			v2xSe_deactivate(),
			V2XSE_FAILURE_INIT);

	printf("Test expected fails in connected state:\n");
	v2xSe_connect();
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
	v2xSe_reset();
	v2xSe_activate(e_EU_AND_GS, &statusCode);
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
	v2xSe_reset();
	v2xSe_activate(e_US_AND_GS, &statusCode);
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


	printf("testprog: DONE\n");
	return 0;
}
