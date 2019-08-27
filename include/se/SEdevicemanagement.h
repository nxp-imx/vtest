
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEdevicemanagement.h
 *
 * @brief Header file for tests for SE Device Management (requirements R5.*)
 *
 */

#ifndef SEDEVICEMANAGEMENT_H
#define SEDEVICEMANAGEMENT_H

/** All version numbers are expected to start with 3.xxxxx */
#define EXPECTED_VERSION_GENERATION	3
/** Maximum size of data allowed for v2xSe_sendReceive */
#define V2XSE_MAX_TX_RX_SIZE 261

/**
 * List of tests from to be run from SEdevicemanagement.c
 * Tests should be listed in order of incrementing test number
 */
#define SE_DEVICE_MANAGEMENT_TESTS \
	VTEST_DEFINE_TEST( 50102, &test_connect_negative, \
		"Negative test for v2xSe_connect")\
	VTEST_DEFINE_TEST( 50202, &test_activate_negative, \
		"Negative test for v2xSe_activate")\
	VTEST_DEFINE_TEST( 50302, &test_activateWithSecurityLevel_negative, \
		"Negative test for v2xSe_activateWithSecurtyLevel")\
	VTEST_DEFINE_TEST( 50402, &test_reset_negative, \
		"Negative test for v2xSe_reset")\
	VTEST_DEFINE_TEST( 50502, &test_deactivate_negative, \
		"Negative test for v2xSe_deactivate")\
	VTEST_DEFINE_TEST( 50602, &test_disconnect_negative, \
		"Negative test for v2xSe_disconnect")\
	VTEST_DEFINE_TEST( 50701, &test_getAppletVersion, \
		"Test v2xSe_getAppletVersion for expected behaviour")\
	VTEST_DEFINE_TEST( 50801, &test_getSeInfo, \
		"Test v2xSe_getSeInfo for expected behaviour")\
	VTEST_DEFINE_TEST( 50901, &test_getCryptoLibVersion, \
		"Test v2xSe_getCryptoLibVersion for expected behaviour")\
	VTEST_DEFINE_TEST( 51001, &test_getPlatformInfo, \
		"Test v2xSe_getPlatformInfo for expected behaviour")\
	VTEST_DEFINE_TEST( 51101, &test_getPlatformConfig, \
		"Test v2xSe_getPlatformConfig for expected behaviour")\
	VTEST_DEFINE_TEST( 51201, &test_getChipInfo, \
		"Test v2xSe_getChipInfo for expected behaviour")\
	VTEST_DEFINE_TEST( 51301, &test_getAttackLog, \
		"Test v2xSe_getAttackLog for expected behaviour")\
	VTEST_DEFINE_TEST( 51401, &test_sendReceive, \
		"Test v2xSe_sendReceive for expected behaviour")\
	VTEST_DEFINE_TEST( 51501, &test_invokeGarbageCollector, \
		"Test v2xSe_invokeGarbageCollector for expected behaviour")\
	VTEST_DEFINE_TEST( 51601, &test_getRemainingNvm, \
		"Test v2xSe_getRemainingNvm for expected behaviour")\
	VTEST_DEFINE_TEST( 51701, &test_getSePhase_keyinject, \
		"Test v2xSe_getSePhase in key injection phase")\
	VTEST_DEFINE_TEST( 51702, &test_getSePhase_normal, \
		"Test v2xSe_getSePhase in normal operating phase")\

void test_connect_negative(void);
void test_activate_negative(void);
void test_activateWithSecurityLevel_negative(void);
void test_reset_negative(void);
void test_deactivate_negative(void);
void test_disconnect_negative(void);
void test_getAppletVersion(void);
void test_getSeInfo(void);
void test_getCryptoLibVersion(void);
void test_getPlatformInfo(void);
void test_getPlatformConfig(void);
void test_getChipInfo(void);
void test_getAttackLog(void);
void test_sendReceive(void);
void test_invokeGarbageCollector(void);
void test_getRemainingNvm(void);
void test_getSePhase_keyinject(void);
void test_getSePhase_normal(void);

#endif
