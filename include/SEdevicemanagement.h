
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

#define EXPECTED_VERSION_GENERATION	3
#define V2XSE_MAX_TX_RX_SIZE 261

#define SE_DEVICE_MANAGEMENT_TESTS \
	{ 50102, &test_connect_negative, \
		"Negative test for v2xSe_connect"},\
	{ 50202, &test_activate_negative, \
		"Negative test for v2xSe_activate"},\
	{ 50302, &test_activateWithSecurityLevel_negative, \
		"Negative test for v2xSe_activateWithSecurtyLevel"},\
	{ 50402, &test_reset_negative, \
		"Negative test for v2xSe_reset"},\
	{ 50502, &test_deactivate_negative, \
		"Negative test for v2xSe_deactivate"},\
	{ 50602, &test_disconnect_negative, \
		"Negative test for v2xSe_disconnect"},\
	{ 50701, &test_getAppletVersion, \
		"Test v2xSe_getAppletVersion for expected behaviour"},\
	{ 50801, &test_getSeInfo, \
		"Test v2xSe_getSeInfo for expected behaviour"},\
	{ 50901, &test_getCryptoLibVersion, \
		"Test v2xSe_getCryptoLibVersion for expected behaviour"},\
	{ 51001, &test_getPlatformInfo, \
		"Test v2xSe_getPlatformInfo for expected behaviour"},\
	{ 51101, &test_getPlatformConfig, \
		"Test v2xSe_getPlatformConfig for expected behaviour"},\
	{ 51201, &test_getChipInfo, \
		"Test v2xSe_getChipInfo for expected behaviour"},\
	{ 51301, &test_getAttackLog, \
		"Test v2xSe_getAttackLog for expected behaviour"},\
	{ 51401, &test_sendReceive, \
		"Test v2xSe_sendReceive for expected behaviour"},\
	{ 51501, &test_invokeGarbageCollector, \
		"Test v2xSe_invokeGarbageCollector for expected behaviour"},\
	{ 51601, &test_getRemainingNvm, \
		"Test v2xSe_getRemainingNvm for expected behaviour"},\
	{ 51701, &test_getSePhase_keyinject, \
		"Test v2xSe_getSePhase in key injection phase"},\
	{ 51702, &test_getSePhase_normal, \
		"Test v2xSe_getSePhase in normal operating phase"},\

int test_connect_negative(void);
int test_activate_negative(void);
int test_activateWithSecurityLevel_negative(void);
int test_reset_negative(void);
int test_deactivate_negative(void);
int test_disconnect_negative(void);
int test_getAppletVersion(void);
int test_getSeInfo(void);
int test_getCryptoLibVersion(void);
int test_getPlatformInfo(void);
int test_getPlatformConfig(void);
int test_getChipInfo(void);
int test_getAttackLog(void);
int test_sendReceive(void);
int test_invokeGarbageCollector(void);
int test_getRemainingNvm(void);
int test_getSePhase_keyinject(void);
int test_getSePhase_normal(void);

#endif
