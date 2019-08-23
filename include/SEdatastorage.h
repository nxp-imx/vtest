
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEdatastorage.h
 *
 * @brief Header file for tests for SE Generic Data Storage (requirements R9.*)
 *
 */

#ifndef SEDATASTORAGE_H
#define SEDATASTORAGE_H

#define TEST_STRING_SLOT_0 	"Hi there slot 0"
#define TEST_STRING_NON_ZERO 	"Hi there non-zero slot"
#define TEST_STRING_MAX_SLOT	"Hi there max slot"

#define SLOT_ZERO	0
#define NON_ZERO_SLOT	1234
#define MAX_SLOT	(seInfo.maxDataSlots - 1)

#define TEST_BYTE	0x13

#define SE_DATA_STORAGE_TESTS \
	{ 90101, &test_storeData_getData, \
		"Test v2xSe_storeData for expected behaviour"},\
	{ 90201, &test_storeData_getData, \
		"Test v2xSe_getData for expected behaviour"},\
	{ 90301, &test_deleteData, \
		"Test v2xSe_deleteData for expected behaviour"},\

int test_storeData_getData(void);
int test_deleteData(void);

#endif
