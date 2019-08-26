
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file vtest.c
 *
 * @brief Header file for V2X test application
 *
 */

#ifndef VTEST_H
#define VTEST_H

#define BEFORE_FIRST_TEST	(0)
#define AFTER_LAST_TEST		(1000000)

#define VTEST_PASS	(1)
#define VTEST_FAIL	(-1)
#define VTEST_CONF	(0)

#define TEST_BYTE	0x13

#define EU_PHASE_FILENAME "/etc/v2x_hsm_adaptation/EU/v2xsePhase"
#define US_PHASE_FILENAME "/etc/v2x_hsm_adaptation/US/v2xsePhase"

#define SLOT_ZERO	0
#define NON_ZERO_SLOT	1234
#define MAX_SLOT	(seInfo.maxDataSlots - 1)

int legacy_test();
#define LEGACY_TESTS_TO_REMOVE \
	{1, &legacy_test, "Legacy test - to be re-written"},\

typedef struct {
	int testNum;
	int (*testFn)(void);
	char* testName;
} testEntry;

int setupInitState(void);
int setupConnectedState(void);
int setupActivatedState(appletSelection_t appId);
int setupActivatedNormalState(appletSelection_t appId);
int removeNvmVariable(char *filename);

#endif
