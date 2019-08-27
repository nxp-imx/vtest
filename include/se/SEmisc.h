
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEmisc.h
 *
 * @brief Header file for miscellaneous support function for SE tests
 *
 */

#ifndef SEMISC_H
#define SEMISC_H

/** Path to EU applet phase variable in file system */
#define EU_PHASE_FILENAME "/etc/v2x_hsm_adaptation/EU/v2xsePhase"
/** Path to UU applet phase variable in file system */
#define US_PHASE_FILENAME "/etc/v2x_hsm_adaptation/US/v2xsePhase"

/** Random known byte for various tests */
#define TEST_BYTE	0x13

/** Index of nvm slot 0 */
#define SLOT_ZERO	0
/** Index of a non-zero nvm slot */
#define NON_ZERO_SLOT	1234
/** Index of last nvm slot */
#define MAX_SLOT	(seInfo.maxDataSlots - 1)

int setupInitState(void);
int setupConnectedState(void);
int setupActivatedState(appletSelection_t appId);
int setupActivatedNormalState(appletSelection_t appId);
int removeNvmVariable(char *filename);

#endif
