
/*
 * Copyright 2019 NXP
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
/** Index of last data nvm slot */
#define MAX_DATA_SLOT	(seInfo.maxDataSlots - 1)
/** Index of last RT nvm slot */
#define MAX_RT_SLOT	(seInfo.maxRtKeysAllowed - 1)
/** Index of last BA nvm slot */
#define MAX_BA_SLOT	(seInfo.maxBaKeysAllowed - 1)

int setupInitState(void);
int setupConnectedState(void);
int setupActivatedState(appletSelection_t appId);
int setupActivatedNormalState(appletSelection_t appId);
int removeNvmVariable(char *filename);

#endif
