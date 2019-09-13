
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
 * @file testlist.c
 *
 * @brief Defines list of all tests that can be run
 *
 */

#include "vtest.h"
#include "SEdevicemanagement.h"
#include "SEkeymanagement.h"
#include "SEsignature.h"
#include "SEecies.h"
#include "SEdatastorage.h"
#include "SEutility.h"
#include "SEkeyinjection.h"
#include "SEperformance.h"
#include "ECDSAplaceholder.h"

/**
 * @brief Array containing entries for all avialable tests
 *
 * This array containts an entry for each available test.
 * Tests should be placed in the following array in order of test
 * number
 */
testEntry_t allTests[] = {
	ECDSA_PLACEHOLDER_TESTS
	SE_DEVICE_MANAGEMENT_TESTS
	SE_KEY_MANAGEMENT_TESTS
	SE_SIGNATURE_TESTS
	SE_ECIES_TESTS
	SE_DATA_STORAGE_TESTS
	SE_UTILITY_TESTS
	SE_KEY_INJECTION_TESTS
	SE_PERFORMANCE_TESTS
};

/**
 *
 * @brief Utility function get total number of available tests
 *
 * @return total number of available tests
 *
 */
int getNumTests(void)
{
	return sizeof(allTests)/sizeof(testEntry_t);
}
