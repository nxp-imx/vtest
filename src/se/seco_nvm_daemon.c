
/*
 * Copyright 2019-2020 NXP
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
 * @file seco_nvm_daemon.c
 *
 * @brief Background process to handle seco blob interaction
 *
 */

#include <stdio.h>
#include "seco_nvm.h"

/**
 *
 * @brief seco-libs function to determine if V2X HW is present
 *
 * @return 1 if V2X HW is present, 0 otherwise
 *
 */
uint32_t seco_os_abs_has_v2x_hw(void);

/** Status variable required by seco_nvm_manager call */
static uint32_t nvm_status;

/**
 *
 * @brief The main function of the seco_nvm_daemon
 *
 * This function simply calls a helper function provided by seco_libs.
 * This helper function must run in a separate thread while using seco_libs
 * and handles seco fs requests for blob handling.
 *
 * @param argc the number of command line arguments, including program name
 * @param argv an array giving the command line arguments
 *
 * @return helper function should never exit, but returns 1 if it does
 *
 */

int main(int argc, char *argv[])
{
	if (seco_os_abs_has_v2x_hw()) {
		printf("calling seco_nvm_manager for V2X\n");
		seco_nvm_manager(NVM_FLAGS_V2X | NVM_FLAGS_HSM, &nvm_status);
	} else {
		printf("calling seco_nvm_manager for SECO\n");
		seco_nvm_manager(NVM_FLAGS_HSM, &nvm_status);
	}

	printf("seco_nvm_manager() completed. nvm_status = 0x%x\n", nvm_status);

	/* return an error as the daemon is never supposed to end */
	return 1;
}
