
/*
 * Copyright 2019 NXP
 */

/**
 *
 * @file SEsignature.h
 *
 * @brief Header files for tests for SE Signature (requirements R7.*)
 *
 */

#ifndef SESIGNATURE_H
#define SESIGNATURE_H

#define SE_SIGNATURE_TESTS \
	{ 70101, &signature_dummy, "Signature placeholder"},\

int signature_dummy(void);

#endif
