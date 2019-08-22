
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

#define SE_DEVICE_MANAGEMENT_TESTS \
	{ 50101, &device_management_dummy, "Device management placeholder"},\

int device_management_dummy(void);

#endif
