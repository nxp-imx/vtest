
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

#define SE_DATA_STORAGE_TESTS \
	{ 90101, &data_storage_dummy, "Data storage placeholder"},\

int data_storage_dummy(void);

#endif
