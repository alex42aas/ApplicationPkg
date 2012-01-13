/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef GLOBAL_CONFIG_TYPE_H_
#define GLOBAL_CONFIG_TYPE_H_

typedef enum {
  SUCCESS_TO_SET_CONFIG,            // 0 Config did well
  CANT_LOCATE_INI_PARSER_PROTOCOL,  // 1 Error to locate iniParserProtocol
  ERROR_INVALID_PARAMETER,          // 2 Invalid parameter passed to the subsystem
  ERROR_OUT_OF_MEMORY,              // 3 Out of memory
  NO_CONFIG_KEY,                     // 4 Can't find  key for specified config in INI file
  CANT_READ_CONFIG_FROM_VARIABLE,   // 5 Config subsystem can't read it's own config from the variable
  UNSUPPORTED_KEY_VALUE,            // 6 Unsupported key value in the INI file for specified config
  CANT_SAVE_CONFIG_TO_VARIABLE,     // 7 Config subsystem can't save it's own config to the variable
  UNSUPPORTED_SETTING_COMBINATION,  // 8 The combination of keys is unsupported
  CANT_SAVE_CONFIG_TO_DICTIONARY,
  NO_CONFIG_SECTION
} CONFIG_ERROR_T;

/** \name A report of configure */
typedef struct {
  CHAR8 *configName;      //!< Name of subsystem
  CONFIG_ERROR_T status;  //!< Status of configure
} REPORT_LIST_T;

/** \name Global Config result */
typedef struct {
  EFI_STATUS globalStatus;     //!< Global Config Status
  UINTN numSubsystems;         //!< Number of config subsystems has been registered
  REPORT_LIST_T *reportList;   //!< A list of results for all subsystems
} CONFIG_RESULT_T;

#endif // GLOBAL_CONFIG_TYPE_H_