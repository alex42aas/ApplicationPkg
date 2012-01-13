/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef GLOBAL_CONFIG_DXE_H_
#define GLOBAL_CONFIG_DXE_H_

#include <Protocol/IniParserDxe.h>
#include <Protocol/GlobalConfigType.h>

typedef struct _GLOBAL_CONFIG_PROTOCOL GLOBAL_CONFIG_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *GLOBAL_CONFIG_ADD_CONFIG) (
  IN CHAR8 *configName,
  IN CONFIG_ERROR_T (*SetConfigFromData)(dictionary *dict),
  IN CONFIG_ERROR_T (*DumpConfigToDictionary)(dictionary *dict)
);

typedef
CONFIG_RESULT_T
(EFIAPI *GLOBAL_CONFIG_DUMP_CONFIG_DATA) (
  IN UINT8 **configData,
  IN UINTN *dataLen
);

typedef
CONFIG_RESULT_T
(EFIAPI *GLOBAL_CONFIG_DO_CONFIG_DATA) (
  IN UINT8 *configData,
  IN UINTN dataLen
);

typedef
CONFIG_RESULT_T
(EFIAPI *GLOBAL_CONFIG_DO_CONFIG_FILE) (
  IN CHAR8 *filePath
);

typedef
CONFIG_RESULT_T
(EFIAPI *GLOBAL_CONFIG_DO_CONFIG) (
  IN VOID
);

/*! Struct of global config protocol */
struct _GLOBAL_CONFIG_PROTOCOL {
  GLOBAL_CONFIG_ADD_CONFIG       AddConfig;            //!< Register callback method for subsystem
  GLOBAL_CONFIG_DUMP_CONFIG_DATA DumpAllConfigToData;  //!< Dump config of all subsystems to memory buffer
  GLOBAL_CONFIG_DO_CONFIG_DATA   DoAllConfigWithData;  //!< Configure all subsystems have been registered with config data
  GLOBAL_CONFIG_DO_CONFIG_FILE   DoAllConfigWithFile;  //!< Configure all subsystems have been registered with path to INI file
  GLOBAL_CONFIG_DO_CONFIG        DoAllConfig;          //!< Configure all subsystems have been registered with default config
};

extern EFI_GUID gGlobalConfigProtocolGuid;

#endif // GLOBAL_CONFIG_DXE_H_