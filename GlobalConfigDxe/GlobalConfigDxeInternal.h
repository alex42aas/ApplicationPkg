/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef GLOBAL_CONFIG_DXE_INTERNAL_H_
#define GLOBAL_CONFIG_DXE_INTERNAL_H_

#include <Protocol/GlobalConfigDxe.h>
#include <Protocol/GlobalConfigType.h>
#include <Protocol/IniParserDxe.h>

/** \name Config subsystem representation */
typedef struct _CONFIG_ENTRY {
  LIST_ENTRY ListEntry;
  LIST_ENTRY ModuleHead;
  CHAR8 *configName;
  CONFIG_ERROR_T (*SetConfigFromDictionary)(dictionary *dict);
  CONFIG_ERROR_T (*DumpConfigToDictionary)(dictionary *dict);
} CONFIG_ENTRY;

typedef struct _GLOBAL_CONFIG_INTERNAL_DATA {
  EFI_HANDLE             DriverHandle;
  GLOBAL_CONFIG_PROTOCOL GlobalConfigProtocol;
  LIST_ENTRY             configEntryHead;       //!< Head of a list of config subsystems
} GLOBAL_CONFIG_INTERNAL_DATA;

#endif // GLOBAL_CONFIG_DXE_INTERNAL_H_