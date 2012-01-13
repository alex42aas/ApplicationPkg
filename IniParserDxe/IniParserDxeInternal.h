/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef INI_PARSER_DXE_INTERNAL_H_
#define INI_PARSER_DXE_INTERNAL_H_

#include <Protocol/IniParserDxe.h>

/** Internal data of the INI parser protocol */
typedef struct _INI_PARSER_INTERNAL_DATA {
  EFI_HANDLE            DriverHandle;       //!< Handle of the INI parser DXE driver
  INI_PARSER_PROTOCOL   IniParserPtotocol;  //!< INI parser protocol
} INI_PARSER_INTERNAL_DATA;

#endif // INI_PARSER_DXE_INTERNAL_H_

