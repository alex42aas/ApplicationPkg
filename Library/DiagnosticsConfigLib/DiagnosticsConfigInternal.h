/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef DIAGNOSTICS_CONFIG_INTERNAL_H_
#define DIAGNOSTICS_CONFIG_INTERNAL_H_

CONFIG_ERROR_T
SetDiagnosticsConfigFromINIFile (
  CHAR8 *filePath
);

extern EFI_GUID gIniParserDxeProtocolGuid;

#endif // DIAGNOSTICS_CONFIG_INTERNAL_H_