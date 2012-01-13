/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __DATE__TIME__PAGE__H
#define __DATE__TIME__PAGE__H


#include <CommonDefs.h>
#include <Library/Messages.h>
#include <Guid/MdeModuleHii.h>
#include <Protocol/HiiConfigAccess.h>
#include <Library/MultibootDescUtils.h>
#include <Library/VfrCommon.h>
#include "vfrdata.h"


EFI_STATUS
DateTimePageStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  );


#endif  /* #ifndef __DATE__TIME__PAGE__H */
