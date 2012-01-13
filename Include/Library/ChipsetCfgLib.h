/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __CHIPSETCFG__LIB__H
#define __CHIPSETCFG__LIB__H

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/HiiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <MultibootDesc.h>

#define CHIPSET_CONFIG_BASIC_MODE                0
#define CHIPSET_CONFIG_CTRL_ONLY_MODE            1
#define CHIPSET_CONFIG_HIDE_CTRL_MODE            2

EFI_STATUS
InitializeChipsetConfig (
  VOID
  );

VOID
CallChipsetConfig (
	VOID
  );

VOID
SetBootManagerMenuMode(
  IN UINT8 Mode
  );

#endif  /* #ifndef __CHIPSETCFG__LIB__H */

