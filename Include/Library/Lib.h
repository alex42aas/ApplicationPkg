/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __BIOS__LIB__H
#define __BIOS__LIB__H


#include <Library/CommonUtils.h>
#include <Library/MultibootDescUtils.h>
#include <Library/Lib/Drm.h>
#include <Library/Lib/MII.h>
#include <Library/Lib/MainPage.h>
#include <Library/VfrCommon.h>
#include <Library/FaultTolerance.h>
#include <Library/ExtHdrUtils.h>
#include <Library/Lib/AdminMainPage.h>
#include <Library/Lib/UsersStorage.h>
#include <Library/Lib/Users.h>
#include <InternalErrDesc.h>
#include <Library/FeLib.h>
#include <Library/Lib/TokenFunctions.h>
#include <Library/Lib/CertificatesControl.h>
#include <Library/Lib/PciDevList.h>
#include <Library/Lib/RecoverModePage.h>
#include <Library/Lib/SuperUser.h>
#include <Library/Lib/PlatformCommon.h>



MULTIBOOT_ENTRY *
BIOSSetup (
  VOID
  );


#endif /* #ifndef __BIOS__LIB__H */
