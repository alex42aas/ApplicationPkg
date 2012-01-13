/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __DRM__H
#define __DRM__H

#include <CommonDefs.h>
#include <Protocol/HiiConfigAccess.h>
#include <Guid/MdeModuleHii.h>

#include <InternalErrDesc.h>

#include <Library/CommonUtils.h>
#include <Library/Messages.h>
#include <Library/MultibootDescUtils.h>
#include <Library/ExtHdrUtils.h>

#include <Protocol/DrmHelperProtocol.h>
#include <Protocol/ActivationKeyProviderProtocol.h>

#include "vfrdata.h"

VOID
DrmStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *Config,
  IN OPTIONAL CHAR8 *Language
  );



#endif  /* #ifndef __DRM__H */
