/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __BIOS__INFO__H
#define __BIOS__INFO__H


#include <Base.h>

// "xx.xx.xx.xx"
#define BIOS_INFO_VER_STR_SIZE            12
// "hh.mm.ss dd.mm.yyyy"
#define BIOS_INFO_BUILD_STR_SIZE          20

#pragma pack(push)
#pragma pack(1)

typedef struct tBiosInfoRecord {
  UINT8 Type;           // 2 - bios info
  UINT16 Size;          //
  EFI_GUID PlatformGuid;
  CHAR8 BiosVerStr[BIOS_INFO_VER_STR_SIZE];
  CHAR8 BiosBuildStr[BIOS_INFO_BUILD_STR_SIZE];
} BiosInfoRecord;

#pragma pack(pop)



#endif /* #ifndef __BIOS__INFO__H */

