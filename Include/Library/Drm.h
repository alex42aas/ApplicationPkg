/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#pragma once

#include <CommonDefs.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/Md5.h>
#include <Library/Base32.h>
#include <Library/Crc32.h>
#include <Library/ExtHdrUtils.h>
#include <Protocol/FirmwareVolumeBlock.h>

// #define DRM_RECORD_GUID_STR   "047EF50B-DCD6-40AD-838A-5B04B39AEB16"   // DRM rec v.0.0.1
#define DRM_RECORD_GUID_STR   "64D63010-BFEE-49CE-BE89-9DB45B68E45D"    // DRM rec v.0.0.2

#define   DRM_HIDE_OPTION_VALUE         0x0010  // 0x0000 - 0xFFFF
#define   MAC_SIZE                      6
#define   DRM_RAW_DATA_SIZE             32  // sizeof(EFI_GUID) + 2*sizeof(MAC_ADDRESS) + 4  // add 4 to get a power of 2
#define   DRM_MIXED_RAW_DATA_SIZE       (DRM_RAW_DATA_SIZE + DRM_RAW_DATA_SIZE/8)
#define   DRM_HASH_DATA_SIZE            MD5_HASHSIZE    // MD5 Hash size = 16
#define   DRM_MIXED_HASH_DATA_SIZE      (DRM_HASH_DATA_SIZE + DRM_HASH_DATA_SIZE/8)
#define   DRM_BASE32_DATA_SIZE          DRM_RAW_DATA_SIZE + 1  // append '\0' symbol
#define   DRM_KEY_GROUP_SIZE            6
#define   DRM_KEY_SIZE                  34
#define   DRM_RECORD_SIZE               (sizeof(UINT8) + sizeof(UINT16) + sizeof(EFI_GUID) + sizeof(UINT8) + DRM_KEY_SIZE)


EFI_STATUS
WriteDrmKeyToFv (
  IN UINT8* DrmKey
  );


EFI_STATUS
GetDrmKey (
  OUT UINT8* DrmKey
  );


EFI_STATUS
GenerateDrmKey (
  IN EFI_GUID *SerialNumber,
  IN UINT8 *MacBuf1,
  IN UINT8 *MacBuf2,
  OUT CHAR8 *DrmKeyBuf
  );
