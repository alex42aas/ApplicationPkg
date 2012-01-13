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

#include <string.h>
#include <Library/DebugLib.h>
#include <Library/PciLib.h>
#include <Library/IoLib.h>
#include <Library/ExtHdrUtils.h>
#include <Library/BaseLib.h>
#include <Library/CommonUtils.h>
#include <Library/HiiLib.h>
#include <Library/PcdLib.h>
#include <Library/PciDevsMonitorLib.h>
#include <Library/FsUtils.h>
#include <Library/Drm.h>
#include <Protocol/Runtime.h>


#define   MAC_ADDRESS_SIZE              6   // bytes

#define   DRM_KEY_FILE_NAME             L"BiosDrmKey"
#define   SERIAL_NUMBER_STRING_LENGTH   (2*sizeof(EFI_GUID) + 4)  // GGGGGGGG-GGGG-GGGG-GGGG-GGGGGGGGGGGG
#define   MAC_STRING_LENGTH             (2*MAC_ADDRESS_SIZE + 5)  // MM:MM:MM:MM:MM:MM
#define   DRM_KEY_STRING_LENGTH         DRM_KEY_SIZE              // DDDDDD-DDDDDD-DDDDDD-DDDDDD-DDDDDD
#define   DRM_KEY_FILE_LINE_LENGTH      (SERIAL_NUMBER_STRING_LENGTH + 2*MAC_STRING_LENGTH + DRM_KEY_STRING_LENGTH + 5) // 4 (';') + '\n' 
#define   DRM_KEY_FILE_SEP_CHAR         ";"

struct _MAC_LIST_NODE {
  EFI_LIST_ENTRY Link;
  UINT8 MacAddressBuf[MAC_ADDRESS_SIZE];
};
typedef   struct _MAC_LIST_NODE   MAC_LIST_NODE;

struct _DRM_KEY_FILE_RECORD {
  EFI_GUID SerialNumber;
  UINT8 MacAddress1[MAC_ADDRESS_SIZE];
  UINT8 MacAddress2[MAC_ADDRESS_SIZE];
  CHAR8 DrmKey[DRM_KEY_SIZE];
};
typedef   struct _DRM_KEY_FILE_RECORD   DRM_KEY_FILE_RECORD;


EFI_STATUS
GetMacAddressList (
  OUT EFI_LIST_ENTRY* ListHead
  );


VOID
FreeMacAddressList (
  IN EFI_LIST_ENTRY* ListHead
  );


EFI_STATUS
VerifyMacAddress (
  IN EFI_GUID *SysGuid,
  IN CHAR8 *Language
  );
