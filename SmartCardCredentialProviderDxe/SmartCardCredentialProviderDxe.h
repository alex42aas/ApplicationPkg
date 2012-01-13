/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef SMARTCARDCREDENTIALPROVIDERDXE_H_
#define SMARTCARDCREDENTIALPROVIDERDXE_H_

#include <Protocol/DevicePath.h>
#include <Protocol/Runtime.h>
#include <Protocol/LoadFile.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/Security.h>
#include <Protocol/UserCredential.h>

#include <Protocol/FormBrowser2.h>
#include <Protocol/HiiDatabase.h>
#include <Protocol/HiiString.h>
#include <Protocol/HiiConfigAccess.h>
#include <Protocol/SimpleTextOut.h>
#include <Protocol/DevicePathToText.h>
#include <Guid/SmartCardCredentialProvider.h>
#include <Library/HiiLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <Guid/MemoryTypeInformation.h>
#include <Guid/FirmwareFileSystem2.h>
#include <Guid/HobList.h>
#include <Guid/DebugImageInfoTable.h>
#include <Guid/FileInfo.h>
#include <Guid/Apriori.h>
#include <Guid/DxeServices.h>
#include <Guid/MemoryAllocationHob.h>
#include <Guid/EventLegacyBios.h>
#include <Guid/EventGroup.h>
#include <Guid/MdeModuleHii.h>


#include <Library/DxeCoreEntryPoint.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/HobLib.h>
#include <Library/PerformanceLib.h>
#include <Library/UefiDecompressLib.h>
#include <Library/ExtractGuidedSectionLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PeCoffLib.h>
#include <Library/PcdLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/ReportStatusCodeLib.h>
#include <Library/TimerLib.h>

#include <Protocol/UserManager.h>
#include <Protocol/SmartCard.h>

#define FORMSET_GUID \
{ \
   0x543cd4ff, 0x1276, 0x443d, {0x41, 0x42, 0x34, 0xc2, 0x32, 0xfe, 0xb2, 0x42 } \
}

#define INVENTORY_GUID \
  { \
    0xb4f55470, 0x6141, 0x4621, {0x8f, 0x19, 0x70, 0x4e, 0x57, 0x7a, 0xa9, 0xe8} \
  }


#define CONFIGURATION_VARSTORE_ID    0x1234

extern UINT8 SmartCardProviderStrings[];
extern UINT8 SmartCardVfrBin[];


#endif /* SMARTCARDCREDENTIALPROVIDERDXE_H_ */
