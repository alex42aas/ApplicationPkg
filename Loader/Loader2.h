/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _MULTIBOOT_LOADER2_H
#define _MULTIBOOT_LOADER2_H

#include <PiDxe.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/GuidedSectionExtraction.h>
#include <Protocol/DevicePath.h>
#include <Protocol/Runtime.h>
#include <Protocol/LoadFile.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/VariableWrite.h>
#include <Protocol/PlatformDriverOverride.h>
#include <Protocol/Variable.h>
#include <Protocol/Timer.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/Bds.h>
#include <Protocol/RealTimeClock.h>
#include <Protocol/WatchdogTimer.h>
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/MonotonicCounter.h>
#include <Protocol/StatusCode.h>
#include <Protocol/Decompress.h>
#include <Protocol/LoadPe32Image.h>
#include <Protocol/Security.h>
#include <Protocol/Ebc.h>
#include <Protocol/Reset.h>
#include <Protocol/Cpu.h>
#include <Protocol/Metronome.h>
#include <Protocol/FirmwareVolumeBlock.h>
#include <Protocol/Capsule.h>
#include <Protocol/BusSpecificDriverOverride.h>

#include <Protocol/FormBrowser2.h>
#include <Protocol/HiiDatabase.h>
#include <Protocol/HiiString.h>
#include <Protocol/HiiConfigAccess.h>
#include <Protocol/SimpleTextOut.h>
#include <Protocol/BlockIo.h>
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
#include <Library/TimerLib.h>
#include <Protocol/Multiboot.h>
#include <Library/Messages.h>
#include <Library/FsUtils.h>
#include <Library/ExtHdrUtilsLite.h>
#include <Library/MultibootDescUtils.h>
#include <Library/BootMngrLib.h>

typedef UINT8 BINARY_HEADER;

typedef struct _KERNEL_HEADER {
  MODULE_FORMAT Format;
  union {
    MULTIBOOT_HEADER *Multiboot;
    LINUX_HEADER     *Linux;
    BINARY_HEADER    *Raw;
  } h;
} KERNEL_HEADER;


extern MULTIBOOT_DATA *gMultibootData;
extern MULTIBOOT_INFO *gMultibootInfo;

VOID 
PrepareToStartOS(
  MULTIBOOT_HEADER *Header,
  UINT32 BaseAddress,
  UINT32 LoadAddress, 
  UINT32 LoadSize,
  UINT32 KernelEntry 
  );

EFI_STATUS
LoadModule(
  IN      CHAR8* DevicePath,
  IN OUT  EFI_PHYSICAL_ADDRESS *BaseAddress,
  OUT     UINTN  *FileSize,
  IN      BOOLEAN bHashPresent,
  IN      UINT8  *RightHash,
  IN      CHAR8 *GuidStr
  );

VOID 
SendError(
  EFI_STRING_ID StringId, 
  EFI_STATUS Status 
  );

VOID 
StartLinuxKernel (
    IN      UINT32        JumpAddr,
    IN      LINUX_PARAMS  *LinuxParams
    );

EFI_STATUS
EFIAPI
MultibootLoaderInit (
  IN EFI_HANDLE                   ImageHandle,
  IN EFI_SYSTEM_TABLE             *SystemTable
  );


#endif
