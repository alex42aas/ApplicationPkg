/** @file
  This module produce main entry for BDS phase - BdsEntry.
  When this module was dispatched by DxeCore, gEfiBdsArchProtocolGuid will be installed
  which contains interface of BdsEntry.
  After DxeCore finish DXE phase, gEfiBdsArchProtocolGuid->BdsEntry will be invoked
  to enter BDS phase.

Copyright (c) 2004 - 2008, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "Bds.h"
#include "Language.h"
#include "FrontPage.h"
//#include "Hotkey.h"
#include "HwErrRecSupport.h"
//#include "Loader.h"
#include "Multiboot.h"
#include <Guid/Performance.h>
#include <Library/TimerLib.h>
#include <Protocol/BdsHelperProtocol.h>


STATIC BDS_HELPER_PROTOCOL *gBdsHelperProtocol;


EFI_STATUS
EFIAPI
MultibootLoaderInit (
  IN EFI_HANDLE                   ImageHandle,
  IN EFI_SYSTEM_TABLE             *SystemTable
  );



///
/// BDS arch protocol instance initial value.
///
/// Note: Current BDS not directly get the BootMode, DefaultBoot,
/// TimeoutDefault, MemoryTestLevel value from the BDS arch protocol.
/// Please refer to the library useage of BdsLibGetBootMode, BdsLibGetTimeout
/// and PlatformBdsDiagnostics in BdsPlatform.c
///
EFI_HANDLE  gBdsHandle = NULL;

EFI_BDS_ARCH_PROTOCOL  gBds = {
  BdsEntry
};

UINT16                          *mBootNext = NULL;

EFI_HANDLE                      mBdsImageHandle;
EFI_SYSTEM_TABLE                *mSystemTable;
EFI_EVENT                   mHiiRegistration;


/**

  Install Boot Device Selection Protocol

  @param ImageHandle     The image handle.
  @param SystemTable     The system table.

  @retval  EFI_SUCEESS  BDS has finished initializing.
                        Return the dispatcher and recall BDS.Entry
  @retval  Other        Return status from AllocatePool() or gBS->InstallProtocolInterface

**/
EFI_STATUS
EFIAPI
BdsInitialize (
  IN EFI_HANDLE                            ImageHandle,
  IN EFI_SYSTEM_TABLE                      *SystemTable
  )
{
  EFI_STATUS  Status;

  mBdsImageHandle = ImageHandle;
  mSystemTable = SystemTable;

  //
  // Register notify function on HII Database Protocol to add font package.
  //
  EfiCreateProtocolNotifyEvent (
    &gEfiHiiDatabaseProtocolGuid,
    TPL_CALLBACK,
    InstallRusLanguage,
    NULL,
    &mHiiRegistration
    );

  //
  // Install protocol interface
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &gBdsHandle,
                  &gEfiBdsArchProtocolGuid, &gBds,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  return Status;
}

/**

  This function attempts to boot for the boot order specified
  by platform policy.

**/
VOID
BdsBootDeviceSelect (
  VOID
  )
{
  EFI_STATUS        Status;
  LIST_ENTRY        *Link;
  BDS_COMMON_OPTION *BootOption;
  UINTN             ExitDataSize;
  CHAR16            *ExitData;
  UINT16            Timeout;
  LIST_ENTRY        BootLists;
  CHAR16            Buffer[20];
  BOOLEAN           BootNextExist;
  LIST_ENTRY        *LinkBootNext;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  //
  // Got the latest boot option
  //
  BootNextExist = FALSE;
  LinkBootNext  = NULL;
  InitializeListHead (&BootLists);

  //
  // First check the boot next option
  //
  ZeroMem (Buffer, sizeof (Buffer));

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (mBootNext != NULL) {
    DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    
    //
    // Indicate we have the boot next variable, so this time
    // boot will always have this boot option
    //
    BootNextExist = TRUE;

    //
    // Clear the this variable so it's only exist in this time boot
    //
    gRT->SetVariable (
          L"BootNext",
          &gEfiGlobalVariableGuid,
          EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
          0,
          mBootNext
          );

    //
    // Add the boot next boot option
    //
    UnicodeSPrint (Buffer, sizeof (Buffer), L"Boot%04x", *mBootNext);
    BootOption = BdsLibVariableToOption (&BootLists, Buffer);

    //
    // If fail to get boot option from variable, just return and do nothing.
    //
    if (BootOption == NULL) {
      return;
    }

    BootOption->BootCurrent = *mBootNext;
  }
  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  //
  // Parse the boot order to get boot option
  //
  BdsLibBuildOptionFromVar (&BootLists, L"BootOrder");
  Link = BootLists.ForwardLink;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  //
  // Parameter check, make sure the loop will be valid
  //
  if (Link == NULL) {
    return ;
  }

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  //
  // Here we make the boot in a loop, every boot success will
  // return to the front page
  //
  for (;;) {
    //
    // Check the boot option list first
    //
    if (Link == &BootLists) {
      //
      // There are two ways to enter here:
      // 1. There is no active boot option, give user chance to
      //    add new boot option
      // 2. All the active boot option processed, and there is no
      //    one is success to boot, then we back here to allow user
      //    add new active boot option
      //
      Timeout = 0xffff;
      //PlatformBdsEnterFrontPage (Timeout, FALSE);
      InitializeListHead (&BootLists);
      BdsLibBuildOptionFromVar (&BootLists, L"BootOrder");
      Link = BootLists.ForwardLink;
      continue;
    }
    //
    // Get the boot option from the link list
    //
    BootOption = CR (Link, BDS_COMMON_OPTION, Link, BDS_LOAD_OPTION_SIGNATURE);

    //
    // According to EFI Specification, if a load option is not marked
    // as LOAD_OPTION_ACTIVE, the boot manager will not automatically
    // load the option.
    //
    if (!IS_LOAD_OPTION_TYPE (BootOption->Attribute, LOAD_OPTION_ACTIVE)) {
      //
      // skip the header of the link list, because it has no boot option
      //
      Link = Link->ForwardLink;
      continue;
    }
    //
    // Make sure the boot option device path connected,
    // but ignore the BBS device path
    //
    if (DevicePathType (BootOption->DevicePath) != BBS_DEVICE_PATH) {
      //
      // Notes: the internal shell can not been connected with device path
      // so we do not check the status here
      //
      BdsLibConnectDevicePath (BootOption->DevicePath);
    }
    //
    // All the driver options should have been processed since
    // now boot will be performed.
    //
    Status = BdsLibBootViaBootOption (BootOption, BootOption->DevicePath, &ExitDataSize, &ExitData);
    if (EFI_ERROR (Status)) {
      //
      // Call platform action to indicate the boot fail
      //
      BootOption->StatusString = GetStringById (L"Boot Failed");//(STRING_TOKEN (STR_BOOT_FAILED));
      if (gBdsHelperProtocol) {
        gBdsHelperProtocol->PlatformBdsBootFail (
                                gBdsHelperProtocol, 
                                BootOption, 
                                Status, 
                                ExitData, 
                                ExitDataSize);
      }

      //
      // Check the next boot option
      //
      Link = Link->ForwardLink;

    } else {
      //
      // Call platform action to indicate the boot success
      //
      BootOption->StatusString = GetStringById (L"Boot Success"); //(STRING_TOKEN (STR_BOOT_SUCCEEDED));
      if (gBdsHelperProtocol) {
        gBdsHelperProtocol->PlatformBdsBootSuccess (
                                gBdsHelperProtocol, 
                                BootOption);
      }

      //
      // Boot success, then stop process the boot order, and
      // present the boot manager menu, front page
      //
      Timeout = 0xffff;
      //PlatformBdsEnterFrontPage (Timeout, FALSE);

      //
      // Rescan the boot option list, avoid potential risk of the boot
      // option change in front page
      //
      if (BootNextExist) {
        LinkBootNext = BootLists.ForwardLink;
      }

      InitializeListHead (&BootLists);
      if (LinkBootNext != NULL) {
        //
        // Reserve the boot next option
        //
        InsertTailList (&BootLists, LinkBootNext);
      }

      BdsLibBuildOptionFromVar (&BootLists, L"BootOrder");
      Link = BootLists.ForwardLink;
    }
  }

}


extern VOID
GetNameFromHandle (
  IN  EFI_HANDLE     Handle,
  OUT CHAR8          *GaugeString
  );


VOID
PrintPerfStr(
  IN CHAR8 *Token,
  IN UINT32 Duration
  )
{
  volatile CHAR8 Str[100];
  UINTN Len, Idx;

  Len = AsciiStrLen(Token);
  if (Len > (sizeof(Str) - 30)) {    
    Token[sizeof(Str) - 31] = 0;
  }
  
  AsciiStrCpy((CHAR8*)Str, Token);
  Len = AsciiStrLen(Token);

  for (Idx = Len; Idx < sizeof(Str) - 1; Idx++) {
    Str[Idx] = ' ';
  }
  Str[sizeof(Str) - 1] = '\0';
  
  AsciiSPrint((CHAR8*)&Str[sizeof(Str) - 31], 30, "%d (0x%X)",
    Duration, Duration);
  DEBUG((EFI_D_INFO, "%a\n", Str));
}

VOID
ShowPerformanceData (
  VOID
  )
{
  EFI_STATUS                Status;
  UINT32                    AcpiLowMemoryLength;
  UINT32                    LimitCount;
  EFI_HANDLE                *Handles;
  UINTN                     NoHandles;
  CHAR8                     GaugeString[PERF_TOKEN_LENGTH];
  UINT8                     *Ptr;
  UINT32                    Index;
  UINT64                    Ticker;
  UINT64                    Freq;
  UINT32                    Duration;
  UINTN                     LogEntryKey;
  CONST VOID                *Handle;
  CONST CHAR8               *Token;
  CONST CHAR8               *Module;
  UINT64                    StartTicker;
  UINT64                    EndTicker;
  UINT64                    StartValue;
  UINT64                    EndValue;
  BOOLEAN                   CountUp;
  UINTN                     EntryIndex;
  UINTN                     NumPerfEntries;
  //
  // List of flags indicating PerfEntry contains DXE handle
  //
  BOOLEAN                   *PerfEntriesAsDxeHandle;
  
  PERF_HEADER               mPerfHeader;
  PERF_DATA                 mPerfData;
  EFI_PHYSICAL_ADDRESS      mAcpiLowMemoryBase = 0x0FFFFFFFFULL;

  //
  // Retrieve time stamp count as early as possible
  //
  Ticker  = GetPerformanceCounter ();

  Freq    = GetPerformanceCounterProperties (&StartValue, &EndValue);
  
  Freq    = DivU64x32 (Freq, 1000);

  ZeroMem(&mPerfHeader, sizeof(mPerfHeader));
  mPerfHeader.CpuFreq = Freq;
 
  //
  // Record BDS raw performance data
  //
  if (EndValue >= StartValue) {
    mPerfHeader.BDSRaw = Ticker - StartValue;
    CountUp            = TRUE;
  } else {
    mPerfHeader.BDSRaw = StartValue - Ticker;
    CountUp            = FALSE;
  }

  //
  // Put Detailed performance data into memory
  //
  Handles = NULL;
  Status = gBS->LocateHandleBuffer (
                  AllHandles,
                  NULL,
                  NULL,
                  &NoHandles,
                  &Handles
                  );
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_INFO, "%a.%d Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return ;
  }


  AcpiLowMemoryLength = 0x4000;
  if (mAcpiLowMemoryBase == 0x0FFFFFFFF) {
    //
    // Allocate a block of memory that contain performance data to OS
    //
    Status = gBS->AllocatePages (
                    AllocateMaxAddress,
                    EfiReservedMemoryType,
                    EFI_SIZE_TO_PAGES (AcpiLowMemoryLength),
                    &mAcpiLowMemoryBase
                    );
    if (EFI_ERROR (Status)) {
      FreePool (Handles);
      DEBUG((EFI_D_INFO, "%a.%d Status=0x%X\n", 
        __FUNCTION__, __LINE__, Status));
      return ;
    }
  }


  Ptr        = (UINT8 *) ((UINT32) mAcpiLowMemoryBase + sizeof (PERF_HEADER));
  LimitCount = (AcpiLowMemoryLength - sizeof (PERF_HEADER)) / sizeof (PERF_DATA);

  NumPerfEntries = 0;
  LogEntryKey    = 0;
  while ((LogEntryKey = GetPerformanceMeasurement (
                          LogEntryKey,
                          &Handle,
                          &Token,
                          &Module,
                          &StartTicker,
                          &EndTicker)) != 0) {
    NumPerfEntries++;
  }
  PerfEntriesAsDxeHandle = AllocateZeroPool (NumPerfEntries * sizeof (BOOLEAN));
  ASSERT (PerfEntriesAsDxeHandle != NULL);

  DEBUG((EFI_D_INFO, "%a.%d NumPerfEntries=%d\n", 
      __FUNCTION__, __LINE__, NumPerfEntries));
  
  //
  // Get DXE drivers performance
  //
  for (Index = 0; Index < NoHandles; Index++) {
    Ticker = 0;
    LogEntryKey = 0;
    EntryIndex  = 0;
    while ((LogEntryKey = GetPerformanceMeasurement (
                            LogEntryKey,
                            &Handle,
                            &Token,
                            &Module,
                            &StartTicker,
                            &EndTicker)) != 0) {
      if (Handle == Handles[Index] && !PerfEntriesAsDxeHandle[EntryIndex]) {
        PerfEntriesAsDxeHandle[EntryIndex] = TRUE;
      }
      EntryIndex++;
      if ((Handle == Handles[Index]) && (EndTicker != 0)) {
        if (StartTicker == 1) {
          StartTicker = StartValue;
        }
        if (EndTicker == 1) {
          EndTicker = StartValue;
        }
        Ticker += CountUp ? (EndTicker - StartTicker) : (StartTicker - EndTicker);
      }
    }

    Duration = (UINT32) DivU64x32 (Ticker, (UINT32) Freq);

    if (Duration > 0) {

      GetNameFromHandle (Handles[Index], GaugeString);

      AsciiStrCpy (mPerfData.Token, GaugeString);
      mPerfData.Duration = Duration;

      CopyMem (Ptr, &mPerfData, sizeof (PERF_DATA));
      Ptr += sizeof (PERF_DATA);

      PrintPerfStr(mPerfData.Token, mPerfData.Duration);

      mPerfHeader.Count++;
      if (mPerfHeader.Count == LimitCount) {
        goto Done;
      }
    }
  }

  DEBUG((EFI_D_INFO, 
    "====================================================\n"));  

  //
  // Get inserted performance data
  //
  LogEntryKey = 0;
  EntryIndex  = 0;
  while ((LogEntryKey = GetPerformanceMeasurement (
                          LogEntryKey,
                          &Handle,
                          &Token,
                          &Module,
                          &StartTicker,
                          &EndTicker)) != 0) {
    if (!PerfEntriesAsDxeHandle[EntryIndex] && EndTicker != 0) {

      ZeroMem (&mPerfData, sizeof (PERF_DATA));

      AsciiStrnCpy (mPerfData.Token, Token, PERF_TOKEN_LENGTH);
      if (StartTicker == 1) {
        StartTicker = StartValue;
      }
      if (EndTicker == 1) {
        EndTicker = StartValue;
      }
      Ticker = CountUp ? (EndTicker - StartTicker) : (StartTicker - EndTicker);

      mPerfData.Duration = (UINT32) DivU64x32 (Ticker, (UINT32) Freq);

      CopyMem (Ptr, &mPerfData, sizeof (PERF_DATA));
      Ptr += sizeof (PERF_DATA);
 
      PrintPerfStr(mPerfData.Token, mPerfData.Duration);

      mPerfHeader.Count++;
      if (mPerfHeader.Count == LimitCount) {
        goto Done;
      }
    }
    EntryIndex++;
  }

Done:

  FreePool (Handles);
  FreePool (PerfEntriesAsDxeHandle);

  mPerfHeader.Signiture = PERFORMANCE_SIGNATURE;

  //
  // Put performance data to Reserved memory
  //
  CopyMem (
    (UINTN *) (UINTN) mAcpiLowMemoryBase,
    &mPerfHeader,
    sizeof (PERF_HEADER)
    );
}



/**

  Service routine for BdsInstance->Entry(). Devices are connected, the
  consoles are initialized, and the boot options are tried.

  @param This             Protocol Instance structure.

**/
VOID
EFIAPI
BdsEntry (
  IN EFI_BDS_ARCH_PROTOCOL  *This
  )
{
  LIST_ENTRY                      DriverOptionList;
  LIST_ENTRY                      BootOptionList;
  UINTN                           BootNextSize;
  CHAR16                          *FirmwareVendor;
  EFI_STATUS                      Status;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  //
  // Insert the performance probe
  //
  PERF_END (NULL, "DXE", NULL, 0);
  PERF_START (NULL, "BDS", NULL, 0);

  Status = gBS->LocateProtocol (
        &gBdsHelperProtocolGuid,
        NULL,
        (VOID **)&gBdsHelperProtocol
        );
  if (EFI_ERROR(Status)) {
    gBdsHelperProtocol = NULL;
    DEBUG((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
  }

  if (gBdsHelperProtocol) {
    gBdsHelperProtocol->SetBdsImageHandle(
      gBdsHelperProtocol, 
      mBdsImageHandle);
  }

  //
  // Initialize the global system boot option and driver option
  //
  InitializeListHead (&DriverOptionList);
  InitializeListHead (&BootOptionList);

  //
  // Initialize hotkey service
  //
  //InitializeHotkeyService ();

  //
  // Fill in FirmwareVendor and FirmwareRevision from PCDs
  //
  FirmwareVendor = (CHAR16 *)PcdGetPtr (PcdFirmwareVendor);
  gST->FirmwareVendor = AllocateRuntimeCopyPool (StrSize (FirmwareVendor), FirmwareVendor);
  ASSERT (gST->FirmwareVendor != NULL);
  gST->FirmwareRevision = PcdGet32 (PcdFirmwareRevision);

  //
  // Fixup Tasble CRC after we updated Firmware Vendor and Revision
  //
  gBS->CalculateCrc32 ((VOID *)gST, sizeof(EFI_SYSTEM_TABLE), &gST->Hdr.CRC32);

  //
  // Do the platform init, can be customized by OEM/IBV
  //
  PERF_START (NULL, "PlatformBds", "BDS", 0);
  if (gBdsHelperProtocol) {
    gBdsHelperProtocol->PlatformBdsInit (gBdsHelperProtocol);
  }

  InitializeHwErrRecSupport();

  //
  // bugbug: platform specific code
  // Initialize the platform specific string and language
  //
  //InitializeStringSupport ();
  InitializeLanguage (TRUE);
  InitializeFrontPage (TRUE);

  //
  // Set up the device list based on EFI 1.1 variables
  // process Driver#### and Load the driver's in the
  // driver option list
  //
  BdsLibBuildOptionFromVar (&DriverOptionList, L"DriverOrder");
  if (!IsListEmpty (&DriverOptionList)) {
    BdsLibLoadDrivers (&DriverOptionList);
  }
  //
  // Check if we have the boot next option
  //
  mBootNext = BdsLibGetVariableAndSize (
                L"BootNext",
                &gEfiGlobalVariableGuid,
                &BootNextSize
                );

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  //
  // Setup some platform policy here
  //
  if (gBdsHelperProtocol) {
    gBdsHelperProtocol->PlatformBdsPolicyBehavior (
                            gBdsHelperProtocol, 
                            &DriverOptionList, 
                            &BootOptionList, 
                            BdsProcessCapsules, 
                            BdsMemoryTest);
  }
  PERF_END (NULL, "PlatformBds", "BDS", 0);

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  PERF_CODE (
    DEBUG((EFI_D_INFO, "%a.%d Perfomance\n", __FUNCTION__, __LINE__));
    ShowPerformanceData ();
  );

  MultibootLoaderInit (mBdsImageHandle, mSystemTable);

  //
  // BDS select the boot device to load OS
  //
  BdsBootDeviceSelect ();

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  //
  // Only assert here since this is the right behavior, we should never
  // return back to DxeCore.
  //
  ASSERT (FALSE);

  return ;
}
