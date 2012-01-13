/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "../../Loader/Bds/Bds.h"
#include "PciDefs.h"
#include "PciDevsMonitor.h"
#include <Protocol/HistoryHandlerProto.h>
#include <Library/Lib/History.h>
#include <Library/Base64.h>
#include "Storage.h"
#include <Library/CommonUtils.h>
#include <Library/PciDevsMonitorLib.h>

STATIC	HISTORY_HANDLER_PROTOCOL	*gHistoryHandlerProtocol;

extern UINT8 PciDevsMonitorVfrBin[];
extern UINT8 PciDevsMonitorLibStrings[];

STATIC MULTIBOOT_CONFIG *CurrentConfig;

STATIC EFI_GUID mPciDevsMonitorGuid = PCI_DEVS_MONITOR_FORMSET_GUID;
STATIC EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
STATIC VOID *StartOpCodeHandle, *EndOpCodeHandle;
/* list of pci devices under monitoring */
STATIC EFI_LIST_ENTRY DevsMonitorListHead;
STATIC UINTN DevsMonitorListItems;
/* list of all pci devices */
STATIC EFI_LIST_ENTRY PciDevsListHead;
STATIC UINTN PciDevsListItems;
STATIC UINT32 CurrentMode;
STATIC BOOLEAN bFormRedraw = FALSE;

STATIC PCI_DEVS_MONITOR_CALLBACK_DATA gPciDevsMonitorPrivate;

STATIC HII_VENDOR_DEVICE_PATH mPciDevsHiiVendorDevicePath = {
  {
    {
      HARDWARE_DEVICE_PATH,
      HW_VENDOR_DP,
      {
        (UINT8) (sizeof (VENDOR_DEVICE_PATH)),
        (UINT8) ((sizeof (VENDOR_DEVICE_PATH)) >> 8)
      }
    },
    //
    // {62FD30FA-BF88-48f1-82DE-9C402E4B3B11}
    //
    { 0x62fd30fa, 0xbf88, 0x48f1, { 0x82, 0xde, 0x9c, 0x40, 0x2e, 0x4b, 0x3b, 0x11 } }
    
  },
  {
    END_DEVICE_PATH_TYPE,
    END_ENTIRE_DEVICE_PATH_SUBTYPE,
    { 
      (UINT8) (END_DEVICE_PATH_LENGTH),
      (UINT8) ((END_DEVICE_PATH_LENGTH) >> 8)
    }
  }
};

STATIC
VOID*
AllocateZeroPoolDbg(
  IN UINTN Size
  )
{
  VOID *Ptr = AllocateZeroPool(Size);
  DEBUG((EFI_D_ERROR, "%a.%d Ptr=%lp (%d)\n", 
    __FUNCTION__, __LINE__, Ptr, Size));
  return Ptr;
}

STATIC
VOID
FreePoolDbg(
  IN VOID *Ptr
  )
{
  DEBUG((EFI_D_ERROR, "%a.%d Ptr=%lp\n", 
    __FUNCTION__, __LINE__, Ptr));
  FreePool(Ptr);
}

STATIC
VOID
PrintListHead(
  IN EFI_LIST_ENTRY *ListHead
  )
{
  DEBUG((EFI_D_ERROR, "%a.%d ListHead->ForwardLink=%p ListHead->BackLink=%p\n", 
    __FUNCTION__, __LINE__, ListHead->ForwardLink, ListHead->BackLink));
}


/**
  This function allows a caller to extract the current configuration for one
  or more named elements from the target driver.
**/
STATIC
EFI_STATUS
EFIAPI
ExtractConfig (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  CONST EFI_STRING                       Request,
  OUT EFI_STRING                             *Progress,
  OUT EFI_STRING                             *Results
  )
{
  if (Progress == NULL || Results == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Progress = Request;
  return EFI_NOT_FOUND;
}

/**
  This function processes the results of changes in configuration.
**/
EFI_STATUS
EFIAPI
RouteConfig (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  CONST EFI_STRING                       Configuration,
  OUT EFI_STRING                             *Progress
  )
{
  if (Configuration == NULL || Progress == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
}


STATIC
EFI_STATUS
PciGetNextBusRange (
  IN OUT EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR  **Descriptors,
  OUT    UINT16                             *MinBus,
  OUT    UINT16                             *MaxBus,
  OUT    BOOLEAN                            *IsEnd
  )
{
  *IsEnd = FALSE;

  if ((*Descriptors) == NULL) {
    *MinBus = 0;
    *MaxBus = PCI_MAX_BUS;
    return EFI_SUCCESS;
  }
  
  while ((*Descriptors)->Desc != ACPI_END_TAG_DESCRIPTOR) {
    if ((*Descriptors)->ResType == ACPI_ADDRESS_SPACE_TYPE_BUS) {
      *MinBus = (UINT16) (*Descriptors)->AddrRangeMin;
      *MaxBus = (UINT16) (*Descriptors)->AddrRangeMax;
      (*Descriptors)++;
      return (EFI_SUCCESS);
    }

    (*Descriptors)++;
  }

  if ((*Descriptors)->Desc == ACPI_END_TAG_DESCRIPTOR) {
    *IsEnd = TRUE;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
PciGetProtocolAndResource (
  IN  EFI_HANDLE                            Handle,
  OUT EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL       **IoDev,
  OUT EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR     **Descriptors
  )
{
  EFI_STATUS  Status;

  //
  // Get inferface from protocol
  //
  Status = gBS->HandleProtocol (
                Handle,
                &gEfiPciRootBridgeIoProtocolGuid,
                (VOID**)IoDev
               );

  if (EFI_ERROR (Status)) {
    return Status;
  }
  //
  // Call Configuration() to get address space descriptors
  //
  Status = (*IoDev)->Configuration (*IoDev, (VOID**)Descriptors);
  if (Status == EFI_UNSUPPORTED) {
    *Descriptors = NULL;
    return EFI_SUCCESS;

  }

  return Status;
}

STATIC
UINT16 *
PciPrintClassCode (
  IN UINT8 *ClassCodePtr
  )
{
  UINT32 ClassCode;
  UINT8 Code;
  PCI_CLASS_STRINGS ClassStrings;
  PCI_CLASS_ENTRY *ClassList = NULL;
  UINTN Index;
  static UINT16 Str16[255];
  static UINT16 StrUnknown[] = L"Unknown";

  ClassList = GetClassStringListDefs();

  ClassCode = 0;
  ClassCode |= ClassCodePtr[0];
  ClassCode |= (ClassCodePtr[1] << 8);
  ClassCode |= (ClassCodePtr[2] << 16);

  Code = (UINT8)(ClassCode >> 16);

  ClassStrings.BaseClass = StrUnknown;
  ClassStrings.PIFClass = StrUnknown;
  ClassStrings.SubClass = StrUnknown;

  Index = 0;
  while (Code != ClassList[Index].Code) {
    if (NULL == ClassList[Index].DescText) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Code=0x%X not found\n",
        __FUNCTION__, __LINE__, Code));      
      goto _exit;
    }

    Index++;
  }
  ClassStrings.BaseClass = ClassList[Index].DescText;

  if (NULL == ClassList[Index].LowerLevelClass) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! No lower level class!\n",
        __FUNCTION__, __LINE__));
    goto _exit;
  }
  //
  // find Subclass entry
  //
  ClassList = ClassList[Index].LowerLevelClass;
  Code = (UINT8) (ClassCode >> 8);
  Index = 0;
  while (Code != ClassList[Index].Code) {
    if (NULL == ClassList[Index].DescText) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Code=0x%X not found\n",
        __FUNCTION__, __LINE__, Code));
      goto _exit;
    }

    Index++;
  }
  ClassStrings.SubClass = ClassList[Index].DescText;

  if (NULL == ClassList[Index].LowerLevelClass) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! No lower level class!\n",
        __FUNCTION__, __LINE__));
    goto _exit;
  }
  //
  // Find programming interface entry
  //
  ClassList  = ClassList[Index].LowerLevelClass;
  Code = (UINT8) ClassCode;
  Index = 0;
  while (Code != ClassList[Index].Code) {
    if (NULL == ClassList[Index].DescText) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Code=0x%X not found\n",
        __FUNCTION__, __LINE__, Code));
      goto _exit;
    }

    Index++;
  }
  ClassStrings.PIFClass = ClassList[Index].DescText;
  
_exit:

  UnicodeSPrint(Str16, sizeof(Str16), L"%s %s %s",
    ClassStrings.BaseClass, ClassStrings.SubClass, ClassStrings.PIFClass);

  DEBUG((EFI_D_ERROR, "%s - %s - %s\n",
    ClassStrings.BaseClass,
    ClassStrings.SubClass,
    ClassStrings.PIFClass));
  
  return Str16;
}


STATIC
BOOLEAN
CheckDeviceFilter (
  IN UINT32 Segment,
  IN UINT16 Bus,
  IN UINT16 Device,
  IN UINT16 Func
  )
{
  if (Bus == 0) {
    return TRUE; 
  }
  return FALSE;
}


STATIC
EFI_STATUS
PciDevsMonitorAddItem(
  IN UINT32 Segment,
  IN UINT16 Bus,
  IN UINT16 Device,
  IN UINT16 Func,
  IN PCI_COMMON_HEADER *PciHeader,
  IN OUT EFI_LIST_ENTRY *ListHead
  )
{
  PCI_DEVS_MONITOR_LIST *ListItem;

  DEBUG((EFI_D_ERROR, "%a.%d (%X-%X:%X:%X)\n",
    __FUNCTION__, __LINE__, Segment, Bus, Device, Func));

  if (CheckDeviceFilter(Segment, Bus, Device, Func)) {
    return EFI_SUCCESS;
  }
  
  ListItem = (PCI_DEVS_MONITOR_LIST*)AllocateZeroPoolDbg(sizeof(PCI_DEVS_MONITOR_LIST));
  if (ListItem == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  ListItem->Data.Seg = Segment;
  ListItem->Data.Bus = Bus;
  ListItem->Data.Device = Device;
  ListItem->Data.Func = Func;
  ListItem->Data.DeviceId = PciHeader->DeviceId;
  ListItem->Data.VendorId = PciHeader->VendorId;
  ListItem->Data.RevisionId = PciHeader->RevisionId;
  CopyMem(ListItem->Data.ClassCode, PciHeader->ClassCode, 
    sizeof(PciHeader->ClassCode));

  
  InsertTailList(ListHead, &ListItem->ListEntry);

  return EFI_SUCCESS;
}


STATIC
EFI_STATUS
PciProcessingBusDevFunc(
  IN EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *IoDev,
  IN UINT16 MinBus,
  IN UINT16 MaxBus,
  IN OUT EFI_LIST_ENTRY *ListHead
  )
{
  UINT16 Bus;
  UINT16 Device;
  UINT16 Func;
  UINT64 Address;
  PCI_COMMON_HEADER PciHeader;
  
  for (Bus = MinBus; Bus <= MaxBus; Bus++) {
    //
    // For each devices, enumerate all functions it contains
    //
    for (Device = 0; Device <= PCI_MAX_DEVICE; Device++) {
      //
      // For each function, read its configuration space and print summary
      //
      for (Func = 0; Func <= PCI_MAX_FUNC; Func++) {
        
        Address = CALC_EFI_PCI_ADDRESS (Bus, Device, Func, 0);
        IoDev->Pci.Read (
                    IoDev,
                    EfiPciWidthUint16,
                    Address,
                    1,
                    &PciHeader.VendorId
                   );
  
        //
        // If VendorId = 0xffff, there does not exist a device at this
        // location. For each device, if there is any function on it,
        // there must be 1 function at Function 0. So if Func = 0, there
        // will be no more functions in the same device, so we can break
        // loop to deal with the next device.
        //
        if (PciHeader.VendorId == 0xffff && Func == 0) {
          break;
        }
  
        if (PciHeader.VendorId == 0xffff) {
          continue;
        }
  
        IoDev->Pci.Read (
                    IoDev,
                    EfiPciWidthUint32,
                    Address,
                    sizeof (PciHeader) / sizeof (UINT32),
                    &PciHeader
                   );

        DEBUG((EFI_D_ERROR, "(%X:%X:%X:%X)\n",
          IoDev->SegmentNumber, Bus, Device, Func));

        PciDevsMonitorAddItem(IoDev->SegmentNumber, Bus, 
          Device, Func, &PciHeader, ListHead);

        PciPrintClassCode(PciHeader.ClassCode);

        //
        // If this is not a multi-function device, we can leave the loop
        // to deal with the next device.
        //
        if (Func == 0 && ((PciHeader.HeaderType & HEADER_TYPE_MULTI_FUNCTION) == 0x00)) {
          break;
        }
      }
    }
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
PciProcessingHandles(
  IN EFI_HANDLE *HandleBuf,
  IN UINTN HandleCount,
  IN OUT EFI_LIST_ENTRY *ListHead
  )
{
  EFI_STATUS Status;
  UINTN Index;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *IoDev;
  EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR *Descriptors;
  BOOLEAN IsEnd;
  UINT16 MinBus;
  UINT16 MaxBus;

  for (Index = 0; Index < HandleCount; Index++) {
    Status = PciGetProtocolAndResource (
              HandleBuf[Index],
              &IoDev,
              &Descriptors
             );
    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error Status=0x%X\n",
        __FUNCTION__, __LINE__, Status));
    }
    while (TRUE) {
      Status = PciGetNextBusRange (&Descriptors, &MinBus, &MaxBus, &IsEnd);

      if (EFI_ERROR (Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error Status=0x%X\n",
          __FUNCTION__, __LINE__, Status));
        return Status;
      }

      if (IsEnd) {
        break;
      }
      Status = PciProcessingBusDevFunc(IoDev, MinBus, MaxBus, ListHead);
      if (EFI_ERROR (Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error Status=0x%X\n",
          __FUNCTION__, __LINE__, Status));
        return Status;
      }
    }
  }

  return EFI_SUCCESS;
}

STATIC
PCI_DEVS_MONITOR_LIST *
FindDevByNum(
  IN UINTN Num,
  IN EFI_LIST_ENTRY *ListHead
  )
{
  EFI_LIST_ENTRY *Entry;
  PCI_DEVS_MONITOR_LIST *DevList;
  UINTN Index = 0;

  if (ListHead == NULL) {
    return NULL;
  }
  if (IsListEmpty(ListHead)) {
    return NULL;
  }
  
  Entry = ListHead->ForwardLink;
  while (Entry != ListHead) {
    DevList = (PCI_DEVS_MONITOR_LIST*)Entry;
    DEBUG((EFI_D_ERROR, "(%X:%X:%X)\n", 
      DevList->Data.Bus, DevList->Data.Device, DevList->Data.Func));
    if (Index == Num) {
      return DevList;
    }
    Index++;
    Entry = Entry->ForwardLink;
  }
  return NULL;
}

/*
 * This function ignore flags difference
 */
STATIC
PCI_DEVS_MONITOR_LIST*
FindDevByEntry(
  IN EFI_LIST_ENTRY *FindEntry,
  IN EFI_LIST_ENTRY *ListHead
  )
{
  EFI_LIST_ENTRY *Entry;
  PCI_DEVS_MONITOR_LIST *DevList;
  PCI_DEVS_MONITOR_LIST *Dev;
  UINT16 Flags1, Flags2;
  INTN Res;

  if (FindEntry == NULL || ListHead == NULL) {
    return NULL;
  }
  if (IsListEmpty(ListHead)) {
    return NULL;
  }

  Dev = (PCI_DEVS_MONITOR_LIST*)FindEntry;
  Entry = ListHead->ForwardLink;
  
  while (Entry != ListHead) {
    DevList = (PCI_DEVS_MONITOR_LIST*)Entry;
    DEBUG((EFI_D_ERROR, "(%X:%X:%X)\n", 
      DevList->Data.Bus, DevList->Data.Device, DevList->Data.Func));
    DEBUG((EFI_D_ERROR, "(%X:%X:%X)\n", 
      Dev->Data.Bus, Dev->Data.Device, Dev->Data.Func));

    Flags1 = DevList->Data.Flags;
    DevList->Data.Flags = 0;
    Flags2 = Dev->Data.Flags;
    Dev->Data.Flags = 0;

    Res = CompareMem(&DevList->Data, &Dev->Data, sizeof(PCI_DEVS_MONITOR_DATA));

    DevList->Data.Flags = Flags1;
    Dev->Data.Flags = Flags2;
    
    if (Res == 0) {
      return DevList;
    }
    Entry = Entry->ForwardLink;
  }
  return NULL;
}


STATIC 
UINTN
CountPciDevChecked(
  IN EFI_LIST_ENTRY *ListHead
  )
{
  EFI_LIST_ENTRY *Entry;
  PCI_DEVS_MONITOR_LIST *DevList;
  UINTN Count;

  Count = 0;
  Entry = ListHead->ForwardLink;
  while (Entry != ListHead) {
    DevList = (PCI_DEVS_MONITOR_LIST*)Entry;
    DEBUG((EFI_D_ERROR, "(%X:%X:%X) Flags=0x%X\n", 
      DevList->Data.Bus, DevList->Data.Device, 
      DevList->Data.Func, DevList->Data.Flags));

    if (DevList->Data.Flags & PCI_DEV_MONITORED_FLAG) {
      Count++;
    }
    
    Entry = Entry->ForwardLink;
  }
  return Count;
}

VOID
FreePciDevList(
  IN EFI_LIST_ENTRY *ListHead
  )
{
  EFI_LIST_ENTRY *Entry, *TmpEntry;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (IsListEmpty(ListHead)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return;
  }

  Entry = ListHead->ForwardLink;
  while (Entry != ListHead) {
    TmpEntry = Entry->ForwardLink;
    RemoveEntryList(Entry);
    FreePoolDbg(Entry);
    Entry = TmpEntry;
  }
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  InitializeListHead(ListHead);
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
}

EFI_STATUS
SetPciDevList(
  IN OUT EFI_LIST_ENTRY *ListHead
  )
{
  EFI_STATUS Status;
  EFI_HANDLE *HandleBuf;
  UINTN HandleBufSize, HandleCount;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  if (ListHead->BackLink == NULL && ListHead->ForwardLink == NULL) {
    InitializeListHead(ListHead);
  } else {
    FreePciDevList(ListHead);
  }

  HandleBufSize = sizeof (EFI_HANDLE);
  HandleBuf     = (EFI_HANDLE *) AllocateZeroPoolDbg (HandleBufSize);
  if (HandleBuf == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  Status = gBS->LocateHandle (
                ByProtocol,
                &gEfiPciRootBridgeIoProtocolGuid,
                NULL,
                &HandleBufSize,
                HandleBuf
               );
  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  if (Status == EFI_BUFFER_TOO_SMALL) {
    HandleBuf = ReallocatePool (sizeof (EFI_HANDLE), HandleBufSize, HandleBuf);
    if (HandleBuf == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_OUT_OF_RESOURCES;
    }

    Status = gBS->LocateHandle (
                  ByProtocol,
                  &gEfiPciRootBridgeIoProtocolGuid,
                  NULL,
                  &HandleBufSize,
                  HandleBuf
                 );
  }
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }
    
  HandleCount = HandleBufSize / sizeof (EFI_HANDLE);
  DEBUG((EFI_D_ERROR, "%a.%d HandleCount=%d\n", 
    __FUNCTION__, __LINE__, HandleCount));
  
  Status = PciProcessingHandles(HandleBuf, HandleCount, ListHead);
  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

EFI_STATUS
CopyListItems (
  IN EFI_LIST_ENTRY *InList,
  IN OUT EFI_LIST_ENTRY *OutList
  )
{
  EFI_LIST_ENTRY *Entry, *CopyEntry;
  PCI_DEVS_MONITOR_LIST *Dev;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  if (InList == NULL || OutList == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (IsListEmpty(InList)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  FreePciDevList(OutList);
  InitializeListHead(OutList);
  Entry = InList->ForwardLink;
  
  while (Entry != InList) {
    Dev = (PCI_DEVS_MONITOR_LIST*)Entry;

    DEBUG((EFI_D_ERROR, "%a.%d Insert item\n", __FUNCTION__, __LINE__));
    CopyEntry = AllocateCopyPool(sizeof(PCI_DEVS_MONITOR_LIST), Entry);
    InsertTailList(OutList, CopyEntry);

    Entry = Entry->ForwardLink;
  }
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_SUCCESS;
}

EFI_STATUS
ObtainListOfCheckedItems (
  IN EFI_LIST_ENTRY *InList,
  IN OUT EFI_LIST_ENTRY *OutList
  )
{
  EFI_LIST_ENTRY *Entry, *CopyEntry;
  PCI_DEVS_MONITOR_LIST *Dev;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  if (InList == NULL || OutList == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (IsListEmpty(InList)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  FreePciDevList(OutList);
  InitializeListHead(OutList);
  Entry = InList->ForwardLink;
  
  while (Entry != InList) {
    Dev = (PCI_DEVS_MONITOR_LIST*)Entry;
    if (Dev->Data.Flags & PCI_DEV_MONITORED_FLAG) {
      DEBUG((EFI_D_ERROR, "%a.%d Insert item\n", __FUNCTION__, __LINE__));
      CopyEntry = AllocateCopyPool(sizeof(PCI_DEVS_MONITOR_LIST), Entry);
      InsertTailList(OutList, CopyEntry);      
    }
    
    Entry = Entry->ForwardLink;
  }
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return EFI_SUCCESS;
}

STATIC
VOID
SetAllPciDevsAsMonitored (
  IN EFI_LIST_ENTRY *AllDevicesList,
  IN BOOLEAN bMonitored
  )
{
  EFI_LIST_ENTRY *EntryMonitored;
  PCI_DEVS_MONITOR_LIST *Dev;

  EntryMonitored = AllDevicesList->ForwardLink;
  while (EntryMonitored != AllDevicesList) {
    Dev = (PCI_DEVS_MONITOR_LIST*)EntryMonitored;
    if (bMonitored) {
      Dev->Data.Flags |= PCI_DEV_MONITORED_FLAG;
    } else {
      Dev->Data.Flags = 0;
    }
    EntryMonitored = EntryMonitored->ForwardLink;
  }
}

VOID
DevsMonitorSetCurrentConfig(
  IN MULTIBOOT_CONFIG *Cfg
  )
{
  CurrentConfig = Cfg;
}


STATIC
EFI_STATUS
Callback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  EFI_STATUS Status;
  
  if (ActionRequest == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (EFI_BROWSER_ACTION_FORM_CLOSE == Action) {    
    return EFI_SUCCESS;
  }
  if (EFI_BROWSER_ACTION_FORM_OPEN == Action) {
    return EFI_SUCCESS;
  }
  if (Action != EFI_BROWSER_ACTION_CHANGING) {
    return EFI_SUCCESS;
  }

  return EFI_SUCCESS;
}


EFI_STATUS
InitializePciDevsMonitor (
  VOID
  )
{
  EFI_STATUS Status;
  STATIC BOOLEAN bAllReadyInit = FALSE;

  
  DEBUG((EFI_D_ERROR, "%a.%d %d\n", __FUNCTION__, __LINE__, bAllReadyInit ? 1 : 0));
  
  
  
  if (bAllReadyInit) {
    return EFI_SUCCESS;
  }
  bAllReadyInit = TRUE;

  Status = gBS->LocateProtocol (
              &gHistoryHandlerProtocolGuid, 
              NULL, 
              (VOID **) &gHistoryHandlerProtocol
              );
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d - gHistoryHandlerProtocolGuid!\n", __FUNCTION__, __LINE__));
  }

  InitializeListHead (&DevsMonitorListHead);
  InitializeListHead (&PciDevsListHead);

  gPciDevsMonitorPrivate.ConfigAccess.Callback = Callback;
  gPciDevsMonitorPrivate.ConfigAccess.ExtractConfig = ExtractConfig;
  gPciDevsMonitorPrivate.ConfigAccess.RouteConfig = RouteConfig;

  //
  // Install Device Path Protocol and Config Access protocol to driver handle
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &gPciDevsMonitorPrivate.DriverHandle,
                  &gEfiDevicePathProtocolGuid,
                  &mPciDevsHiiVendorDevicePath,
                  &gEfiHiiConfigAccessProtocolGuid,
                  &gPciDevsMonitorPrivate.ConfigAccess,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  //
  // Publish our HII data
  //  
  gPciDevsMonitorPrivate.HiiHandle = HiiAddPackages (
                                    &mPciDevsMonitorGuid,
                                    gPciDevsMonitorPrivate.DriverHandle,
                                    PciDevsMonitorVfrBin,
                                    PciDevsMonitorLibStrings,
                                    NULL
                                    );
  if (gPciDevsMonitorPrivate.HiiHandle == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
  } else {
    Status = EFI_SUCCESS;
  }
  return Status;
}


EFI_STATUS
CreateMenu2(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN VOID *EndOpCodeHandle,
  IN EFI_LIST_ENTRY *ListHead
  )
{
  EFI_LIST_ENTRY *Entry;
  CHAR16 TmpStr16[255];
  CHAR16 TmpStr16_2[255];
  CHAR16 *StrPtr16;
  PCI_DEVS_MONITOR_LIST *DevsList;
  EFI_STRING_ID HelpToken;
  EFI_QUESTION_ID QuestionId;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (NULL == HiiCreateCheckBoxOpCode (StartOpCodeHandle, PCI_DEVS_CTRL_ID,
      0, 0, STRING_TOKEN(STR_CHANGES_CTRL),
      STRING_TOKEN(STR_CHANGES_CTRL_HLP), EFI_IFR_FLAG_CALLBACK,
      CurrentMode ==  MODE_CHECKIN_CTRL_ON ? 
        EFI_IFR_CHECKBOX_DEFAULT : 0, 
      NULL)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  if (NULL == HiiCreateActionOpCode(
                StartOpCodeHandle, 
                PCI_DEVS_MONITOR_ITEMS_SAVE_ALL_ID,
                STRING_TOKEN(STR_SAVE_CONF),
                STRING_TOKEN(STR_LAST_STRING), 
                EFI_IFR_FLAG_CALLBACK, 
                0)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  QuestionId = PCI_DEVS_MONITOR_ITEMS_START_ID;
  
  Entry = ListHead->ForwardLink;
  
  while (Entry != ListHead) {
    DevsList = (PCI_DEVS_MONITOR_LIST*)Entry;
    
    DEBUG((EFI_D_ERROR, "(%X:%X:%X) Flags=0x%X\n", 
      DevsList->Data.Bus, 
      DevsList->Data.Device, 
      DevsList->Data.Func,
      DevsList->Data.Flags));
    
    Entry = Entry->ForwardLink;

    StrPtr16 = PciPrintClassCode(DevsList->Data.ClassCode);
    if (NULL == StrPtr16) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_ABORTED;
    }

    UnicodeSPrint(TmpStr16_2, sizeof(TmpStr16_2), 
      L"%s\nVendor ID=%04X\nDevice ID=%04X\n%s", 
      StrPtr16,       
      DevsList->Data.VendorId,
      DevsList->Data.DeviceId,
      DevsList->Data.Flags & PCI_DEV_MON_ERR_FLAG ? 
        HiiGetString(HiiHandle,
          STRING_TOKEN(STR_PCI_DEV_ABSENCE_ERR),
          NULL) :
        HiiGetString(HiiHandle,
          STRING_TOKEN(STR_LAST_STRING),
          NULL)
      );

    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"%s   (%X:%X:%X)", 
      DevsList->Data.Flags & PCI_DEV_MONITORED_FLAG ? L"[X]" : L"[ ]",
      DevsList->Data.Bus, 
      DevsList->Data.Device, 
      DevsList->Data.Func
      );

    HelpToken = HiiSetString (HiiHandle, 0, TmpStr16_2, NULL);

  if (NULL == HiiCreateActionOpCode(
                StartOpCodeHandle, 
                QuestionId++,
                HiiSetString (HiiHandle, 0, TmpStr16, NULL),
                HelpToken, 
                EFI_IFR_FLAG_CALLBACK, 
                0)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  }

  return EFI_SUCCESS;
}

EFI_STATUS
PciDevsMonitorCheckConfiguration (
  VOID
  )
{
  EFI_STATUS Status = EFI_SUCCESS;

  EFI_LIST_ENTRY *Entry;
  UINT32 Mode;
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  FreePciDevList(&DevsMonitorListHead);
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  FreePciDevList(&PciDevsListHead);

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = SetPciDevList(&PciDevsListHead);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _Done;
  }
  

  Status = PciDevsMonStorageGetData(&DevsMonitorListHead, &Mode);
  if (EFI_ERROR(Status)) {
    if (Status == EFI_NOT_FOUND) {
      Status = EFI_SUCCESS;
      goto _Done;
    } else {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      Status = EFI_ABORTED;
      goto _Done;
    }
  }

  if (Mode == (UINT32)MODE_CHECKIN_CTRL_OFF) {
    FreePciDevList(&DevsMonitorListHead);
    PciDevsMonStorageInitEmpty (MODE_CHECKIN_CTRL_OFF);
    Status = EFI_SUCCESS;
    goto _Done;
  }

  if (IsListEmpty(&DevsMonitorListHead) && IsListEmpty(&PciDevsListHead)) {
    /* list for monitoring is empty */
    DEBUG((EFI_D_ERROR, "%a.%d Monitoring list is empty!\n", __FUNCTION__, __LINE__));
    Status = EFI_SUCCESS;
    goto _Done;
  }

  Entry = DevsMonitorListHead.ForwardLink;
  
  while (Entry != &DevsMonitorListHead) {
    if (NULL == FindDevByEntry(Entry, &PciDevsListHead)) {
      Status = EFI_ABORTED;
      goto _Done;
    }
    Entry = Entry->ForwardLink;
  }

  Entry = PciDevsListHead.ForwardLink;
  
  while (Entry != &PciDevsListHead) {
    if (NULL == FindDevByEntry(Entry, &DevsMonitorListHead)) {
      Status = EFI_ABORTED;
      goto _Done;
    }
    Entry = Entry->ForwardLink;
  }

_Done:  

  if (EFI_ERROR(Status)) {
    if (gHistoryHandlerProtocol) {
      gHistoryHandlerProtocol->AddRecord (
              gHistoryHandlerProtocol,
              HEVENT_PCI_DEVS_MONITOR_FAIL, 
              SEVERITY_LVL_ERROR,
              0);
    }
  }
  return Status;
}


VOID
MergePciDevsLists (
  IN EFI_LIST_ENTRY *AllDevicesList,
  IN EFI_LIST_ENTRY *MonitoredDevicesList
  )
{
  EFI_LIST_ENTRY *CopyEntry;
  EFI_LIST_ENTRY *EntryMonitored;
  PCI_DEVS_MONITOR_LIST *Dev, *Dev2;

  EntryMonitored = MonitoredDevicesList->ForwardLink;
  while (EntryMonitored != MonitoredDevicesList) {
    Dev = FindDevByEntry(EntryMonitored, AllDevicesList);
    if (Dev == NULL) {
      CopyEntry = AllocateCopyPool(sizeof(PCI_DEVS_MONITOR_LIST), 
        EntryMonitored);
      Dev = (PCI_DEVS_MONITOR_LIST*)CopyEntry;
      Dev->Data.Flags |= PCI_DEV_MON_ERR_FLAG;
      InsertHeadList(AllDevicesList, CopyEntry);
    } else {
      Dev2 = (PCI_DEVS_MONITOR_LIST *)EntryMonitored;
      Dev->Data.Flags = Dev2->Data.Flags;
    }
    EntryMonitored = EntryMonitored->ForwardLink;
  }
}

STATIC
EFI_STATUS
AskForInitStorage (
  IN EFI_HII_HANDLE HiiHandle
  )
{
  EFI_INPUT_KEY Key;
  EFI_STATUS Status = EFI_ABORTED;
  
  do {
    CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_RED, &Key, 
      HiiGetString(HiiHandle, STRING_TOKEN(STR_LOAD_CONF_ERR), NULL), 
      HiiGetString(HiiHandle, 
        STRING_TOKEN(STR_ASK_FOR_INIT_STORAGE_EMPTY), NULL),
      NULL);
    if (Key.UnicodeChar == 'Y' || Key.UnicodeChar == 'y') {
      Status = EFI_SUCCESS;
      break;
    }
    if (Key.UnicodeChar == 'N' || Key.UnicodeChar == 'n') {
      Status = EFI_ABORTED;
      break;
    }
  } while (1);

  gST->ConOut->ClearScreen(gST->ConOut);
  return Status;
}

VOID
RunPciDevsMonitor (
  VOID
  )
{
  EFI_STATUS                  Status;
  EFI_HII_HANDLE              HiiHandle;
  EFI_BROWSER_ACTION_REQUEST  ActionRequest;
  VOID                        *StartOpCodeHandle = NULL;
  VOID                        *EndOpCodeHandle = NULL;
  EFI_IFR_GUID_LABEL          *StartLabel;
  EFI_IFR_GUID_LABEL          *EndLabel;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  HiiHandle = gPciDevsMonitorPrivate.HiiHandle;
  
  gST->ConOut->ClearScreen(gST->ConOut);

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  InitializeListHead (&DevsMonitorListHead);
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  InitializeListHead (&PciDevsListHead);

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = SetPciDevList(&PciDevsListHead);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    ShowErrorPopup(HiiHandle, 
        HiiGetString(HiiHandle,
          STRING_TOKEN(STR_PCI_LIST_ERR), 
          NULL));
    return;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = PciDevsMonitorCheckConfiguration();
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
    ShowErrorPopup(HiiHandle, 
      HiiGetString(HiiHandle, 
        STRING_TOKEN(STR_PCI_DEVS_MONITOR_ERR), NULL));
  }

DrawMenu:
  MergePciDevsLists(&PciDevsListHead, &DevsMonitorListHead);
  
  bFormRedraw = FALSE;

  //
  // Allocate space for creation of UpdateData Buffer
  //
  StartOpCodeHandle = HiiAllocateOpCodeHandle ();
  ASSERT (StartOpCodeHandle != NULL);

  EndOpCodeHandle = HiiAllocateOpCodeHandle ();
  ASSERT (EndOpCodeHandle != NULL);

  //
  // Create Hii Extend Label OpCode as the start opcode
  //
  StartLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
                                          StartOpCodeHandle, 
                                          &gEfiIfrTianoGuid, 
                                          NULL, 
                                          sizeof (EFI_IFR_GUID_LABEL));
  StartLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  StartLabel->Number       = LABEL_DEVICES_MONITOR_OPTION;

  //
  // Create Hii Extend Label OpCode as the end opcode
  //
  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
                                          EndOpCodeHandle, 
                                          &gEfiIfrTianoGuid, 
                                          NULL, 
                                          sizeof (EFI_IFR_GUID_LABEL));
  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_DEVICES_MONITOR_OPTION_END;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  PrintListHead(&DevsMonitorListHead);

  CreateMenu2(HiiHandle, StartOpCodeHandle, EndOpCodeHandle, &PciDevsListHead);
  
  HiiUpdateForm (
    HiiHandle,
    &mPciDevsMonitorGuid,
    PCI_DEVS_MONITOR_FORM_ID,
    StartOpCodeHandle,
    EndOpCodeHandle
    );


  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  if (StartOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (StartOpCodeHandle);
    StartOpCodeHandle = NULL;
  }
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (EndOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (EndOpCodeHandle);
    EndOpCodeHandle = NULL;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
    (VOID **) &gFormBrowser2);
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto Done;
  }

  ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
  Status = gFormBrowser2->SendForm (
                           gFormBrowser2,
                           &HiiHandle,
                           1,
                           &mPciDevsMonitorGuid,
                           0,
                           NULL,
                           &ActionRequest
                           );
  if (bFormRedraw) {
    goto DrawMenu;
  }
  
Done:
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  FreePciDevList(&DevsMonitorListHead);
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  FreePciDevList(&PciDevsListHead);

  DEBUG((EFI_D_ERROR, "%a()--\n", __FUNCTION__));
}

EFI_STATUS
EFIAPI
PciDevsMonitorLibConstructor (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  return InitializePciDevsMonitor();
}
