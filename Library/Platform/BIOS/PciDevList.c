/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/Lib/PciDevList.h>


static EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
static EFI_HII_HANDLE CurrentHiiHandle;
static VOID *StartOpCodeHandle, *EndOpCodeHandle;
static UINT16 CurrentMode;
static UINT16 *ModesList;
static UINTN ModesAmount;


static BOOLEAN bFormExitFlag, bRefreshForm, bFormChanged;
static int CurrentEvent;

static EFI_LIST_ENTRY DevListHead;
static EFI_LIST_ENTRY DevCommonListHead;

static UINTN DevListItems;


EFI_STATUS
PciGetNextBusRange (
  IN OUT EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR  **Descriptors,
  OUT    UINT16                             *MinBus,
  OUT    UINT16                             *MaxBus,
  OUT    BOOLEAN                            *IsEnd
  )
{
  *IsEnd = FALSE;

  //
  // When *Descriptors is NULL, Configuration() is not implemented, so assume
  // range is 0~PCI_MAX_BUS
  //
  if ((*Descriptors) == NULL) {
    *MinBus = 0;
    *MaxBus = PCI_MAX_BUS;
    return EFI_SUCCESS;
  }
  //
  // *Descriptors points to one or more address space descriptors, which
  // ends with a end tagged descriptor. Examine each of the descriptors,
  // if a bus typed one is found and its bus range covers bus, this handle
  // is the handle we are looking for.
  //

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

BOOLEAN
PciDevEnabled(
  IN UINT32 Segment,
  IN UINT16 Bus,
  IN UINT16 Device,
  IN UINT16 Func
  )
{
  UINT8 *Data;
  UINTN Amount, i;
  DA_DEV_REC *Dev;
  EFI_STATUS Status;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = GetSetupPciDevListByIndex((UINTN)CurrentMode, &Data, &Amount);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status = 0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return FALSE;
  }

  DEBUG((EFI_D_ERROR, "%a.%d Amount=0x%X\n", 
    __FUNCTION__, __LINE__, Amount));
  
  if (Amount == 0) {
    return FALSE;
  }
  for (i = 0; i < Amount; i++) {
    Dev = (DA_DEV_REC*)Data;
    
    DEBUG((EFI_D_ERROR, "(%X:%X:%X)\n", 
      Dev->Bus, Dev->Dev, Dev->Func));

    if (Dev->Bus == Bus && Dev->Dev == Device && Dev->Func == Func) {
      return TRUE;
    }
    
    Data += sizeof(DA_DEV_REC);
  }
  return FALSE;
}

EFI_STATUS
PciAddListInfo(
  IN UINT32 Segment,
  IN UINT16 Bus,
  IN UINT16 Device,
  IN UINT16 Func,
  IN PCI_COMMON_HEADER *PciHeader
  )
{
  PCI_DEV_LIST *ListItem;
  PCI_DEV_COMMON_LIST *InfoItem;

  DEBUG((EFI_D_ERROR, "%a.%d ? (%X-%X:%X:%X)\n",
    __FUNCTION__, __LINE__, Segment, Bus, Device, Func));

  if (!PciDaAlloweed((UINT8)(Bus & 0xFF), (UINT8)(Device & 0xFF),
    (UINT8)(Func & 0xFF))) {
    DEBUG((EFI_D_ERROR, "%a.%d Device (%X:%X:%X) not allowed!\n", 
      __FUNCTION__, __LINE__, Bus, Device, Func));
    return EFI_SUCCESS;
  }
  
  InfoItem = (PCI_DEV_COMMON_LIST*)AllocateZeroPool(
    sizeof(PCI_DEV_COMMON_LIST));
  ListItem = (PCI_DEV_LIST*)AllocateZeroPool(sizeof(PCI_DEV_LIST));
  if (ListItem == NULL || InfoItem == NULL) {
    if (ListItem) {
      FreePool(ListItem);
    }
    if (InfoItem) {
      FreePool(InfoItem);
    }
    return EFI_OUT_OF_RESOURCES;
  }
  ListItem->Seg = Segment;
  ListItem->Bus = Bus;
  ListItem->Device = Device;
  ListItem->Func = Func;

  if (PciDevEnabled(Segment, Bus, Device, Func)) {
    ListItem->Flags |= PCI_DEV_EN_FLAG;
  }
  
  InsertTailList(&DevListHead, &ListItem->DevList);

  InfoItem->DeviceId = PciHeader->DeviceId;
  InfoItem->VendorId = PciHeader->VendorId;
  InfoItem->RevisionId = PciHeader->RevisionId;
  CopyMem(InfoItem->ClassCode, PciHeader->ClassCode, 
    sizeof(PciHeader->ClassCode));
  InsertTailList(&DevCommonListHead, &InfoItem->ListEntry);

  DevListItems++;

  return EFI_SUCCESS;
}


EFI_STATUS
PciProcessingBusDevFunc(
  IN EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *IoDev,
  IN UINT16 MinBus,
  IN UINT16 MaxBus
  )
{
  UINT16 Bus;
  UINT16 Device;
  UINT16 Func;
  UINT64 Address;
  PCI_COMMON_HEADER PciHeader;
  EFI_STATUS Status;
//  PCI_CONFIG_SPACE ConfigSpace;
  
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

        Status = PciAddListInfo(IoDev->SegmentNumber, Bus, Device, Func, 
          &PciHeader);
        if (EFI_ERROR(Status)) {
          DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
            __FUNCTION__, __LINE__, Status));
          return Status;
        }

        PciPrintClassCode(PciHeader.ClassCode);
      }
    }
  }
  return EFI_SUCCESS;
}


EFI_STATUS
PciProcessingHandles(
  EFI_HANDLE *HandleBuf,
  UINTN HandleCount
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
      Status = PciProcessingBusDevFunc(IoDev, MinBus, MaxBus);
      if (EFI_ERROR (Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error Status=0x%X\n",
          __FUNCTION__, __LINE__, Status));
        return Status;
      }
    }
  }

  return EFI_SUCCESS;
}


EFI_ACPI_HANDLE
FindDMARTable(
  VOID
  )
{
  EFI_STATUS Status;
  EFI_ACPI_SDT_PROTOCOL *SdtProtocol;
  EFI_ACPI_SDT_HEADER *Table;
  EFI_ACPI_TABLE_VERSION Version;
  UINTN TableKey;
  UINTN Index;
  EFI_ACPI_HANDLE TableHandle;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  Status = gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, &SdtProtocol);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return NULL;
  }
  
  Index = 0;

  do {
    Status = SdtProtocol->GetAcpiTable(Index, &Table, &Version, &TableKey);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
        __FUNCTION__, __LINE__, Status));
      break;
    }
    Index++;
    DEBUG((EFI_D_ERROR, "GetAcpiTable:%c%c%c%c %p\n", 
      ((Table->Signature) & 0xFF),
      ((Table->Signature >> 8) & 0xFF),
      ((Table->Signature >> 16) & 0xFF),
      ((Table->Signature >> 24) & 0xFF),
      Table));
    
    if(Table->Signature != SIGNATURE_32('D','M','A','R')) {
      continue;      
    } else {
      break;
    }
  } while (1);
  
  Status = SdtProtocol->OpenSdt(TableKey, &TableHandle);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return NULL;
  }
  
  return TableHandle;
}

PCI_DEV_LIST*
FindDevByNum(
  IN UINTN Num
  )
{
  EFI_LIST_ENTRY *Entry;
  PCI_DEV_LIST *DevList;
  UINTN Index = 0;
  
  Entry = DevListHead.ForwardLink;
  while (Entry != &DevListHead) {
    DevList = (PCI_DEV_LIST*)Entry;
    DEBUG((EFI_D_ERROR, "(%X:%X:%X)\n", 
      DevList->Bus, DevList->Device, DevList->Func));
    if (Index == Num) {
      return DevList;
    }
    Index++;
    Entry = Entry->ForwardLink;
  }
  return NULL;
}


static UINTN
CountPciDevChecked(
  VOID
  )
{
  EFI_LIST_ENTRY *Entry;
  PCI_DEV_LIST *DevList;
  UINTN Count;

  Count = 0;
  Entry = DevListHead.ForwardLink;
  while (Entry != &DevListHead) {
    DevList = (PCI_DEV_LIST*)Entry;
    DEBUG((EFI_D_ERROR, "(%X:%X:%X) Flags=0x%X\n", 
      DevList->Bus, DevList->Device, DevList->Func, DevList->Flags));

    if (DevList->Flags & PCI_DEV_EN_FLAG) {
      Count++;
    }
    
    Entry = Entry->ForwardLink;
  }
  return Count;
}

VOID
PciDevListDestroy(
  VOID
  )
{
  EFI_LIST_ENTRY *Entry, *TmpEntry;
  PCI_DEV_LIST *DevList;
  PCI_DEV_COMMON_LIST *InfoList;
  
  Entry = DevListHead.ForwardLink;
  while (Entry != &DevListHead) {
    DevList = (PCI_DEV_LIST*)Entry;
    DEBUG((EFI_D_ERROR, "(%X:%X:%X)\n", 
      DevList->Bus, DevList->Device, DevList->Func));
    TmpEntry = Entry->ForwardLink;
    RemoveEntryList(Entry);
    FreePool(Entry);
    Entry = TmpEntry;
  }

  Entry = DevCommonListHead.ForwardLink;
  while (Entry != &DevCommonListHead) {
    InfoList = (PCI_DEV_COMMON_LIST*)Entry;
    DEBUG((EFI_D_ERROR, "(%X_%X_%X)\n", 
      InfoList->ClassCode[0], InfoList->ClassCode[1], InfoList->ClassCode[2]));
    PciPrintClassCode(InfoList->ClassCode);
    TmpEntry = Entry->ForwardLink;
    RemoveEntryList(Entry);
    FreePool(Entry);
    Entry = TmpEntry;
  }
  
  DevListItems = 0;
}


EFI_LIST_ENTRY *
GetPciDevList(
  VOID
  )
{
  return &DevListHead;
}


EFI_STATUS
PciDevListInit(
  VOID
  )
{
  EFI_STATUS Status;
  EFI_HANDLE *HandleBuf;
  UINTN HandleBufSize, HandleCount;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (DevListItems) {
    PciDevListDestroy();
  }

  InitializeListHead(&DevListHead);
  InitializeListHead(&DevCommonListHead);
  
  HandleBufSize = sizeof (EFI_HANDLE);
  HandleBuf     = (EFI_HANDLE *) AllocateZeroPool (HandleBufSize);
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
  
  Status = PciProcessingHandles(HandleBuf, HandleCount);
  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

VOID
PciDevListTest(
  VOID
  )
{
  EFI_STATUS Status;
  EFI_HANDLE *HandleBuf;
  UINTN HandleBufSize, HandleCount;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (DevListItems) {
    PciDevListDestroy();
  }

  InitializeListHead(&DevListHead);
  InitializeListHead(&DevCommonListHead);
  
  HandleBufSize = sizeof (EFI_HANDLE);
  HandleBuf     = (EFI_HANDLE *) AllocateZeroPool (HandleBufSize);
  if (HandleBuf == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return;
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
      return;
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
    return;
  }

  HandleCount = HandleBufSize / sizeof (EFI_HANDLE);
  DEBUG((EFI_D_ERROR, "%a.%d HandleCount=%d\n", 
    __FUNCTION__, __LINE__, HandleCount));
  
  PciProcessingHandles(HandleBuf, HandleCount);
  PciDevListDestroy();
}

static VOID
DestroyHiiResources(
  VOID
  )
{
  if (StartOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (StartOpCodeHandle);
    StartOpCodeHandle = NULL;
  }
  if (EndOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (EndOpCodeHandle);
    EndOpCodeHandle = NULL;
  }
}

static VOID
UpdateFrameTitle(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  CHAR16 *HiiStr1, HiiStr2[] = L")";
  static BOOLEAN bUpdated;
  
  if (bUpdated) {
    return;
  }
  bUpdated = TRUE;
  
  HiiStr1 = HiiGetString(HiiHandle, STR_FW_VERSION, NULL);
  HiiStr1[0] = L'(';
  VfrFwVersionString(HiiHandle, HiiStr1, 
    STRING_TOKEN(STR_PCI_DEV_LIST_MODE_PAGE_TITLE), HiiStr2);
}

static EFI_STATUS
AllocateHiiResources(
  VOID
  )
{
  EFI_IFR_GUID_LABEL *StartLabel;
  EFI_IFR_GUID_LABEL *EndLabel;
  EFI_GUID FormSetGuid = FORMSET_PCI_DEV_LIST_MODE_GUID;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_FORM_ID FormId = PCI_DEV_LIST_MODE_PAGE_ID;
  
  DestroyHiiResources();
  
  StartOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (StartOpCodeHandle == NULL) {
    goto _exit;
  }

  EndOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (EndOpCodeHandle == NULL) {
    goto _exit;
  }

  StartLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      StartOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  StartLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  StartLabel->Number       = LABEL_PCI_DEV_LIST_MODE_PAGE_LIST_START;

  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      EndOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_PCI_DEV_LIST_MODE_PAGE_LIST_END;
  
  Status = EFI_SUCCESS;
  
  HiiUpdateForm(CurrentHiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  
_exit:  
  return Status;
}


EFI_STATUS
PciDevListCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  if (ActionRequest == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (EFI_BROWSER_ACTION_FORM_CLOSE == Action) {    
    bFormExitFlag = TRUE;
    return EFI_SUCCESS;
  }
  if (EFI_BROWSER_ACTION_FORM_OPEN == Action) {
    return EFI_SUCCESS;
  }
  if (Action != EFI_BROWSER_ACTION_CHANGING) {
    return EFI_SUCCESS;
  }

  if (CurrentMode == 0 && ModesAmount && ModesList != NULL) {
    if (QuestionId == PCI_DEV_LIST_LOAD_DEFAULTS_ID) {
      EFI_STATUS Status;
      SETUP_VAR_PROTOCOL *pSetupProto;
  
      DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
      Status = gBS->LocateProtocol (
        &gSetupVarProtocolGuid,
        NULL,
        (VOID **)&pSetupProto
        );
      DEBUG ((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
        __FUNCTION__, __LINE__, Status));
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        return Status;
      }
      
      Status = pSetupProto->SetDefaultPciDaDevices(pSetupProto);
      DEBUG ((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
        __FUNCTION__, __LINE__, Status));
      if (EFI_ERROR(Status)) {
        ShowErrorPopup(CurrentHiiHandle, HiiGetString(
          CurrentHiiHandle, STRING_TOKEN(STR_LOAD_DEFAULTS_ERROR), NULL));
      }      
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    } else if ((UINTN)(QuestionId - PCI_DEV_LIST_START_QID) < ModesAmount) {
      CurrentMode = ModesList[QuestionId - PCI_DEV_LIST_START_QID];
      DEBUG((EFI_D_ERROR, "%a.%d CurrentMode=0x%X\n", 
        __FUNCTION__, __LINE__, CurrentMode));
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    }
  } else if (QuestionId >= PCI_DEV_LIST_START_QID) {    
    PCI_DEV_LIST *DevList; 

    bFormChanged = TRUE;
    
    DevList = FindDevByNum(QuestionId - PCI_DEV_LIST_START_QID);
    if (DevList == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    } else {
      DevList->Flags ^= PCI_DEV_EN_FLAG;
    }
  } else {
    DEBUG((EFI_D_ERROR, "%a.%d: QuestionId=0x%x\n", 
      __FUNCTION__, __LINE__, QuestionId));  
  }

  return EFI_SUCCESS;
}

EFI_STATUS
SavePciDevCheckedItems(
  VOID
  )
{
  UINT8 *Data, *TmpPtr;
  UINTN Amount;
  EFI_LIST_ENTRY *Entry;
  PCI_DEV_LIST *DevList;
  DA_DEV_REC *DaDev;
  EFI_STATUS Status;

  DEBUG((EFI_D_ERROR, "\n%a.%d\n", __FUNCTION__, __LINE__));

  Data = NULL;
  Amount = CountPciDevChecked();
  if (Amount == 0) {
    goto _exit;
  }

  Data = AllocateZeroPool(Amount * sizeof(DA_DEV_REC));
  if (Data == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  Entry = DevListHead.ForwardLink;
  TmpPtr = Data;
  while (Entry != &DevListHead) {
    DevList = (PCI_DEV_LIST*)Entry;    

    if (DevList->Flags & PCI_DEV_EN_FLAG) {
      DEBUG((EFI_D_ERROR, "(%X:%X:%X) Flags=0x%X\n", 
        DevList->Bus, DevList->Device, DevList->Func, DevList->Flags));
      DaDev = (DA_DEV_REC*)TmpPtr;
      DaDev->Bus = (UINT8)(DevList->Bus & 0xFF);
      DaDev->Dev = (UINT8)(DevList->Device & 0xFF);
      DaDev->Func = (UINT8)(DevList->Func & 0xFF);
      TmpPtr += sizeof(DA_DEV_REC);
    }
        
    Entry = Entry->ForwardLink;
  }

_exit:
  Status = SetSetupPciDevList((UINTN)CurrentMode, Data, Amount);
  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
    __FUNCTION__, __LINE__, Status));
  return Status;
}

EFI_STATUS
DoModeSelectForm(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  EFI_GUID FormSetGuid = FORMSET_PCI_DEV_LIST_MODE_GUID;
  EFI_FORM_ID FormId = PCI_DEV_LIST_MODE_PAGE_ID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID HelpToken;
  EFI_QUESTION_ID QuestionId;
  CHAR16 *StrPtr16;
  UINTN i;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  CurrentMode = 0;
  
  if (EFI_SUCCESS != AllocateHiiResources()) {
    return EFI_OUT_OF_RESOURCES;
  }

  if (ModesList) {
    FreePool(ModesList);
    ModesList = NULL;
  }
  ModesAmount = 0;
  Status = GetSetupPciDevListIndexes(&ModesList, &ModesAmount);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  if (ModesList == NULL || ModesAmount == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
      __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  QuestionId = PCI_DEV_LIST_START_QID;
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

  HiiCreateActionOpCode(StartOpCodeHandle, PCI_DEV_LIST_LOAD_DEFAULTS_ID,
      STRING_TOKEN(STR_LOAD_DEFAULTS), HelpToken, EFI_IFR_FLAG_CALLBACK, 0);     
  
  DEBUG((EFI_D_ERROR, "%a.%d ModesAmount=%d\n", 
    __FUNCTION__, __LINE__, ModesAmount));
  for (i = 0; i < ModesAmount; i++) {
    DEBUG((EFI_D_ERROR, "%a.%d Modes[i]=0x%X\n", 
      __FUNCTION__, __LINE__, ModesList[i]));
    
    StrPtr16 = GetEntryNameByIndex((UINTN)ModesList[i]);
    DEBUG((EFI_D_ERROR, "%a.%d StrPtr16=%s\n", 
      __FUNCTION__, __LINE__, StrPtr16));
    
    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId++,
      HiiSetString (HiiHandle, 0, StrPtr16, NULL), HelpToken, 
      EFI_IFR_FLAG_CALLBACK, 0);    
  }
  
  HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
    
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
    (VOID **) &gFormBrowser2);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
  Status = EFI_SUCCESS;

  do {
    Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1,
      &FormSetGuid, FormId, NULL, &ActionRequest);
          
    if (bFormExitFlag) {
      Status = EFI_SUCCESS;
      break;
    }
  } while (CurrentMode == 0);

  if (ModesList) {
    FreePool(ModesList);
    ModesList = NULL;
  }
  
  return EFI_SUCCESS;
}

BOOLEAN
PciDevPresent(
  IN UINT16 DeviceId,
  IN UINT16 VendorId
  )  
{
  EFI_LIST_ENTRY *Entry, *InfoEntry;
  PCI_DEV_LIST *DevList;
  PCI_DEV_COMMON_LIST *InfoList;
  
  PciDevListInit();

  Entry = DevListHead.ForwardLink;
  InfoEntry = DevCommonListHead.ForwardLink;

  while (Entry != &DevListHead) {
      DevList = (PCI_DEV_LIST*)Entry;
      InfoList = (PCI_DEV_COMMON_LIST*)InfoEntry;      
      if (InfoList->DeviceId == DeviceId &&
          InfoList->VendorId == VendorId) {
        return TRUE;
      }
      Entry = Entry->ForwardLink;
      InfoEntry = InfoEntry->ForwardLink;
  }
  return FALSE;
}


EFI_STATUS
PciDevListPageStart(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  EFI_GUID FormSetGuid = FORMSET_PCI_DEV_LIST_MODE_GUID;
  EFI_FORM_ID FormId = PCI_DEV_LIST_MODE_PAGE_ID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID HelpToken;//, RMP_mode1_str, RMP_mode2_str;
  EFI_QUESTION_ID QuestionId;
  CHAR16 TmpStr16[255], *StrPtr16;
  EFI_LIST_ENTRY *Entry, *InfoEntry;
  PCI_DEV_LIST *DevList;
  PCI_DEV_COMMON_LIST *InfoList;
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  

  CurrentHiiHandle = HiiHandle;
  bRefreshForm = FALSE;
  
  do {  
    bFormChanged = FALSE;
    CurrentMode = 0;
    
    Status = DoModeSelectForm(HiiHandle);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
    }

    if (CurrentMode == 0) {
      break;
    }
    
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    
    PciDevListInit();

    UpdateFrameTitle(HiiHandle);

    if (EFI_SUCCESS != AllocateHiiResources()) {
      return EFI_OUT_OF_RESOURCES;
    }
    
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

    QuestionId = PCI_DEV_LIST_START_QID;

    HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

    Entry = DevListHead.ForwardLink;
    InfoEntry = DevCommonListHead.ForwardLink;
    
    while (Entry != &DevListHead) {
      DevList = (PCI_DEV_LIST*)Entry;
      InfoList = (PCI_DEV_COMMON_LIST*)InfoEntry;
      DEBUG((EFI_D_ERROR, "(%X:%X:%X) Flags=0x%X\n", 
        DevList->Bus, DevList->Device, DevList->Func,
        DevList->Flags));
      
      Entry = Entry->ForwardLink;
      InfoEntry = InfoEntry->ForwardLink;

      StrPtr16 = PciPrintClassCode(InfoList->ClassCode);
      if (NULL == StrPtr16) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        return EFI_ABORTED;
      }
      UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"(%X:%X:%X)", 
        DevList->Bus, DevList->Device, DevList->Func);
      HelpToken = HiiSetString (HiiHandle, 0, StrPtr16, NULL);
      if (NULL == HiiCreateCheckBoxOpCode (StartOpCodeHandle, QuestionId++,
          0, 0, HiiSetString (HiiHandle, 0, TmpStr16, NULL),
          HelpToken, EFI_IFR_FLAG_CALLBACK,
          DevList->Flags & PCI_DEV_EN_FLAG ? EFI_IFR_CHECKBOX_DEFAULT : 0, 
          NULL)) {
        return EFI_OUT_OF_RESOURCES;
      }      
    }

    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
    
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    
    Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
      (VOID **) &gFormBrowser2);
    if (EFI_ERROR (Status)) {
      goto _exit;
    }

    ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
    Status = EFI_SUCCESS;

    do {
      Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1,
        &FormSetGuid, FormId, NULL, &ActionRequest);
            
      if (bFormExitFlag) {
        Status = EFI_SUCCESS;
        break;
      }
    } while (1);

  _exit:

    if (bFormChanged) {
      Status = AreYouSureWarning(CurrentHiiHandle, 
        STRING_TOKEN(STR_SAVE_AND_REBOOT), 
        STRING_TOKEN(STR_YOUR_CHOISE));
      if (Status == EFI_SUCCESS) {
        Status = SavePciDevCheckedItems();
        if (EFI_ERROR(Status)) {
          MsgInternalError(INT_ERR_DA_DEVICES_SAVE);
        }
        HistoryAddRecord(HEVENT_RESET_SYSTEM, GetCurrentUserId(), 
          SEVERITY_LVL_DEBUG, HISTORY_RECORD_FLAG_RESULT_OK);
        gRT->ResetSystem(EfiResetCold, Status, 0, NULL);
      }
    }
    DestroyHiiResources();
    if (EFI_ERROR(Status)) {
      continue;
    } 
  } while (bRefreshForm);

    
  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


