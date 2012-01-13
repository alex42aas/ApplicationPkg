/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "Storage.h"
#include "PciDevsMonitor.h"

STATIC EFI_GUID PciDevsMonStorageGuid = STORAGE_GUID;

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


EFI_STATUS
PciDevsMonStorageSetRawData(
  IN UINT8 *RawData,
  IN UINTN RawDataLen
  )
{
  EFI_STATUS Status;
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DEBUG((EFI_D_ERROR, "%a.%d &PciDevsMonStorageGuid=%g\n", 
    __FUNCTION__, __LINE__, &PciDevsMonStorageGuid));  

  SetStorageAttributes(STORAGE_WRITE_ONLY_ATTR);
  Status = StorageSetRawData2(
    &PciDevsMonStorageGuid, 
    STORAGE_VARIABLE_NAME,
    (UINT8*)RawData,
    RawDataLen,
    (STORAGE_VARIABLE_MAX_STORAGE_SIZE + STORAGE_VARIABLE_MAX_CARD_SIZE) / 
          STORAGE_VARIABLE_MAX_CARD_SIZE,
    STORAGE_VARIABLE_MAX_STORAGE_SIZE,
    STORAGE_VARIABLE_MAX_CARD_SIZE,
    FALSE);

  DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", 
    __FUNCTION__, __LINE__, Status));
  return Status; 
}

EFI_STATUS
PciDevsMonSaveData(
  IN EFI_LIST_ENTRY *PciDevsList,
  IN UINT32 Mode
  )
{
  EFI_LIST_ENTRY *Entry;
  UINTN ItemsCount, Idx;
  PCI_DEVS_COMMON_DATA *Data;
  PCI_DEVS_MONITOR_LIST *List;
  PCI_DEVS_MONITOR_DATA *DevsMonData;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (PciDevsList == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  if (IsListEmpty(PciDevsList)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  /* Calculate items */
  ItemsCount = 0;
  Entry = PciDevsList->ForwardLink;
  while (Entry != PciDevsList) {
    ItemsCount++;
    Entry = Entry->ForwardLink;
  }

  Data = AllocateZeroPoolDbg(sizeof(PCI_DEVS_COMMON_DATA) - 1 + 
    sizeof(PCI_DEVS_MONITOR_DATA) * ItemsCount);
  if (Data == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  Data->Mode = Mode;
  Data->DataLen = (UINT32)(sizeof(PCI_DEVS_MONITOR_DATA) * ItemsCount);

  Idx = 0;
  DevsMonData = (PCI_DEVS_MONITOR_DATA*)Data->Data;
  Entry = PciDevsList->ForwardLink;
  while (Entry != PciDevsList) {
    List = (PCI_DEVS_MONITOR_LIST*)Entry;
    CopyMem(&DevsMonData[Idx], &List->Data, sizeof(PCI_DEVS_MONITOR_DATA));
    Idx++;
    Entry = Entry->ForwardLink;
  }
  
  return PciDevsMonStorageSetRawData((UINT8*)Data, 
    sizeof(PCI_DEVS_COMMON_DATA) - 1 + Data->DataLen);
}


EFI_STATUS
PciDevsMonStorageGetData(
  IN OUT EFI_LIST_ENTRY *PciDevsList,
  IN OUT UINT32 *Mode
  )
{
  STORAGE_DATA StorageData;
  PCI_DEVS_COMMON_DATA *PciDevsData;
  PCI_DEVS_MONITOR_LIST *List;
  UINTN Size;
  UINT8 *Ptr;
  EFI_STATUS Status = EFI_SUCCESS;
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DEBUG((EFI_D_ERROR, "%a.%d &PciDevsMonStorageGuid=%g\n", 
    __FUNCTION__, __LINE__, &PciDevsMonStorageGuid));

  PciDevsData = NULL;
  StorageData.Data = NULL;
  SetStorageAttributes(STORAGE_RDWR_ATTR);
  Status = StorageGetData2(&PciDevsMonStorageGuid, STORAGE_VARIABLE_NAME,
    &StorageData, STORAGE_VARIABLE_MAX_STORAGE_SIZE);
  
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Size = StorageData.DataLen;
  DEBUG((EFI_D_ERROR, "%a.%d Size=%d\n", __FUNCTION__, __LINE__, Size));

  if (Size < (sizeof(PCI_DEVS_COMMON_DATA) - 1)) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_NOT_FOUND\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  
  PciDevsData = (PCI_DEVS_COMMON_DATA *)StorageData.Data;
  if (PciDevsData == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d EFI_OUT_OF_RESOURCES\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DEBUG((EFI_D_ERROR, "Size=%d PciDevsData->DataLen=%d\n", 
    Size, PciDevsData->DataLen));
  
  if (PciDevsData->DataLen && 
      PciDevsData->DataLen != Size - sizeof(PCI_DEVS_COMMON_DATA) + 1) {
    Status = EFI_ABORTED;
    DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
    goto Done;
  }

  InitializeListHead(PciDevsList);

  *Mode = PciDevsData->Mode;
  Ptr = PciDevsData->Data;
  Size = PciDevsData->DataLen;
  
  while (Size >= sizeof(PCI_DEVS_MONITOR_DATA)) {    
    List = AllocateZeroPoolDbg(sizeof(PCI_DEVS_MONITOR_LIST));
    DEBUG((EFI_D_ERROR, "%a.%d List=%p\n", __FUNCTION__, __LINE__, List));
    if (List == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    CopyMem((UINT8*)&List->Data, Ptr, sizeof(PCI_DEVS_MONITOR_DATA));
   
    Ptr += sizeof(PCI_DEVS_MONITOR_DATA);
    Size -= sizeof(PCI_DEVS_MONITOR_DATA);
    
    InsertTailList (PciDevsList, &List->ListEntry);
    
    DEBUG((EFI_D_ERROR, "Added item: (%02X.%02X:%02X)\n", 
      List->Data.Bus,
      List->Data.Device,
      List->Data.Func));
  }
  
Done:
  if (PciDevsData != NULL) {
    FreePoolDbg(PciDevsData);
  }  

  return Status;
}


EFI_STATUS
PciDevsMonStorageInitEmpty (
  IN UINT32 Mode
  )
{
  EFI_STATUS Status;
  PCI_DEVS_COMMON_DATA PciDevsData;

  DEBUG((EFI_D_ERROR, "%a.%d: Start\n", __FUNCTION__, __LINE__));
  Status = StorageInitEmpty(STORAGE_VARIABLE_NAME, &PciDevsMonStorageGuid,
    NULL, 0, NULL, FALSE);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d: Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  PciDevsData.Mode = Mode;
  PciDevsData.Data[0] = 0;
  PciDevsData.DataLen = 0;
  
  SetStorageAttributes(STORAGE_RDWR_ATTR);
  Status = StorageSetRawData2(&PciDevsMonStorageGuid,
    STORAGE_VARIABLE_NAME, (UINT8*)&PciDevsData,
    sizeof(PCI_DEVS_COMMON_DATA),
    (STORAGE_VARIABLE_MAX_STORAGE_SIZE + STORAGE_VARIABLE_MAX_CARD_SIZE) / 
          STORAGE_VARIABLE_MAX_CARD_SIZE,
    STORAGE_VARIABLE_MAX_STORAGE_SIZE,
    STORAGE_VARIABLE_MAX_CARD_SIZE, 
    FALSE
    );

  return Status;
}


