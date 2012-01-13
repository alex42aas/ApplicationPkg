/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/MacAddressController.h>
#include "DrmControlWindows.h"

#if 1
  #define LOG(ARG)   DEBUG(ARG)
#else 
  #define LOG(ARG)   // just stub
#endif

// A51BB7D5-9622-4863-996F-7423E256E77A
STATIC EFI_GUID DrmControlWindowsGuid = { 0xA51BB7D5, 0x9622, 0x4863, 
    { 0x99, 0x6F, 0x74, 0x23, 0xE2, 0x56, 0xE7, 0x7A } };

//=================================================================================================
//                                PRIVATE FUNCTIONS
//=================================================================================================

/*
  @retval   EFI_SUCCESS           -   read success
  @retval   EFI_NOT_FOUND         -   network device not found (VID and DID is 0xFFFF)
*/
EFI_STATUS
ReadMacAddressFromEthCtrl (
  IN UINT32 PciBaseAddress,
  OUT UINT8 *MacAddress
  )
{
  UINT32 MmioBaseAddress;
  UINT32 MacRegHigh, MacRegLow;
  UINT16 VidReg, DidReg;
  UINT32 VidDidValue, DevClass;
  EFI_STATUS Status;

  LOG ((EFI_D_INFO, "%a.%d Entry.\n", __FUNCTION__, __LINE__));

  MmioBaseAddress = (UINTN) (PciRead32(PCI_LIB_ADDRESS (0, 0, 0, 0x60)) & 0xFC000000) + PciBaseAddress;
  LOG ((EFI_D_INFO, "%a.%d MmioBaseAddress = 0x%08x.\n", __FUNCTION__, __LINE__, MmioBaseAddress));
  VidReg = MmioRead16(MmioBaseAddress);
  DidReg = MmioRead16(MmioBaseAddress + 2);
  
  DevClass = MmioRead32(MmioBaseAddress + 8);

  // cut ProgIF
  if ((DevClass & 0xFFFF0000) != NETWORK_ETH_CTRL_CODE) {
    return EFI_NOT_FOUND;
  }
  
  LOG ((EFI_D_INFO, "%a.%d VID = 0x%04x; DID = 0x%04x.\n", __FUNCTION__, __LINE__, VidReg, DidReg));
  
  Status = EFI_SUCCESS;
  VidDidValue = (VidReg << 16) | DidReg;
  switch (VidDidValue) {
    case I210_VID_DID_VALUE:
      MacRegLow = MmioRead32(MmioBaseAddress + I210_MAC_REG_LOW_OFFSET);
      MacRegHigh = MmioRead32(MmioBaseAddress + I210_MAC_REG_HIGH_OFFSET);
      MacAddress[0] = (UINT8) (MacRegHigh >> 24);
      MacAddress[1] = (UINT8) (MacRegHigh >> 16);
      MacAddress[2] = (UINT8) (MacRegHigh >> 8);
      MacAddress[3] = (UINT8) (MacRegLow >> 16);
      MacAddress[4] = (UINT8) (MacRegLow >> 8);
      MacAddress[5] = (UINT8) MacRegLow;
      break;
      
    case I350_VID_DID_VALUE:
{
UINTN	LanMmio;		// регистры контроллера, доступные через адресное пространство памяти
UINTN	LanId;			// номер порта внутри контроллера
UINT32	LanBase;		// смещение внутри EEPROM, соответствующее MAC-адресу для каждого порта
UINTN	tmp16;

	LanMmio = MmioRead32(MmioBaseAddress + I350_MBAR_OFFSET);
	LanId = MmioRead32(LanMmio + I350_DEV_STATUS_OFFSET);
	LanId >>= 2;
	LanId &= 0x3;
	switch(LanId){
	case 0:
		LanBase = I350_LAN_BASE_OFFSET;
		break;
	case 1:
		LanBase = I350_LAN_BASE_OFFSET + 0x80;
		break;
	case 2:
		LanBase = I350_LAN_BASE_OFFSET + 0xc0;
		break;
	case 3:
	default:
		LanBase = I350_LAN_BASE_OFFSET + 0x100;
		break;
	}
	MmioWrite32(LanMmio + I350_EERD_OFFSET, ((LanBase + 0) << 2) | 1);
	while(1)
	{
	  tmp16 = MmioRead32(LanMmio + I350_EERD_OFFSET);
	  if(tmp16 & 2)
			break;
	}
        MacAddress[0] = (UINT8) (tmp16 >> 16);
        MacAddress[1] = (UINT8) (tmp16 >> 24);

	MmioWrite32(LanMmio + I350_EERD_OFFSET, ((LanBase + 1) << 2) | 1);
	while(1)
	{
	  tmp16 = MmioRead32(LanMmio + I350_EERD_OFFSET);
	  if(tmp16 & 2)
			break;
	}
       MacAddress[2] = (UINT8) (tmp16 >> 16);
        MacAddress[3] = (UINT8) (tmp16 >> 24);

	MmioWrite32(LanMmio + I350_EERD_OFFSET, ((LanBase + 2) << 2) | 1);
	while(1)
	{
	  tmp16 = MmioRead32(LanMmio + I350_EERD_OFFSET);
	  if(tmp16 & 2)
			break;
	}
        MacAddress[4] = (UINT8) (tmp16 >> 16);
        MacAddress[5] = (UINT8) (tmp16 >> 24);
}
      break;
      
    case RTL8111_VID_DID_VALUE:
      MmioBaseAddress = MmioRead32(MmioBaseAddress + RTL8111_MBARC_REG_OFFSET) & 0xFFFFF000;
      MacRegLow = MmioRead32(MmioBaseAddress + RTL8111_MAC_REG_LOW_OFFSET);
      MacRegHigh = MmioRead32(MmioBaseAddress + RTL8111_MAC_REG_HIGH_OFFSET);
      CopyMem(&MacAddress[0], &MacRegLow, 4);
      CopyMem(&MacAddress[4], &MacRegHigh, 2);
      break;
      
    case INT_GBE_VID_DID_VALUE:
    case INT_GBE_VID_DID_VALUE2:
      MmioBaseAddress = MmioRead32(MmioBaseAddress + INT_GBE_MBARA_REG_OFFSET) & 0xFFFE0000;
      MacRegLow = MmioRead32(MmioBaseAddress + INT_GBE_MAC_REG_LOW_OFFSET);
      MacRegHigh = MmioRead32(MmioBaseAddress + INT_GBE_MAC_REG_HIGH_OFFSET);
      CopyMem(&MacAddress[0], &MacRegLow, 4);
      CopyMem(&MacAddress[4], &MacRegHigh, 2);
      break;
    
    default:
      Status = EFI_NOT_FOUND;
      break;
  }

  if (Status == EFI_SUCCESS) {
    LOG ((EFI_D_INFO, "%a.%d MAC address %02x:%02x:%02x:%02x:%02x:%02x\n", __FUNCTION__, __LINE__,
        MacAddress[0], MacAddress[1], MacAddress[2], MacAddress[3], MacAddress[4], MacAddress[5]));
  }
  LOG ((EFI_D_INFO, "%a.%d Status = %0x\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


/*
  @retval   EFI_SUCCESS           -   DRM key is match
  @retval   EFI_ACCESS_DENIED     -   DRM key is NOT match
  @retval   EFI_ABORTED           -   error of GenerateDrmKey
*/
EFI_STATUS
CompareMacListWithDrm (
  IN EFI_GUID *SysGuid,
  IN EFI_LIST_ENTRY *MacListHead,
  IN CHAR8 *DrmKey
  )
{
  EFI_LIST_ENTRY *Mac1ListEntry, *Mac2ListEntry;
  UINT8 *MacAddress1, *MacAddress2;
  CHAR8 TempDrmKey[DRM_KEY_SIZE];
  EFI_STATUS Status;

  LOG ((EFI_D_INFO, "%a.%d Entry.\n", __FUNCTION__, __LINE__));
  
  if (IsNodeAtEnd(MacListHead, MacListHead->ForwardLink) == TRUE) {
    // list contain only one MAC address
    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    MacAddress1 = ((MAC_LIST_NODE*) MacListHead->ForwardLink)->MacAddressBuf;
    Mac1ListEntry = MacListHead;
    do {
      if (Mac1ListEntry == MacListHead) {
        Status = GenerateDrmKey(SysGuid, MacAddress1, NULL, TempDrmKey);
      } else {
        Status = GenerateDrmKey(SysGuid, NULL, MacAddress1, TempDrmKey);        
      }
      if (Status != EFI_SUCCESS) {
        LOG ((EFI_D_ERROR, "%a.%d Status = %0x.\n", __FUNCTION__, __LINE__, EFI_ABORTED));
        return EFI_ABORTED;
      }
      if (CompareMem(TempDrmKey, DrmKey, DRM_KEY_SIZE) == 0) {
        LOG ((EFI_D_ERROR, "%a.%d DRM key match is found.\n", __FUNCTION__, __LINE__));
        return EFI_SUCCESS;
      }
      Mac1ListEntry = Mac1ListEntry->ForwardLink;
    } while (Mac1ListEntry != MacListHead);
  } else {
    // check all possible combinations of MAC addresses from list (including various location in the pair)
    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    for (Mac1ListEntry = MacListHead->ForwardLink; Mac1ListEntry != MacListHead; 
        Mac1ListEntry = Mac1ListEntry->ForwardLink) 
    {
      MacAddress1 = ((MAC_LIST_NODE*) Mac1ListEntry)->MacAddressBuf;
      for (Mac2ListEntry = Mac1ListEntry->ForwardLink; Mac2ListEntry != Mac1ListEntry;
          Mac2ListEntry = Mac2ListEntry->ForwardLink)
      {
        if (Mac2ListEntry != MacListHead) {   // skip node of MacListHead, because it is empty terminator node
          MacAddress2 = ((MAC_LIST_NODE*) Mac2ListEntry)->MacAddressBuf;
          Status = GenerateDrmKey(SysGuid, MacAddress1, MacAddress2, TempDrmKey);
          if (Status != EFI_SUCCESS) {
            LOG ((EFI_D_ERROR, "%a.%d Status = %0x.\n", __FUNCTION__, __LINE__, EFI_ABORTED));
            return EFI_ABORTED;
          }
          if (CompareMem(TempDrmKey, DrmKey, DRM_KEY_SIZE) == 0) {
            LOG ((EFI_D_INFO, "%a.%d DRM key match is found.\n", __FUNCTION__, __LINE__));
            return EFI_SUCCESS;
          }
        }
      }
    }
  }

  LOG ((EFI_D_ERROR, "%a.%d Status = %0x\n", __FUNCTION__, __LINE__, EFI_ACCESS_DENIED));
  return EFI_ACCESS_DENIED;
}


/*
  DrmKeyFileLine format: 
    GGGGGGGG-GGGG-GGGG-GGGG-GGGGGGGGGGGG;M1:M1:M1:M1:M1:M1;M2:M2:M2:M2:M2:M2;DDDDDD-DDDDDD-DDDDDD-DDDDDD-DDDDDD

  @retval   EFI_SUCCESS   - parsing success
  @retval   EFI_ABORTED   - parsing fail
*/
EFI_STATUS
ParseDrmKeyFileLine (
  IN CHAR8 *DrmKeyFileLine,
  OUT DRM_KEY_FILE_RECORD *DrmKeyFileRecord
  )
{
  CHAR8 *SerialNumberStr, *MacAddress1Str, *MacAddress2Str, *DrmKeyStr;
  EFI_STATUS Status;

  LOG ((EFI_D_INFO, "%a.%d Entry.\n", __FUNCTION__, __LINE__));

  SerialNumberStr = strtok(DrmKeyFileLine, DRM_KEY_FILE_SEP_CHAR);
  MacAddress1Str = strtok(NULL, DRM_KEY_FILE_SEP_CHAR);
  MacAddress2Str = strtok(NULL, DRM_KEY_FILE_SEP_CHAR);
  DrmKeyStr = strtok(NULL, DRM_KEY_FILE_SEP_CHAR);
  
  // LOG ((EFI_D_ERROR, "%a.%d SerialNumberStr: '%a'\n", __FUNCTION__, __LINE__, SerialNumberStr));
  // LOG ((EFI_D_ERROR, "%a.%d MacAddress1Str: '%a'\n", __FUNCTION__, __LINE__, MacAddress1Str));
  // LOG ((EFI_D_ERROR, "%a.%d MacAddress2Str: '%a'\n", __FUNCTION__, __LINE__, MacAddress2Str));
  // LOG ((EFI_D_ERROR, "%a.%d DrmKeyStr: '%a'\n", __FUNCTION__, __LINE__, DrmKeyStr));
  
  if (((SerialNumberStr != NULL) && (strlen(SerialNumberStr) == SERIAL_NUMBER_STRING_LENGTH)) &&
      ((MacAddress1Str != NULL) && (strlen(MacAddress1Str) == MAC_STRING_LENGTH)) &&
      ((MacAddress2Str != NULL) && (strlen(MacAddress2Str) == MAC_STRING_LENGTH)) && 
      ((DrmKeyStr != NULL) && (strlen(DrmKeyStr) == DRM_KEY_SIZE)))
  {
    StringToGuid_L(SerialNumberStr, &DrmKeyFileRecord->SerialNumber);
    Status = MacStrToByteBuf(MacAddress1Str, DrmKeyFileRecord->MacAddress1);
    if (Status == EFI_SUCCESS) {
      Status = MacStrToByteBuf(MacAddress2Str, DrmKeyFileRecord->MacAddress2);
      if (Status == EFI_SUCCESS) {
        CopyMem(DrmKeyFileRecord->DrmKey, DrmKeyStr, DRM_KEY_SIZE);
        Status = EFI_SUCCESS;
      } else {
        ZeroMem(DrmKeyFileRecord, sizeof(DrmKeyFileRecord));
        Status = EFI_ABORTED;        
      }
    } else {
      ZeroMem(DrmKeyFileRecord, sizeof(DrmKeyFileRecord));
      Status = EFI_ABORTED;
    }
  } else {
    DEBUG ((EFI_D_ERROR, "%a.%d Parsing fail! Invalid line format: '%a'.\n", __FUNCTION__, __LINE__, DrmKeyFileLine));
    Status = EFI_ABORTED;
  }

  LOG ((EFI_D_INFO, "%a.%d Status = %0x\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


/*
  @retval   EFI_SUCCESS           -   DrmKeyFileRecord matches SerialNumber and MacAddresses
  @retval   EFI_NOT_FOUND         -   DrmKeyFileRecord NOT matches SerialNumber and MacAddresses
*/
EFI_STATUS
CheckDrmKeyFileRecord (
  IN DRM_KEY_FILE_RECORD *DrmKeyFileRecord,
  IN EFI_GUID *SerialNumber,
  IN EFI_LIST_ENTRY *MacListHead
  )
{
  EFI_LIST_ENTRY *Mac1ListEntry, *Mac2ListEntry;
  UINT8 *MacAddress1, *MacAddress2;

  // at first compare Serial Number
  if (CompareMem(&DrmKeyFileRecord->SerialNumber, SerialNumber, sizeof(SerialNumber)) == 0) {
    if (IsNodeAtEnd(MacListHead, MacListHead->ForwardLink) == TRUE) {
      // list contain only one MAC address
      MacAddress1 = ((MAC_LIST_NODE*) MacListHead->ForwardLink)->MacAddressBuf;
      if ((CompareMem(MacAddress1, DrmKeyFileRecord->MacAddress1, MAC_ADDRESS_SIZE) == 0) ||
          (CompareMem(MacAddress1, DrmKeyFileRecord->MacAddress2, MAC_ADDRESS_SIZE) == 0))
      {
        return EFI_SUCCESS;
      }
    } else {
      // and after check all possible combinations of MAC addresses from list (including various location in the pair)
      for (Mac1ListEntry = MacListHead->ForwardLink; Mac1ListEntry != MacListHead; 
          Mac1ListEntry = Mac1ListEntry->ForwardLink)
      {
        MacAddress1 = ((MAC_LIST_NODE*) Mac1ListEntry)->MacAddressBuf;
        if ((CompareMem(MacAddress1, DrmKeyFileRecord->MacAddress1, MAC_ADDRESS_SIZE) == 0) ||
            (CompareMem(MacAddress1, DrmKeyFileRecord->MacAddress2, MAC_ADDRESS_SIZE) == 0))
        {
          for (Mac2ListEntry = Mac1ListEntry->ForwardLink; Mac2ListEntry != Mac1ListEntry;
              Mac2ListEntry = Mac2ListEntry->ForwardLink)
          {
            if (Mac2ListEntry != MacListHead) {   // skip node of MacListHead, because it is empty terminator node
              MacAddress2 = ((MAC_LIST_NODE*) Mac2ListEntry)->MacAddressBuf;
              if ((CompareMem(MacAddress2, DrmKeyFileRecord->MacAddress1, MAC_ADDRESS_SIZE) == 0) ||
                  (CompareMem(MacAddress2, DrmKeyFileRecord->MacAddress2, MAC_ADDRESS_SIZE) == 0))
              {
                return EFI_SUCCESS;
              }
            }
          }
        }
      }
    }
  }

  return EFI_NOT_FOUND;
}


/*
  @retval   EFI_SUCCESS           -   DRM key is found
  @retval   EFI_NOT_FOUND         -   DRM key is NOT found
*/
EFI_STATUS
SearchDrmKeyOnUsbFile (
  IN CHAR16 *DrmKeyFilePath,
  IN EFI_GUID *SysGuid,
  IN EFI_LIST_ENTRY *MacListHead,
  OUT CHAR8 *DrmKey
  )
{
  EFI_FILE_HANDLE DrmKeyFile;
  UINTN DrmKeyFileSize;
  CHAR8 *DrmKeyFileData;
  CHAR8 DrmKeyFileLine[DRM_KEY_FILE_LINE_LENGTH];
  DRM_KEY_FILE_RECORD DrmKeyFileRecord;
  UINTN i;
  EFI_STATUS Status = EFI_NOT_FOUND;

  LOG ((EFI_D_INFO, "%a.%d Entry.\n", __FUNCTION__, __LINE__));

  ZeroMem(DrmKey, DRM_KEY_SIZE);

  DrmKeyFile = LibFsOpenFile16(DrmKeyFilePath, EFI_FILE_MODE_READ, 0);
  if (DrmKeyFile != NULL) {
    DEBUG ((EFI_D_INFO, "%a.%d DrmKeyFile is found.\n", __FUNCTION__, __LINE__));
    DrmKeyFileSize = LibFsSizeFile(DrmKeyFile);
    if (DrmKeyFileSize != 0) {
      // read all file data to buffer, because FsUtilsLib doesn't has ReadLine functions
      DrmKeyFileData = AllocateZeroPool(DrmKeyFileSize+1);
      LibFsReadFile(DrmKeyFile, &DrmKeyFileSize, DrmKeyFileData);
      DrmKeyFileData[DrmKeyFileSize] = '\0';
      // transform each file line to DrmKeyFileRecord format and check for a match with SerialNumber and MacList
      strncpy(DrmKeyFileLine, DrmKeyFileData, DRM_KEY_FILE_LINE_LENGTH);
      for (i = 1; ((DrmKeyFileLine != NULL) && (strlen(DrmKeyFileLine) == DRM_KEY_FILE_LINE_LENGTH)); i++) {
        LOG ((EFI_D_INFO, "%a.%d [%03d]: '%a'\n", __FUNCTION__, __LINE__, i, DrmKeyFileLine));
        Status = ParseDrmKeyFileLine(DrmKeyFileLine, &DrmKeyFileRecord);
        if (Status != EFI_SUCCESS) {
          DEBUG ((EFI_D_ERROR, "%a.%d Invalid file line, stop search.\n", __FUNCTION__, __LINE__));
          Status = EFI_NOT_FOUND;
          break;
        }
        Status = CheckDrmKeyFileRecord(&DrmKeyFileRecord, SysGuid, MacListHead);
        if (Status == EFI_SUCCESS) {
          LOG ((EFI_D_INFO, "%a.%d match MAC addresses.\n", __FUNCTION__, __LINE__));
          Status = CompareMacListWithDrm(SysGuid, MacListHead, DrmKeyFileRecord.DrmKey);
          if (Status == EFI_SUCCESS) {
            LOG ((EFI_D_INFO, "%a.%d user DRM key is confirmed.\n", __FUNCTION__, __LINE__));
            CopyMem(DrmKey, DrmKeyFileRecord.DrmKey, DRM_KEY_SIZE);
            break;
          }
        }
        strncpy(DrmKeyFileLine, DrmKeyFileData + (i * (DRM_KEY_FILE_LINE_LENGTH + 1)), DRM_KEY_FILE_LINE_LENGTH);
        Status = EFI_NOT_FOUND;   // relevant only if the last iteration of loop
      }
      FreePool(DrmKeyFileData);
    } else {
      DEBUG ((EFI_D_ERROR, "%a.%d DrmKeyFile empty.\n", __FUNCTION__, __LINE__));
      Status = EFI_NOT_FOUND;
    }
    LibFsCloseFile(DrmKeyFile);
  } else {
    DEBUG ((EFI_D_ERROR, "%a.%d DrmKeyFile is not found.\n", __FUNCTION__, __LINE__));
    Status = EFI_NOT_FOUND;
  }

  LOG ((EFI_D_INFO, "%a.%d Status = %0x\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


/*
*/
VOID
RequestDrmKeyInputByUser (
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language,
  IN EFI_GUID *SysGuid,
  IN EFI_LIST_ENTRY *MacListHead,
  OUT CHAR8 *DrmKey
  )
{
  CHAR8 UserDrmKey[DRM_KEY_SIZE+1];
  UINTN UserDrmKeyLength;

  LOG ((EFI_D_INFO, "%a.%d Entry.\n", __FUNCTION__, __LINE__));

  ZeroMem(DrmKey, DRM_KEY_SIZE);

  do {
    ShowDrmKeyRequestWindow(HiiHandle, Language, SysGuid);
    UserDrmKeyLength = ReadLineAndHide(UserDrmKey, sizeof(UserDrmKey), FALSE);
    UserDrmKey[UserDrmKeyLength] = '\0';
    LOG ((EFI_D_INFO, "%a.%d UserDrmKeyLength = %d\n", __FUNCTION__, __LINE__, UserDrmKeyLength));
    LOG ((EFI_D_INFO, "%a.%d UserDrmKey = %a\n", __FUNCTION__, __LINE__, UserDrmKey));
    if ((UserDrmKeyLength == DRM_KEY_SIZE) && 
        (CompareMacListWithDrm(SysGuid, MacListHead, UserDrmKey) == EFI_SUCCESS)) 
    {
      CopyMem(DrmKey, UserDrmKey, DRM_KEY_SIZE);
      LOG ((EFI_D_INFO, "%a.%d user key is confirmed.\n", __FUNCTION__, __LINE__));
      ShowDrmKeyConfirmSuccessWindow(HiiHandle, Language);
      break;
    } else {
      LOG ((EFI_D_ERROR, "%a.%d user key is NOT confirmed, retry request.\n", __FUNCTION__, __LINE__));
      ShowDrmKeyConfirmUnsuccessWindow(HiiHandle, Language);
    }
  } while (1);   // repeat until user key will be confirmed
  
  LOG ((EFI_D_INFO, "%a.%d Exit.\n", __FUNCTION__, __LINE__));
}


/*
  @retval   EFI_SUCCESS           -   received is valid DRM key from user
  @retval   EFI_ABORTED           -   runtime error
*/
EFI_STATUS
RequestUserDrmKey (
  IN CHAR8 *Language,
  IN EFI_GUID *SysGuid,
  IN EFI_LIST_ENTRY *MacListHead,
  OUT CHAR8 *DrmKey
  )
{
  EFI_HII_HANDLE HiiHandle;
  CHAR16 DrmKeyFilePath[255];
  EFI_STATUS Status;

  LOG ((EFI_D_INFO, "%a.%d Entry.\n", __FUNCTION__, __LINE__));
  
  HiiHandle = HiiAddPackages(&DrmControlWindowsGuid, NULL, MacAddressControllerLibStrings, NULL);

  UnicodeSPrint(DrmKeyFilePath, sizeof(DrmKeyFilePath), L"%s:\\%s", USB_PATH_SHORT_NAME, DRM_KEY_FILE_NAME);
  LOG ((EFI_D_INFO, "%a.%d DrmKeyFilePath = %s\n", __FUNCTION__, __LINE__, DrmKeyFilePath));

  // at first search DRM key on USB-drive
  Status = SearchDrmKeyOnUsbFile(DrmKeyFilePath, SysGuid, MacListHead, DrmKey);
  if (Status != EFI_SUCCESS) {
    ShowBiosActivationWindow(HiiHandle, Language, SysGuid);
    WaitForKP();  // wait for ENTER key pressed
    // after pressing ENTER key will search again USB-drive with DRM key file
    Status = SearchDrmKeyOnUsbFile(DrmKeyFilePath, SysGuid, MacListHead, DrmKey);
    // and if not found - request DRM key input by user
    if (Status != EFI_SUCCESS) {
      RequestDrmKeyInputByUser(HiiHandle, Language, SysGuid, MacListHead, DrmKey);
      Status = EFI_SUCCESS;
    }
  } else {
    // if USB-drive with DRM key was found right away - don't disturb user
    LOG ((EFI_D_INFO, "%a.%d USB drive with DRM key was found right away.\n", __FUNCTION__, __LINE__));
  }

  LOG ((EFI_D_INFO, "%a.%d Status = %0x\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


//=================================================================================================
//                                PUBLIC FUNCTIONS
//=================================================================================================

/*
  @retval   EFI_SUCCESS             -   MAC-address successfully writen to byte buffer
  @retval   EFI_DEVICE_ERROR        -   Ethernet controller not found or unavailable
  @retval   EFI_INVALID_PARAMETER   -   invalid ListHead
*/
EFI_STATUS
GetMacAddressList (
  OUT EFI_LIST_ENTRY* ListHead
  )
{
  UINT32 PciBaseAddress;
  EFI_LIST_ENTRY DevsListHead;
  EFI_LIST_ENTRY* CurDevsListEntry;
  PCI_DEVS_MONITOR_DATA* DevData;
  MAC_LIST_NODE LocalCopy;
  MAC_LIST_NODE* ListNode;
  EFI_STATUS Status = EFI_DEVICE_ERROR;


  
  LOG ((EFI_D_INFO, "%a.%d Entry.\n", __FUNCTION__, __LINE__));

  if (NULL == ListHead) {
    DEBUG ((EFI_D_ERROR, "%a.%d Null pointer obtained!\n", __FUNCTION__, __LINE__));
    Status = EFI_INVALID_PARAMETER;
  }

  // Internal GBE MAC address must be first in the list
  if (EFI_SUCCESS == ReadMacAddressFromEthCtrl(INT_GBE_MMIO_BASE, LocalCopy.MacAddressBuf))
  {
    ListNode = AllocateCopyPool (sizeof (MAC_LIST_NODE), &LocalCopy);
    InsertTailList(ListHead, &ListNode->Link);
    Status = EFI_SUCCESS;
  } else {
    LOG ((EFI_D_INFO, "%a.%d Internal GBE MAC address is not found\n", __FUNCTION__, __LINE__));
  }
  
  // then search other External Ethernet Controllers on PCI bus
  InitializeListHead(&DevsListHead);
  if (EFI_SUCCESS != SetPciDevList(&DevsListHead)) {
    // return internal GbE status
    return Status;
  }
  
  for (CurDevsListEntry = DevsListHead.ForwardLink; CurDevsListEntry != &DevsListHead;
      CurDevsListEntry = CurDevsListEntry->ForwardLink) 
  { 
    // search Ethernet Controller
    DevData = &((PCI_DEVS_MONITOR_LIST*) CurDevsListEntry)->Data;
    PciBaseAddress = PCI_LIB_ADDRESS (DevData->Bus, DevData->Device, DevData->Func, 0);
    
    //!!! Class code checking moved to ReadMacAddressFromEthCtrl()
    
    if (EFI_SUCCESS != ReadMacAddressFromEthCtrl (PciBaseAddress, LocalCopy.MacAddressBuf)) continue;

    LOG ((EFI_D_INFO, "%a.%d Network controller location - %X:%X:%X\n",
        __FUNCTION__, __LINE__, DevData->Bus, DevData->Device, DevData->Func));

    ListNode = AllocateCopyPool (sizeof (MAC_LIST_NODE), &LocalCopy);
    InsertTailList(ListHead, &ListNode->Link);
    Status = EFI_SUCCESS;
  }
  
  FreePciDevList(&DevsListHead);
  
  LOG ((EFI_D_INFO, "%a.%d Status = %0x\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


VOID
FreeMacAddressList (
  IN EFI_LIST_ENTRY* ListHead
  )
{
  EFI_LIST_ENTRY* CurListEntry;
  EFI_LIST_ENTRY* TempListEntry;

  LOG ((EFI_D_INFO, "%a.%d Entry.\n", __FUNCTION__, __LINE__));

  if (IsListEmpty(ListHead) == FALSE) {
    CurListEntry = ListHead->ForwardLink;
    while (CurListEntry != ListHead) {
      TempListEntry = CurListEntry->ForwardLink;
      RemoveEntryList(CurListEntry);
      FreePool(CurListEntry);
      CurListEntry = TempListEntry;
    }
  }
  LOG ((EFI_D_INFO, "%a.%d Exit.\n", __FUNCTION__, __LINE__));
}


/*
  High-level function for perform all stages MAC-address verification.
  
  @retval   EFI_SUCCESS         -   device MAC-address match with DRM key, or DRM record written successfully
  @retval   EFI_ACCESS_DENIED   -   device MAC-address NOT match with DRM key
  @retval   EFI_DEVICE_ERROR    -   error reading device MAC-address
  @retval   EFI_ABORTED         -   other verification error
*/
EFI_STATUS
VerifyMacAddress (
  IN EFI_GUID *SysGuid,
  IN CHAR8 *Language
  )
{
  EFI_LIST_ENTRY MacListHead;
  CHAR8 DrmKey[DRM_KEY_SIZE];
  EFI_STATUS Status;

  if (PcdGetBool(bEnableMacControl) == FALSE) {
    LOG ((EFI_D_INFO, "%a.%d MAC control disabled.\n", __FUNCTION__, __LINE__));
    return EFI_SUCCESS;

  } else {

    LOG ((EFI_D_INFO, "%a.%d Entry.\n", __FUNCTION__, __LINE__));

    InitializeListHead(&MacListHead);
    Status = GetMacAddressList(&MacListHead);
    if (Status == EFI_SUCCESS) {
      Status = GetDrmKey(DrmKey);
      if (Status == EFI_SUCCESS) {  // DRM key record present
        Status = CompareMacListWithDrm(SysGuid, &MacListHead, DrmKey);
      } else if (Status == EFI_NOT_FOUND) {
        Status = RequestUserDrmKey(Language, SysGuid, &MacListHead, DrmKey);
        if (Status == EFI_SUCCESS) {
          Status = WriteDrmKeyToFv(DrmKey);
        }
      }
    }
    FreeMacAddressList(&MacListHead);

    LOG ((EFI_D_INFO, "%a.%d Status = %0x\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
}
