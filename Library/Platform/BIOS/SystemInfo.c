/** @file
  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/


#include <Library/Lib/IntegrityChecking.h>
#include <Guid/SignFvGuidedSectionExtraction.h>
#include <Library/BootMngrLib.h>
#include <Include/Protocol/PlatformInfo.h>
#include <Include/Protocol/PeripheralInfo.h>
#include <Include/Library/CommonUtils.h>
#include <Include/Library/MacAddressController.h>

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)          DEBUG(MSG)
#endif

EFI_GUID gEfiPlatformInfoProtocolGuid = EFI_PLATFORM_INFO_PROTOCOL_GUID;
EFI_GUID gEfiPeripheralInfoProtocolGuid = EFI_PERIPHERAL_INFO_PROTOCOL_GUID;

STATIC EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2 = NULL;
STATIC VOID *StartOpCodeHandle, *EndOpCodeHandle;
STATIC EFI_HII_HANDLE CurrentHiiHandle;
STATIC BOOLEAN bFormExit = FALSE;
STATIC MULTIBOOT_CONFIG *MbConfig;

STATIC
VOID
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

STATIC
EFI_STATUS
AllocateHiiResources(
  VOID
  )
{
  EFI_IFR_GUID_LABEL *StartLabel;
  EFI_IFR_GUID_LABEL *EndLabel;
  EFI_GUID FormSetGuid = FORMSET_SYSTEM_INFO_GUID; // FORMSET_INTEGRITY_GUID;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_FORM_ID FormId = SYSTEM_INFO_PAGE_ID; // INTEGRITY_PAGE_ID;
  
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
  StartLabel->Number       = LABEL_SYSTEM_INFO_START; // LABEL_INTEGRITY_LIST_START;

  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      EndOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_SYSTEM_INFO_END;// LABEL_INTEGRITY_LIST_END;
  
  Status = EFI_SUCCESS;
  
  HiiUpdateForm(CurrentHiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  
_exit:  
  return Status;
}


EFI_STATUS
SystemInfoPageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  EFI_STATUS Status;

  LOG((EFI_D_INFO, "SystemInfoPageCallback START \n"));
  
  (VOID)Status;
  if (ActionRequest == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  LOG((EFI_D_INFO, "%a.%d: Action=0x%x\n", __FUNCTION__, __LINE__, Action));

  if (EFI_BROWSER_ACTION_FORM_CLOSE == Action) {
    bFormExit = TRUE;
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

STATIC
EFI_STATUS
ListPageStrings(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_STRING_ID Title,
  IN EFI_QUESTION_ID StartQId
  )
{
  EFI_STATUS                    Status;
  EFI_STRING_ID                 Token;
  EFI_STRING_ID                 HelpToken;
  EFI_QUESTION_ID               QuestionId;
  EFI_GUID                      FormSetGuid = FORMSET_SYSTEM_INFO_GUID;
  EFI_FORM_ID                   FormId = SYSTEM_INFO_PAGE_ID;
  EFI_PLATFORM_INFO_PROTOCOL    *pInfoProtocol;
  EFI_PERIPHERAL_INFO_PROTOCOL  *pPeriphInfoProtocol;
  SSataInfo*                    pSataInfo;
  EFI_LIST_ENTRY                MacListHead;
  CHAR16                        *SmartStatusString = L"";

  UINT32 i;
  
  CHAR16 TmpStr16[255];

  LOG((EFI_D_INFO, "ListPageStrings START \n"));
  
  if (EFI_SUCCESS != AllocateHiiResources()) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
  QuestionId = (EFI_QUESTION_ID)StartQId;
  
 //HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Title,
 //       HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);
 // HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
 //     StartOpCodeHandle, EndOpCodeHandle);
 // QuestionId++;
  
  //
  // Получение информации о процессоре и его параметрах
  //
  
  LOG((EFI_D_INFO, "ListPageStrings LocateProtocol PlatformInfo\n"));
    
  Status = gBS->LocateProtocol(
	&gEfiPlatformInfoProtocolGuid, NULL,
	&pInfoProtocol);
	
  if (EFI_SUCCESS != Status) 
  {
	DEBUG((EFI_D_ERROR, "ListPageStrings error code 0x%08x \n", Status));
    return Status;
  }
  
  //
  // Процессор
  //
  Token = STRING_TOKEN(STR_PROCESSOR_TITLE);
  HiiCreateSubTitleOpCode (StartOpCodeHandle, Token, 0, 0, 1);

  for (i = 0; i < pInfoProtocol->_PlatformInfo._nCpuCount; i++) {
  
    /*UnicodeSPrint(TmpStr16, sizeof(TmpStr16), HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_PROCESSOR_TITLE), NULL));
    Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
          HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);*/
    QuestionId++;

    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_PROCESSOR_MAIN_INFO), NULL), 
	  pInfoProtocol->_PlatformInfo._ProcessorInfo[i]._wszCpuModel);
    Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
          HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);
    QuestionId++;

    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_PROCESSOR_FREQ_INFO), NULL),
	  pInfoProtocol->_PlatformInfo._ProcessorInfo[i]._nCpuFreqInMHz);
    Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
          HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);
    QuestionId++;

    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_PROCESSOR_CORES_INFO), NULL), 
	  pInfoProtocol->_PlatformInfo._ProcessorInfo[i]._nCoresCount);
    Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
          HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);
    QuestionId++;


    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_PROCESSOR_THREADS_INFO), NULL), 
	  pInfoProtocol->_PlatformInfo._ProcessorInfo[i]._nThreadsCount);
    Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
          HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);
    QuestionId++;

    if (i + 1 < pInfoProtocol->_PlatformInfo._nCpuCount) {
      Token = STRING_TOKEN(STR_SPACE);
      HiiCreateSubTitleOpCode (StartOpCodeHandle, Token, 0, 0, 1);
    }

  }
  
  //
  // Память
  //
    
  /*UnicodeSPrint(TmpStr16, sizeof(TmpStr16), HiiGetString(CurrentHiiHandle, 
    STRING_TOKEN(STR_MEMORY_TITLE), NULL));
  Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);*/
  Token = STRING_TOKEN(STR_NULL_STRING);
  HiiCreateSubTitleOpCode (StartOpCodeHandle, Token, 0, 0, 1);
  Token = STRING_TOKEN(STR_MEMORY_TITLE);
  HiiCreateSubTitleOpCode (StartOpCodeHandle, Token, 0, 0, 1);
  QuestionId++;	
	
  UnicodeSPrint(TmpStr16, sizeof(TmpStr16), HiiGetString(CurrentHiiHandle, 
    STRING_TOKEN(STR_MEMORY_SIZE_INFO), NULL), 
	pInfoProtocol->_PlatformInfo._MemoryInfo._nTotalMemoryInMb);
  Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);
  QuestionId++;
  
  UnicodeSPrint(TmpStr16, sizeof(TmpStr16), HiiGetString(CurrentHiiHandle, 
    STRING_TOKEN(STR_MEMORY_FREQ_INFO), NULL), 
	pInfoProtocol->_PlatformInfo._MemoryInfo._nMemFreqInMHz);
  Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);
  QuestionId++;

  HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
	  StartOpCodeHandle, EndOpCodeHandle);

  //
  // Получение информации о SATA-дисках
  //

  LOG((EFI_D_INFO, "ListPageStrings LocateProtocol PeripheralInfo\n"));

  Status = gBS->LocateProtocol(
	  &gEfiPeripheralInfoProtocolGuid, NULL,
	  &pPeriphInfoProtocol);

  if (!EFI_ERROR(Status)) 
  {
	  pSataInfo = &pPeriphInfoProtocol->_PeripheralInfo._SataInfo;

	  if (pSataInfo->_nDeviceCount)
	  {
		  /*UnicodeSPrint(TmpStr16, sizeof(TmpStr16), HiiGetString(CurrentHiiHandle, 
			  STRING_TOKEN(STR_SATA_TITLE_INFO), NULL));
		  Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
		  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
			  HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);*/
      Token = STRING_TOKEN(STR_NULL_STRING);
      HiiCreateSubTitleOpCode (StartOpCodeHandle, Token, 0, 0, 1);
      Token = STRING_TOKEN(STR_SATA_TITLE_INFO);
      HiiCreateSubTitleOpCode (StartOpCodeHandle, Token, 0, 0, 1);
		  QuestionId++;
	  }

	  for (i = 0; i < pSataInfo->_nDeviceCount; i++)
	  {
      
      if(pSataInfo->_aSataDevice[i].Attributes & SATA_DEVICE_INFO_ATTR_SMART_SUPPORT) {
        SmartStatusString = (pSataInfo->_aSataDevice[i].Attributes & SATA_DEVICE_INFO_ATTR_SMART_OK) ? 
                        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_SATA_SMART_STATUS_OK), NULL) :
                        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_SATA_SMART_STATUS_BAD), NULL);
      }
      
		  if (pSataInfo->_aSataDevice[i]._nSizeInBytes)
		  {
			  UnicodeSPrint(TmpStr16, sizeof(TmpStr16), HiiGetString(CurrentHiiHandle, 
				  STRING_TOKEN(STR_SATA_TEMPLATE_SIZE_INFO), NULL), 
				  pSataInfo->_aSataDevice[i]._wszModel,
				  (UINT32)(pSataInfo->_aSataDevice[i]._nSizeInBytes / (1024*1024*1024)),
          SmartStatusString);
		  }
		  else
		  {
			  UnicodeSPrint(TmpStr16, sizeof(TmpStr16), HiiGetString(CurrentHiiHandle, 
				  STRING_TOKEN(STR_SATA_TEMPLATE_INFO), NULL),
				  pSataInfo->_aSataDevice[i]._wszModel,
          SmartStatusString);
		  }

		  Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
		  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
			  HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);
		  QuestionId++;
	  }
  }

  //
  // Получение информации об обнаруженных MAC-адресах Ethernet-контроллеров
  //

  InitializeListHead(&MacListHead);
  LOG((EFI_D_INFO, "GetMacAddressList Entry \n"));
  Status = GetMacAddressList (&MacListHead);
  LOG((EFI_D_INFO, "GetMacAddressList Exit \n"));
  if (!EFI_ERROR(Status))
  {
	  EFI_LIST_ENTRY* pCurDevsListEntry;
	  UINT8* pMacAddr;

	  LOG((EFI_D_INFO, "GetMacAddressList OK \n"));

	  if (MacListHead.ForwardLink != &MacListHead)
	  {
		  LOG((EFI_D_INO, "List isn't empty \n"));

		  /*UnicodeSPrint(TmpStr16, sizeof(TmpStr16), HiiGetString(CurrentHiiHandle, 
			  STRING_TOKEN(STR_ETHERNET_TITLE_INFO), NULL));
		  Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
		  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
			  HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);*/
      Token = STRING_TOKEN(STR_NULL_STRING);
      HiiCreateSubTitleOpCode (StartOpCodeHandle, Token, 0, 0, 1);
      Token = STRING_TOKEN(STR_ETHERNET_TITLE_INFO);
      HiiCreateSubTitleOpCode (StartOpCodeHandle, Token, 0, 0, 1);
		  QuestionId++;
	  }

	  for (pCurDevsListEntry = MacListHead.ForwardLink; pCurDevsListEntry != &MacListHead;
		  pCurDevsListEntry = pCurDevsListEntry->ForwardLink)
	  {
		  pMacAddr = &(((MAC_LIST_NODE*) pCurDevsListEntry)->MacAddressBuf[0]);

		  LOG((EFI_D_INFO, "Found mac addr %02X-%02X-%02X-%02X-%02X-%02X\n", 
			  pMacAddr[0],
			  pMacAddr[1],
			  pMacAddr[2],
			  pMacAddr[3],
			  pMacAddr[4],
			  pMacAddr[5]));

		  UnicodeSPrint(TmpStr16, sizeof(TmpStr16), HiiGetString(CurrentHiiHandle, 
			  STRING_TOKEN(STR_ETHERNET_MAC_ADDR_TEMPLATE), NULL), 
			  pMacAddr[0],
			  pMacAddr[1],
			  pMacAddr[2],
			  pMacAddr[3],
			  pMacAddr[4],
			  pMacAddr[5]
			  );

		  Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
		  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
			  HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);
		  QuestionId++;
	  }

	  LOG((EFI_D_INFO, "FreeMacAddressList Entry \n"));
	  FreeMacAddressList(&MacListHead);
	  LOG((EFI_D_INFO, "FreeMacAddressList Exit \n"));
  }

  HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);

  LOG((EFI_D_INFO, "Interface drawing OK"));

  return EFI_SUCCESS;
}


EFI_STATUS
SystemInfoPage(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  EFI_GUID FormSetGuid = FORMSET_SYSTEM_INFO_GUID;
  EFI_FORM_ID FormId = SYSTEM_INFO_PAGE_ID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  
  LOG((EFI_D_INFO, "SystemInfoPage START\n"));
  
  Status = ListPageStrings(HiiHandle, STRING_TOKEN(STR_SYSTEM_INFO_TITLE),
		(EFI_QUESTION_ID)SYSTEM_INFO_RES_START);
  LOG((EFI_D_INFO, "%a.%d Status=0x%X\n", 
    __FUNCTION__, __LINE__, Status));
  if (EFI_ERROR(Status)) {
    DestroyHiiResources();
    return Status;
  }

  Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
    (VOID **) &gFormBrowser2);
  if (EFI_ERROR (Status)) 
  {
     DEBUG((EFI_D_ERROR, "%a.%d Error 0x08x\n", __FUNCTION__, __LINE__, Status));
    DestroyHiiResources();
    return Status;
  }

  ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
  Status = EFI_SUCCESS;

  do {
    Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1,
      &FormSetGuid, FormId, NULL, &ActionRequest);      
    LOG((EFI_D_INFO, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));  
    if (bFormExit) {
      Status = EFI_SUCCESS;
      break;
    }
  } while (1);

  DestroyHiiResources();
  return Status;
}


EFI_STATUS
SystemInfoPageStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  CurrentHiiHandle = HiiHandle;
  
  //
  // Асинхронное окно здесь пока не нужно
  //
  
  /*
  CreatePopUp (
          EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE, 
          NULL, 
          L"", 
          HiiGetString(CurrentHiiHandle, 
            STRING_TOKEN(STR_SYSTEM_INFO), NULL),
          L"", 
          NULL
          );
 */		  
  return SystemInfoPage(HiiHandle, Language);
}



