/** @file
  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include <Library/Lib/RecoverModePage.h>


static MULTIBOOT_CONFIG *CurrentConfig;
static EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
static EFI_HII_HANDLE CurrentHiiHandle;
static VOID *StartOpCodeHandle, *EndOpCodeHandle;

static BOOLEAN bFormExitFlag, bRefreshForm;
static int CurrentEvent;


int
RMPGetSelectionNum(
  VOID
  )
{
  return (CurrentEvent - RMP_MODE1);
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


static EFI_STATUS
AllocateHiiResources(
  VOID
  )
{
  EFI_IFR_GUID_LABEL *StartLabel;
  EFI_IFR_GUID_LABEL *EndLabel;
  EFI_GUID FormSetGuid = FORMSET_RECOVER_MODE_GUID;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_FORM_ID FormId = RECOVER_MODE_PAGE_ID;
  
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
  StartLabel->Number       = LABEL_RECOVER_MODE_PAGE_LIST_START;

  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      EndOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_RECOVER_MODE_PAGE_LIST_END;
  
  Status = EFI_SUCCESS;
  
  HiiUpdateForm(CurrentHiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  
_exit:  
  return Status;
}


EFI_STATUS
RMPCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
//  EFI_STATUS Status;

  if (ActionRequest == NULL) {
    return EFI_INVALID_PARAMETER;
  }

#if 1
  DEBUG((EFI_D_ERROR, "%a.%d: Action=0x%x\n", __FUNCTION__, __LINE__, Action));
#endif

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

  CurrentEvent = QuestionId;
  *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
  return EFI_SUCCESS;
}


EFI_STATUS
RMPInit(
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *Cfg
  )
{
  bFormExitFlag = FALSE;
  bRefreshForm = FALSE;
  
  CurrentEvent = 0;
    
  CurrentConfig = Cfg;
  CurrentHiiHandle = HiiHandle;
  return EFI_SUCCESS;
}


EFI_STATUS
RMP(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR16 **ParamStrings,
  IN UINTN ParamStringsAmount
  )
{
  EFI_GUID FormSetGuid = FORMSET_RECOVER_MODE_GUID;
  EFI_FORM_ID FormId = RECOVER_MODE_PAGE_ID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID HelpToken, RMP_mode1_str, RMP_mode2_str;
  
  do {  
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    
    if (EFI_SUCCESS != AllocateHiiResources()) {
      return EFI_OUT_OF_RESOURCES;
    }
    
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

    HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
    RMP_mode1_str = HiiSetString (HiiHandle, 0, ParamStrings[0], NULL);
    RMP_mode2_str = HiiSetString (HiiHandle, 0, ParamStrings[1], NULL);

    HiiCreateActionOpCode(StartOpCodeHandle, 
      (EFI_QUESTION_ID)-1, 
      STRING_TOKEN(STR_CHOOSE_RECOVER_PARAMS),
      HelpToken, EFI_IFR_FLAG_READ_ONLY, 0);
    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
    
    HiiCreateActionOpCode(StartOpCodeHandle, 
      (EFI_QUESTION_ID)RMP_MODE1, 
      RMP_mode1_str,
      HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
    
    HiiCreateActionOpCode(StartOpCodeHandle, 
      (EFI_QUESTION_ID)RMP_MODE2, 
      RMP_mode2_str,
      HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
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
    DestroyHiiResources();
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      break;
    }
  } while (bRefreshForm);
    
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
  return Status;
}


EFI_STATUS
RMPStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR16 **ParamStrings,
  IN UINTN ParamStringsAmount
  )
{
  EFI_STATUS Status;
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
#if 0  
  if (CurrentConfig == NULL) {
    return EFI_INVALID_PARAMETER;
  }
#endif  
  CurrentHiiHandle = HiiHandle;
  bRefreshForm = FALSE;
  Status = RMP(HiiHandle, ParamStrings, ParamStringsAmount);
  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

