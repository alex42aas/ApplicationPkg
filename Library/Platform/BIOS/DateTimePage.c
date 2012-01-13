/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/Lib/DateTimePage.h>


extern UINT8 MainPagevfrBin[];

static EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;


EFI_STATUS
DateTimePageCallback(
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

  
  return EFI_SUCCESS;
}

EFI_STATUS
DateTimePageStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  EFI_STATUS Status;
  EFI_GUID FormSetGuid = DATE_TIME_SETUP_PAGE_GUID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  
  DEBUG((EFI_D_ERROR, "%a.%d: Start\n", __FUNCTION__, __LINE__));
  
  (VOID)Language;
  
  Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
    (VOID **) &gFormBrowser2);
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
    return Status;
  }

  ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
  Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1,
      &FormSetGuid, DATE_TIME_SETUP_PAGE_ID, NULL, &ActionRequest);
  DEBUG((EFI_D_ERROR, "%a.%d: Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  DEBUG((EFI_D_ERROR, "%a.%d: ActionRequest=0x%X\n", __FUNCTION__, __LINE__, ActionRequest));
  return Status;
}
