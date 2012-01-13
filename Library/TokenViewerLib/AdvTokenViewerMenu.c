/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>

#include <Library/TokenViewerLib/AdvTokenViewerMenu.h>

#include "TokenViewerInternals.h"

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

extern EFI_GUID gTokenSelectCertVarGuid;

//------------------------------------------------------------------------------
/*! \brief Process TokenViewer menu */
//------------------------------------------------------------------------------
EFI_STATUS
ProcessTokenViewerFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
)
{
  EFI_STATUS Status;

  LOG((EFI_D_ERROR, "%a.%d QuestionId: 0x%X\n", __FUNCTION__, __LINE__, QuestionId));

  Status = gRT->SetVariable(
                  TOKEN_SELECT_CERT_VAR_NAME,
                  &gTokenSelectCertVarGuid,
                  EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  sizeof(QuestionId),
                  &QuestionId
                  );

  *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Fill menu elements with values */
///------------------------------------------------------------------------------
EFI_STATUS
FillTokenViewerFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
)
{
  // No need to do anything
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

