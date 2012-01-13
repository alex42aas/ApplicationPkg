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
#include <Library/BIOSLib/History.h>
#include <Library/DiagnosticsConfigLib/DiagnosticsConfig.h>
#include <Library/AdvDiagnosticsConfigMenu/AdvDiagnosticsConfigMenu.h>

#include <Protocol/HistoryHandlerProto.h>

#include <CommonGuiSetup.h>

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

//------------------------------------------------------------------------------
/*! \brief Delete Diagnostics Config */
/*! This function doesn't delete config from efi variable. Only variable from RAM
    is been deleting. */
//------------------------------------------------------------------------------
VOID
DeleteDiagnosticsConfigFormData (
  VOID
)
{
  DeleteDiagnosticsConfig();

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Process element's actions from Diagnostics Config Menu */
/*! \param[in] *This Pointer to ADV_MENU_HANDLER_PROTOCOL
    \paran[in] QuestionId ID of element, which action we need to process
    \param[in] *Value Pointer to the value of the element's data
    \param[out] *ActionRequest an action request to the top level of the AdvMenu */
/*! \return Status of the operation */
/*! \retval EFI_SUCCESS Success
    \retval EFI_INVALID_PARAMETER Value for the element is NULL */
//------------------------------------------------------------------------------
EFI_STATUS
ProcessDiagnosticsConfigFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
)
{
  EFI_STATUS Status;

  LOG((EFI_D_ERROR, "%a.%d: QuestionId: %d\n",__FUNCTION__, __LINE__, QuestionId));
  
  switch(QuestionId) {
  case USE_DIAGNOSTICS_LOG:
    if (FALSE == Value->b)
      SetDiagnosticsLogUsageFlag(NOT_USE);
    else
      SetDiagnosticsLogUsageFlag(USE);
    break;
  case USE_COM_PORT:
    if (FALSE == Value->b)
      SetComPortUsageFlag(NOT_USE);
    else
      SetComPortUsageFlag(USE);
    break;
  case USE_NET_LOG:
    if (FALSE == Value->b)
      SetNetLogUsageFlag(NOT_USE);
    else
      SetNetLogUsageFlag(USE);
    break;
  case USE_RAM_LOG:
    if (FALSE == Value->b)
      SetRamLogUsageFlag(NOT_USE);
    else
      SetRamLogUsageFlag(USE);
    break;
  case SAVE_DIAGNOSTICS_SETTINGS:
    Status = SaveDiagnosticsConfig();
    {
      EFI_STATUS St;
      HISTORY_HANDLER_PROTOCOL  *HistoryHandlerProtocol;
      St = gBS->LocateProtocol (&gHistoryHandlerProtocolGuid, NULL, 
          (VOID **) &HistoryHandlerProtocol);
      if (!EFI_ERROR (St)) {
        if (HistoryHandlerProtocol != NULL) {
          HistoryHandlerProtocol->AddRecord(
            HistoryHandlerProtocol,
            HEVENT_DIAGNOSTICS_CFG_CHANGED,
            EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
            EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
        }
      }
    }
    switch (Status) {
      case EFI_UNSUPPORTED:
        ShowErrorPopup(This->GetHiiHandle(This), 
          HiiGetString(This->GetHiiHandle(This), This->GetStringId(DIAGNOSTIC_LOG_NOT_SET),
            NULL));
        break;
      case EFI_SUCCESS:
        ShowSuccessPopup(This->GetHiiHandle(This),
          HiiGetString(This->GetHiiHandle(This), This->GetStringId(CONFIG_SAVES_SUCCESS),
            NULL));
        *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
        break;
      default:
        ShowErrorPopup(This->GetHiiHandle(This), 
          HiiGetString(This->GetHiiHandle(This), This->GetStringId(CONFIG_SAVES_ERROR),
            NULL));
        break;
    }
    break;
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a data to the Value of the element */
/*! \param[in] *This Pointer to ADV_MENU_HANDLER_PROTOCOL
    \paran[in] QuestionId ID of element, which Value we want to set
    \param[in] *Value Pointer to the value of the element's data
    \param[out] *ActionRequest an action request to the top level of the AdvMenu */
/*! \return Status of the operation */
/*! \retval EFI_SUCCESS Success of the operation
    \retval EFI_INVALID_PARAMETER Value for the element is NULL */
//------------------------------------------------------------------------------
EFI_STATUS
FillDiagnosticsConfigFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
)
{
  LOG((EFI_D_ERROR, "%a.%d: QuestionId: %d\n",
      __FUNCTION__, __LINE__, QuestionId));

  switch(QuestionId) {
  case USE_DIAGNOSTICS_LOG:
    if (GetDiagnosticsLogUsageFlag() == NOT_USE)
      *(BOOLEAN *)Value = FALSE;
    else
      *(BOOLEAN *)Value = TRUE;
    break;
  case USE_COM_PORT:
    if (GetDiagnosticsLogUsageFlag() == NOT_USE)
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    else if(GetComPortUsageFlag() == NOT_USE)
      *(BOOLEAN *)Value = FALSE;
    else
      *(BOOLEAN *)Value = TRUE;
    break;
  case USE_NET_LOG:
    if (GetDiagnosticsLogUsageFlag() == NOT_USE)
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    else if(GetNetLogUsageFlag() == NOT_USE)
      *(BOOLEAN *)Value = FALSE;
    else
      *(BOOLEAN *)Value = TRUE;
    break;
  case USE_RAM_LOG:
    if (GetDiagnosticsLogUsageFlag() == NOT_USE)
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    else if(GetRamLogUsageFlag() == NOT_USE)
      *(BOOLEAN *)Value = FALSE;
    else
      *(BOOLEAN *)Value = TRUE;
    break;
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

