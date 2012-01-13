/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/BIOSLib/History.h>
#include <Library/BIOSLib/CertificatesControl.h>
#include <Library/RevokeChkConfigLib/RevokeChkConfig.h>

#include <Library/AdvRevokeChkConfigMenu/AdvRevokeChkConfigMenu.h>

#include <Protocol/HistoryHandlerProto.h>

#include <CommonGuiSetup.h>

//------------------------------------------------------------------------------
/*! \brief Delete RevokeChkConfig */
/*! This function doesn't delete config from efi variable. Only variable from RAM
    is been deleting. */
//------------------------------------------------------------------------------
VOID
DeleteRevokeChkConfigFormData (
  VOID
)
{
  DeleteRevokeChkConfig();
  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Process element's actions from Revoke Check Config Menu */
/*! \param[in] *This Pointer to ADV_MENU_HANDLER_PROTOCOL
    \paran[in] QuestionId ID of element, which action we need to process
    \param[in] *Value Pointer to the value of the element's data
    \param[out] *ActionRequest an action request to the top level of the AdvMenu */
/*! \return Status of the operation */
/*! \retval EFI_SUCCESS Success
    \retval EFI_INVALID_PARAMETER Value for the element is NULL */
//------------------------------------------------------------------------------
EFI_STATUS
ProcessRevokeChkConfigFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
)
{
  EFI_STRING_ID StrId = Value->string;
  CHAR16 *recvString16 = NULL;
  EFI_STATUS Status;

  DEBUG((EFI_D_ERROR, "%a.%d: QuestionId: %X\n",
      __FUNCTION__, __LINE__, QuestionId));


  if (QuestionId == OCSP_URL_INPUT || QuestionId == LOCAL_CDP_URL_INPUT) {
    if (StrId == (EFI_STRING_ID)0) {
      DEBUG((EFI_D_ERROR, "%a.%d: Value = NULL!! \n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    }

    recvString16 = HiiGetString(This->GetHiiHandle(This), StrId, NULL);
    if (recvString16 == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d: Value = NULL!! \n", __FUNCTION__, __LINE__));
      return EFI_INVALID_PARAMETER;
    }
  }
  
  switch(QuestionId) {
  case USE_OCSP_CONFIG:
    if (FALSE == Value->b)
      SetOcspUsageFlag(NOT_USE);
    else
      SetOcspUsageFlag(USE);
    break;
  case OCSP_URL_INPUT:
    if (SetOcspUrl(recvString16) != EFI_SUCCESS) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error to set ocsp url!\n", __FUNCTION__, __LINE__));
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
    }
    break;
  case USE_OCSP_RSP_VERITY:
    if (FALSE == Value->b)
      SetOCSPResponceVerifyUsageFlag(NOT_USE);
    else
      SetOCSPResponceVerifyUsageFlag(USE);
    break;
  case USE_LOCAL_CDP_CONFIG:
    if (FALSE == Value->b)
      SetLocalCdpUsageFlag(NOT_USE);
    else
      SetLocalCdpUsageFlag(USE);
    break;
  case LOCAL_CDP_URL_INPUT:
    if (SetLocalCdpUrl(recvString16) != EFI_SUCCESS) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error to set local cdp url!\n", __FUNCTION__, __LINE__));
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
    }
    break;
  case USE_CRL_CHECK:
    if (Value->u16 <= CRL_CHECK && Value->u16 >= DONT_CHECK_CRL)
      SetCrlCheckMode(Value->u16);
    break;
  case USE_CDP_CASHE:
    if (FALSE == Value->b)
      SetCDPCasheUsageFlag(NOT_USE);
    else
      SetCDPCasheUsageFlag(USE);
    break;
  case USE_TLS_CRL_CHECK:
    if (Value->u16 <= CRL_CHECK && Value->u16 >= DONT_CHECK_CRL)
      SetTLSCrlCheckMode(Value->u16);
    break;
  case USE_CDP_FROM_CERT:
    if (FALSE == Value->b)
      SetCDPfromCertUsageFlag(NOT_USE);
    else
      SetCDPfromCertUsageFlag(USE);
    break;
  case SAVE_REVOKE_CHECK_CONFIG:
    Status = SaveRevokeChkConfig();
    {
      EFI_STATUS St;
      HISTORY_HANDLER_PROTOCOL  *HistoryHandlerProtocol;
      St = gBS->LocateProtocol (&gHistoryHandlerProtocolGuid, NULL, 
          (VOID **) &HistoryHandlerProtocol);
      if (!EFI_ERROR (St)) {
        if (HistoryHandlerProtocol != NULL) {
          HistoryHandlerProtocol->AddRecord(
            HistoryHandlerProtocol,
            HEVENT_REVOKE_CERTS_CFG_CHANGED,
            EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
            EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
        }
      }
    }
    switch (Status) {
      case EFI_UNSUPPORTED:
        ShowErrorPopup(This->GetHiiHandle(This), 
          HiiGetString(This->GetHiiHandle(This), This->GetStringId(OCSP_URL_EMPTY),
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
FillRevokeChkConfigFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
)
{
  CHAR16        *recvString16 = (CHAR16*)Value;

  DEBUG((EFI_D_ERROR, "%a.%d: QuestionId: %d\n",
      __FUNCTION__, __LINE__, QuestionId));

  if (recvString16 == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: Value = NULL!! \n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }  

  switch(QuestionId) {
  case USE_OCSP_CONFIG:
    if (GetOcspUsageFlag() == NOT_USE) {
      *(BOOLEAN *)Value = FALSE;
    } else {
      *(BOOLEAN *)Value = TRUE;
    }
    break;

  case OCSP_URL_INPUT:
    if (GetOcspUsageFlag() == NOT_USE) {
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    } else if(GetOcspUrlLenght() > 0) {
      StrnCpy(recvString16, GetOcspUrl(), MAX_INPUT_AREA_SIZE);
    }
    break;

  case USE_OCSP_RSP_VERITY:
    if (GetOcspUsageFlag() == NOT_USE) {
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    }
    if (GetOCSPResponceVerifyUsageFlag() == NOT_USE) {
      *(BOOLEAN *)Value = FALSE;
    } else {
      *(BOOLEAN *)Value = TRUE;
    }
    break;

  case USE_LOCAL_CDP_CONFIG:
    if (GetLocalCdpUsageFlag() == NOT_USE) {
      *(BOOLEAN *)Value = FALSE;
    } else {
      *(BOOLEAN *)Value = TRUE;
    }
    break;

  case LOCAL_CDP_URL_INPUT:
    if (GetLocalCdpUsageFlag() == NOT_USE) {
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    } else if(GetLocalCdpUrlLenght() > 0) {
      StrnCpy(recvString16, GetLocalCdpUrl(), MAX_INPUT_AREA_SIZE);
    }
    break;

  case USE_CRL_CHECK:
    *(UINT16*)Value = GetCrlCheckMode();
    break;

  case USE_CDP_CASHE:
    if (GetLocalCdpUsageFlag() == NOT_USE) {
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    }
    if (GetCDPCasheUsageFlag() == NOT_USE) {
      *(BOOLEAN *)Value = FALSE;
    } else {
      *(BOOLEAN *)Value = TRUE;
    }
    break;

  case USE_TLS_CRL_CHECK:
    *(UINT16*)Value = GetTLSCrlCheckMode();
    break;

  case USE_CDP_FROM_CERT:
    if (GetLocalCdpUsageFlag() == NOT_USE) {
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    }
    if (GetCDPfromCertUsageFlag() == NOT_USE) {
      *(BOOLEAN *)Value = FALSE;
    } else {
      *(BOOLEAN *)Value = TRUE;
    }
    break;
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------
