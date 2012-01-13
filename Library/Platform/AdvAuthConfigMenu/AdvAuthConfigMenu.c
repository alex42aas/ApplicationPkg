/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/BaseLib.h>
#include <Library/AdvAuthConfigMenu/AdvAuthConfigMenu.h>

#include <Library/AuthModeConfig/AuthModeConfig.h>

#include <CommonGuiSetup.h>
#include <Protocol/HistoryHandlerProto.h>
#include <Library/BIOSLib/History.h>


//------------------------------------------------------------------------------
/*! \brief Delete Auth Mode Config Menu data */
//------------------------------------------------------------------------------
VOID
DeleteAuthModeFormData( 
  VOID
  )
{
  DeleteAuthModeConfig();

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Process element's actions from Auth Configuration Menu */
/*! \param[in] *This Pointer to ADV_MENU_HANDLER_PROTOCOL
    \paran[in] QuestionId ID of element, which action we need to process
    \param[in] *Value Pointer to the value of the element's data
    \param[out] *ActionRequest an action request to the top level of the AdvMenu */
/*! \return Status of the operation */
/*! \retval EFI_SUCCESS Success
    \retval EFI_INVALID_PARAMETER Value for the element is NULL */
//------------------------------------------------------------------------------
EFI_STATUS
ProcessAuthConfigFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
)
{
  CHAR16 *recvString16 = NULL;
    
  EFI_STATUS    Status;
  EFI_STRING_ID StrId = 0;
    
  // Check the Value if the action isn't for the Save Auth Mode Config action element
  if (QuestionId == SELECT_AUTH_MODE || QuestionId == USAGE_LOCAL_GUEST ||
      QuestionId == SAVE_AUTH_CONFIG || QuestionId == USAGE_LDAP_GUEST ||
      QuestionId == CN_COMPARISON    || QuestionId == OU_COMPARISON    ||
      QuestionId == SUBJECT_COMPARISON || QuestionId == USAGE_USER_PC_LINK) {
    ; // PASS
  } else {
    StrId = Value->string;

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
  case USAGE_USER_PC_LINK:
    if (TRUE == Value->b)
      SetUserPCLinkCheckStatus(USE_SETTING);
    else
      SetUserPCLinkCheckStatus(DONT_USE_SETTING);
    break;
  case SELECT_AUTH_MODE:
    if (Value->u8 <= GUEST_AUTH_MODE && Value->u8 >= DEFAULT_AUTH_MODE)
      SetAuthMode(Value->u8);
    break;
  case USAGE_LOCAL_GUEST:
    if (TRUE == Value->b)
      SetLocalUsageStatus(USE_SETTING);
    else
      SetLocalUsageStatus(DONT_USE_SETTING);
    break;
  case USAGE_LDAP_GUEST:
    if (TRUE == Value->b)
      SetLdapUsageStatus(USE_SETTING);
    else
      SetLdapUsageStatus(DONT_USE_SETTING);
    break;
  case CN_COMPARISON:
    if (TRUE == Value->b)
      SetTypeOfComparison(CN_CMP);
    else
      ClearTypeOfComparison(CN_CMP);
    break;
  case CN_DATA:
    if (SetCmpDataByType(CN_CMP, recvString16) != EFI_SUCCESS) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error to set CN!!!\n", __FUNCTION__, __LINE__));
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
    }
    break;
  case OU_COMPARISON:
    if (TRUE == Value->b)
      SetTypeOfComparison(OU_CMP);
    else
      ClearTypeOfComparison(OU_CMP);
    break;
  case OU_DATA:
    if (SetCmpDataByType(OU_CMP, recvString16) != EFI_SUCCESS) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error to set OU!!!\n", __FUNCTION__, __LINE__));
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
    }
    break;
  case SUBJECT_COMPARISON:
    if (TRUE == Value->b)
      SetTypeOfComparison(SUBJECT_CMP);
    else
      ClearTypeOfComparison(SUBJECT_CMP);
    break;
  case SUBJECT_DATA:
    if (SetCmpDataByType(SUBJECT_CMP, recvString16) != EFI_SUCCESS) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error to set SUBJECT!!!\n", __FUNCTION__, __LINE__));
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
    }
    break;
  case SAVE_AUTH_CONFIG:
    Status = SaveAuthModeConfig();
    {
      EFI_STATUS St;
      HISTORY_HANDLER_PROTOCOL  *HistoryHandlerProtocol;
      St = gBS->LocateProtocol (&gHistoryHandlerProtocolGuid, NULL, 
          (VOID **) &HistoryHandlerProtocol);
      if (!EFI_ERROR (St)) {
        if (HistoryHandlerProtocol != NULL) {
          HistoryHandlerProtocol->AddRecord(
            HistoryHandlerProtocol,
            HEVENT_AUTH_MODE_CFG_CHANGED, 
            EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
            EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
        }
      }
    }
    switch (Status) {
      case EFI_UNSUPPORTED:
        ShowErrorPopup(This->GetHiiHandle(This), 
        HiiGetString(This->GetHiiHandle(This), This->GetStringId(UNSUPPORTED_SETTING),
          NULL));
        break;
      case EFI_INVALID_PARAMETER:
        ShowErrorPopup(This->GetHiiHandle(This), 
        HiiGetString(This->GetHiiHandle(This), This->GetStringId(CORRRESPONDENCE_ERROR),
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
  default:
    // NOP. Unknown QuestionId.
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
FillAuthConfigFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
)
{
  UINT8   authMode, cmpType;
  const CHAR16 *str16;

  DEBUG((EFI_D_ERROR, "%a.%d: QuestionId: 0x%X\n",
    __FUNCTION__, __LINE__, QuestionId));
        
  if (Value == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: Value = NULL!! \n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
    
  cmpType = GetTypeOfComparison();
    
  *ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
    
  if (GetAuthMode() == DEFAULT_AUTH_MODE &&
    QuestionId != SELECT_AUTH_MODE &&
    QuestionId != USAGE_USER_PC_LINK) {
    *ActionRequest = EFI_BROWSER_ACTION_HIDE;
  } else {
    switch(QuestionId){
    case USAGE_USER_PC_LINK:
     if (IsUserPCLinkCheck() == TRUE) {
        *(BOOLEAN*)Value = TRUE;
      } else {
        *(BOOLEAN*)Value = FALSE;
      }
      break;

    case SELECT_AUTH_MODE:
      authMode = GetAuthMode();
      if (authMode <= GUEST_AUTH_MODE && authMode >= DEFAULT_AUTH_MODE) {
        *(UINT8*)Value = authMode;
      }
      break;

    case USAGE_LOCAL_GUEST:
      if (IsUseLocalGuestLogin() == TRUE) {
        *(BOOLEAN*)Value = TRUE;
      } else {
        *(BOOLEAN*)Value = FALSE;
      }
      break;

    case USAGE_LDAP_GUEST:
      if (IsUseLdapGuestLogin() == TRUE) {
        *(BOOLEAN*)Value = TRUE;
      } else {
        *(BOOLEAN*)Value = FALSE;
      }
      break;

    case CN_COMPARISON:
      if (IsUseLocalGuestLogin() == FALSE) {
        *ActionRequest = EFI_BROWSER_ACTION_HIDE;
      } else if (CN_CMP == (cmpType & CN_CMP)) {
        *(BOOLEAN *)Value = TRUE;
      } else {
        *(BOOLEAN *)Value = FALSE;
      }
      break;

    case CN_DATA:
      if ((IsUseLocalGuestLogin() == FALSE) || (CN_CMP == ((~cmpType) & CN_CMP))) {
        *ActionRequest = EFI_BROWSER_ACTION_HIDE;
      } else {
        str16 = GetCmpDataByType(CN_CMP);
        if (str16 != NULL) {
          StrnCpy((CHAR16*)Value, str16, MAX_INPUT_AREA_SIZE);
        }
      }
      break;

    case OU_COMPARISON:
      if (IsUseLocalGuestLogin() == FALSE) {
        *ActionRequest = EFI_BROWSER_ACTION_HIDE;
      } else if (OU_CMP == (cmpType & OU_CMP)) {
        *(BOOLEAN *)Value = TRUE;
      } else {
        *(BOOLEAN *)Value = FALSE;
      }
      break;

    case OU_DATA:
      if ((IsUseLocalGuestLogin() == FALSE) || (OU_CMP == ((~cmpType) & OU_CMP))) {
        *ActionRequest = EFI_BROWSER_ACTION_HIDE;
      } else {
        str16 = GetCmpDataByType(OU_CMP);
        if (str16 != NULL) {
          StrnCpy((CHAR16*)Value, str16, MAX_INPUT_AREA_SIZE);
        }
      }
      break;
    case SUBJECT_COMPARISON: 
      if (IsUseLocalGuestLogin() == FALSE) {
        *ActionRequest = EFI_BROWSER_ACTION_HIDE;
      } else if (SUBJECT_CMP == (cmpType & SUBJECT_CMP)) {
        *(BOOLEAN *)Value = TRUE;
      } else {
        *(BOOLEAN *)Value = FALSE;
      }
      break;

    case SUBJECT_DATA:
      if ((IsUseLocalGuestLogin() == FALSE) || (SUBJECT_CMP == ((~cmpType) & SUBJECT_CMP))) {
        *ActionRequest = EFI_BROWSER_ACTION_HIDE;
      } else {
        str16 = GetCmpDataByType(SUBJECT_CMP);
        if (str16 != NULL) {
          StrnCpy((CHAR16*)Value, str16, MAX_INPUT_AREA_SIZE);
        }
      }
      break;
    default:
      break;
    }
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------
