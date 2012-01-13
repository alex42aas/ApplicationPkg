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
#include <Library/BaseLib.h>
#include <Library/BIOSLib/History.h>
#include <Library/AdvCDPLdapConfigMenu/AdvCDPLdapConfigMenu.h>

#include <Library/CDPSupportLib/CDPLdapConfig.h>

#include <Protocol/HistoryHandlerProto.h>

#include <CommonGuiSetup.h>

static BOOLEAN isFirstTime = TRUE;
static CHAR16 *emptyAdminPasswordTitle;  // name of empty password GUI element
static CHAR16 *fillAdminPasswordTitle;   // name of filled password GUI element

//------------------------------------------------------------------------------
/*! \brief Make titles for the admin password GUI element */
//------------------------------------------------------------------------------
static
VOID
MakeAdminPasswordNames(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN CHAR16 *initialName
  )
{
  CHAR16 *setStr, *notSetStr;
  if (initialName == NULL)
    return;

  if (fillAdminPasswordTitle != NULL)
    FreePool(fillAdminPasswordTitle);
  if (emptyAdminPasswordTitle != NULL)
    FreePool(emptyAdminPasswordTitle);

  setStr = HiiGetString(This->GetHiiHandle(This), This->GetStringId(PASSWORD_SET), NULL);
  if (setStr != NULL) {
    fillAdminPasswordTitle = AllocateZeroPool(StrLen(initialName)*sizeof(CHAR16) + StrSize(setStr));
    if (fillAdminPasswordTitle != NULL) {
      StrCpy(fillAdminPasswordTitle, initialName);
      StrCpy(fillAdminPasswordTitle + StrLen(initialName), setStr);
    }
  }

  notSetStr = HiiGetString(This->GetHiiHandle(This), This->GetStringId(PASSWORD_NOT_SET), NULL);
  if (notSetStr != NULL) {
    emptyAdminPasswordTitle = AllocateZeroPool(StrLen(initialName)*sizeof(CHAR16) + StrSize(notSetStr));
    if (emptyAdminPasswordTitle != NULL) {
      StrCpy(emptyAdminPasswordTitle, initialName);
      StrCpy(emptyAdminPasswordTitle + StrLen(initialName), notSetStr);
    }
  }

  DEBUG((EFI_D_ERROR, "%a.%d: fillAdminPasswordTitle: %s\n", __FUNCTION__, __LINE__, fillAdminPasswordTitle));
  DEBUG((EFI_D_ERROR, "%a.%d: emptyAdminPasswordTitle: %s\n", __FUNCTION__, __LINE__, emptyAdminPasswordTitle));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Initialize CDP Ldap Config Menu data */
/*! Most of the init work has been processed by AdvMenuProtocol. However,
    we need to init some private data */
/*! \return Status of the operation */
/*! \retval EFI_LOAD_ERROR Received error to read CDP ldap config
    \retval EFI_SUCCESS Config has been read successfully */
//------------------------------------------------------------------------------
EFI_STATUS
InitCDPLdapConfigFormData( 
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  CHAR16 *initialName = NULL;
  
  if (isFirstTime == TRUE) {
    This->GetTokenStrForEntryByQuestionTd(This, ENTER_CDP_LDAP_ROOTPW, &initialName);
    if (initialName != NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d: %s\n", __FUNCTION__, __LINE__, initialName));
      MakeAdminPasswordNames(This, initialName);
      FreePool(initialName);
      isFirstTime = FALSE;
    }
  }

  Status = ReadCDPLdapConfig();
  if (!EFI_ERROR(Status)) {
    if (GetSizeOfCDPLdapRootpw() > 0)
      This->SetTokenStrForEntryByQuestionTd(This, ENTER_CDP_LDAP_ROOTPW, fillAdminPasswordTitle);
    else
      This->SetTokenStrForEntryByQuestionTd(This, ENTER_CDP_LDAP_ROOTPW, emptyAdminPasswordTitle);
  }

  return Status;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Delete CDP Ldap Config Menu data */
//------------------------------------------------------------------------------
VOID
DeleteCDPLdapConfigFormData( 
  VOID
)
{
  DeleteCDPLdapConfig();

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Process element's actions from CDP Ldap Configuration Menu */
/*! \param[in] *This Pointer to ADV_MENU_HANDLER_PROTOCOL
    \paran[in] QuestionId ID of element, which action we need to process
    \param[in] *Value Pointer to the value of the element's data
    \param[out] *ActionRequest an action request to the top level of the AdvMenu */
/*! \return Status of the operation */
/*! \retval EFI_SUCCESS Success
    \retval EFI_INVALID_PARAMETER Value for the element is NULL */
//------------------------------------------------------------------------------
EFI_STATUS
ProcessCDPLdapConfigFormAction(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
)
{
  EFI_STATUS Status = EFI_ABORTED;
  EFI_STRING_ID StrId = Value->string;
  UINTN  ldapPort;
  CHAR16 *recvString16 = NULL;
  
  // Check the Value if the action isn't for the Save Ldap Config action element
  if (QuestionId == SAVE_CDP_LDAP_CONFIG) {
    ; // PASS
  } else {
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
  case ENTER_CDP_LDAP_SERVER_IP_ADDR:
    if (SetCDPLdapServerAddr(recvString16) != EFI_SUCCESS) {
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
      ShowErrorPopup(This->GetHiiHandle(This), 
        HiiGetString(This->GetHiiHandle(This), This->GetStringId(INCORRECT_IP_ADDRESS),
        NULL));
    }
    break;
  case ENTER_CDP_LDAP_SERVER_PORT:
    if (StrLen (recvString16) > 5) {
      // wrong cdp ldap port
      ldapPort = 0;
    } else {
      ldapPort = StrDecimalToUintn(recvString16);
    }
    if (ldapPort >= 1 && ldapPort <= 65535) {
      if (SetCDPLdapPort(ldapPort) != EFI_SUCCESS) {
        DEBUG((EFI_D_ERROR, "%a.%d: Error to set port!!!\n", __FUNCTION__, __LINE__));
        HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
      }
    } else {
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
      ShowErrorPopup(This->GetHiiHandle(This), 
                      HiiGetString(This->GetHiiHandle(This), 
                      This->GetStringId(INCORRECT_TCP_PORT),
                      NULL));
    }
    break;
  case ENTER_CDP_LDAP_SERVER_NAME:
    if (SetCDPLdapServerName(recvString16) != EFI_SUCCESS) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error to set name!!!\n", __FUNCTION__, __LINE__));
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
    }
    break;
  case ENTER_CDP_LDAP_ROOTDN:
    if (SetCDPLdapRootdn(recvString16) != EFI_SUCCESS) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error to set rootdn!!!\n", __FUNCTION__, __LINE__));
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
    }
    break;
  case ENTER_CDP_LDAP_ROOTPW:
    if (SetCDPLdapRootpw(recvString16) != EFI_SUCCESS) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error\n", __FUNCTION__, __LINE__));
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
    } else {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    }

    if (GetSizeOfCDPLdapRootpw() > 0)
      This->SetTokenStrForEntryByQuestionTd(This, ENTER_CDP_LDAP_ROOTPW, fillAdminPasswordTitle);
    else
      This->SetTokenStrForEntryByQuestionTd(This, ENTER_CDP_LDAP_ROOTPW, emptyAdminPasswordTitle);

    break;
  case SAVE_CDP_LDAP_CONFIG:
    Status = SaveCDPLdapConfig();
    {
      EFI_STATUS St;
      HISTORY_HANDLER_PROTOCOL  *HistoryHandlerProtocol;
      St = gBS->LocateProtocol (&gHistoryHandlerProtocolGuid, NULL,
          (VOID **) &HistoryHandlerProtocol);
      if (!EFI_ERROR (St)) {
        if (HistoryHandlerProtocol != NULL) {
          HistoryHandlerProtocol->AddRecord(
            HistoryHandlerProtocol,
            HEVENT_CDP_LDAP_CFG_CHANGE,
            EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
            EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
        }
      }
    }
    if (Status == EFI_SUCCESS) {
      ShowSuccessPopup(This->GetHiiHandle(This),
        HiiGetString(This->GetHiiHandle(This), This->GetStringId(CONFIG_SAVES_SUCCESS),
        NULL));
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    } else {
      ShowErrorPopup(This->GetHiiHandle(This), 
        HiiGetString(This->GetHiiHandle(This), This->GetStringId(CONFIG_SAVES_ERROR),
        NULL));
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
FillCDPLdapConfigFormElement(
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
      
  switch(QuestionId){
  case ENTER_CDP_LDAP_SERVER_IP_ADDR:
    StrnCpy(recvString16, GetCDPLdapServerAddr(), MAX_INPUT_AREA_SIZE);
    break;

  case ENTER_CDP_LDAP_SERVER_PORT:
    UnicodeValueToString(recvString16,
                         0, 
                         GetCDPLdapServerPort(),
                         MAX_PORT_NUM_SIZE);
    break;

  case ENTER_CDP_LDAP_SERVER_NAME:
    if(GetSizeOfCDPLdapServerName() > 0) {
      StrnCpy(recvString16, GetCDPLdapServerName(), MAX_INPUT_AREA_SIZE);
    }
    break;

  case ENTER_CDP_LDAP_ROOTDN:
    if (GetSizeOfCDPLdapRootdn() > 0) {
      StrnCpy(recvString16, GetCDPLdapRootdn(), MAX_INPUT_AREA_SIZE);
    }
    break;

  case ENTER_CDP_LDAP_ROOTPW:
    if (GetSizeOfCDPLdapRootpw() > 0) {

    }
    break;

  default:
    // NOP. Unknown QuestionId.
    break;
  }
  
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

