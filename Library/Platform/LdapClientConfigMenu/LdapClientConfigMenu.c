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
#include <Library/Lib/History.h>
#include <Library/LdapClientConfigMenu/LdapClientConfigMenu.h>

#include <Protocol/LdapAuthDxe.h>
#include <Protocol/HistoryHandlerProto.h>

#include <CommonGuiSetup.h>

static LDAP_AUTH_PROTOCOL *pLdapAuthProtocol;

static EFI_GUID LdapMenuFormGuid;  // GUID of our form

extern EFI_GUID gPcdHostsVarGuid;

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
/*! \brief Check a requirement of a making of HOSTS variable */
/*! If ldapserver address and ldapserver name have been entered we have to create
    a hosts file*/
/*! \param[in] A pointer to the LdapClientConfig structure */
/*! \retval TRUE if Need to make hosts file
    \retval FALSE if no need to make hosts file */
//------------------------------------------------------------------------------
static
BOOLEAN
IsNeedToMakeHosts(
  IN LDAP_CONFIG_OP* LdapConfig
)
{
  if (LdapConfig->GetLdapServerAddr() != NULL &&
      LdapConfig->GetSizeOfLdapServerName() > 0 &&
      LdapConfig->GetLdapServerName() != NULL)
    return TRUE;
  else
    return FALSE;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set Hosts variable */
/*! Host ip address is a LdapServerAddr, Host name is a LdapServerName */
/*! \param[in] A pointer to the LdapClientConfig structure */
//------------------------------------------------------------------------------
static
EFI_STATUS
SaveHostsVariable( 
  IN LDAP_CONFIG_OP* LdapConfig
)
{
  UINTN Size = 0;
  EFI_STATUS Status;
  CHAR8 *varBuf = NULL, *serverName = NULL, *startBuf = NULL;
  CHAR8 addrC8[STRING_ADDR_LEN + 1];

  if (LdapConfig->GetLdapServerAddr() == NULL ||
      LdapConfig->GetSizeOfLdapServerName() == 0 ||
      LdapConfig->GetLdapServerName() == NULL) {
    return EFI_ABORTED;
  }

  ZeroMem(addrC8, sizeof(addrC8));

  Size = StrLen(LdapConfig->GetLdapServerAddr());
  Size += AsciiStrLen("   ");
  Size += StrLen(LdapConfig->GetLdapServerName());
  Size += AsciiStrLen("\n");
  Size += 2*sizeof(CHAR8);

  varBuf = AllocateZeroPool(Size);
  startBuf = varBuf;

  serverName = AllocateZeroPool(StrSize(LdapConfig->GetLdapServerName()) + sizeof(CHAR8));
  UnicodeStrToAsciiStr(LdapConfig->GetLdapServerName(), serverName);

  UnicodeStrToAsciiStr(LdapConfig->GetLdapServerAddr(), addrC8);
  CopyMem(varBuf, addrC8, sizeof(addrC8));
  varBuf += StrLen(LdapConfig->GetLdapServerAddr());
  CopyMem(varBuf, "   ", AsciiStrLen("   "));
  varBuf += AsciiStrLen("   ");
  CopyMem(varBuf, serverName, StrLen(LdapConfig->GetLdapServerName()));
  varBuf += StrLen(LdapConfig->GetLdapServerName());
  CopyMem(varBuf, "\n", AsciiStrLen("\n"));

  DEBUG((EFI_D_ERROR, "%a.%d: Host: %a\n",
    __FUNCTION__, __LINE__, startBuf));

  Status = gRT->SetVariable (
                  L"Hosts",
                  &gPcdHostsVarGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  Size,
                  startBuf);

  FreePool(serverName);
  FreePool(startBuf);

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Clear Hosts variable */
//------------------------------------------------------------------------------
static
EFI_STATUS
ClearHostsVariable(
  VOID
)
{
  EFI_STATUS Status;
  CHAR8 varBuf[] = "#empty file";

  Status = gRT->SetVariable (
                  L"Hosts",
                  &gPcdHostsVarGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  sizeof(varBuf),
                  varBuf);
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Initialize Ldap Client Config Menu data */
/*! Most of the init work has been processed by AdvMenuProtocol. However,
    we need to init some private data */
/*! \return Status of the operation */
/*! \retval EFI_LOAD_ERROR Received error to read ldap client config
    \retval EFI_SUCCESS Config has been read successfully */
//------------------------------------------------------------------------------
EFI_STATUS
InitLdapFormData( 
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  CHAR16 *initialName = NULL;
  
  Status = gBS->LocateProtocol (
                  &gLdapAuthDxeProtocolGuid,
                  NULL,
                  (VOID **) &pLdapAuthProtocol
                  );
  if (EFI_ERROR(Status)) {
  DEBUG((EFI_D_ERROR, "%a.%d: pLdapAuthProtocol is not found\n", __FUNCTION__, __LINE__));
   return EFI_LOAD_ERROR;
  }

  if (pLdapAuthProtocol == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d: pLdapAuthProtocol is NULL!! \n",
      __FUNCTION__, __LINE__));
    return EFI_LOAD_ERROR;
  }

  if (isFirstTime == TRUE) {
    This->GetTokenStrForEntryByQuestionTd(This, ENTER_ROOTPW, &initialName);
    if (initialName != NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d: %s\n", __FUNCTION__, __LINE__, initialName));
      MakeAdminPasswordNames(This, initialName);
      FreePool(initialName);
      isFirstTime = FALSE;
    }
  }

  Status = pLdapAuthProtocol->LdapConfigOp.ReadLdapConfig();
  if (!EFI_ERROR(Status)) {
    if (pLdapAuthProtocol->LdapConfigOp.GetSizeOfLdapRootpw() > 0)
      This->SetTokenStrForEntryByQuestionTd(This, ENTER_ROOTPW, fillAdminPasswordTitle);
    else
      This->SetTokenStrForEntryByQuestionTd(This, ENTER_ROOTPW, emptyAdminPasswordTitle);
  }
  else
  {
      DEBUG((EFI_D_ERROR, "%a.%d: ReadLdapConfig error \n", __FUNCTION__, __LINE__));
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Delete Ldap Client Config Menu data */
//------------------------------------------------------------------------------
VOID
DeleteLdapFormData( VOID )
{
  if (NULL == pLdapAuthProtocol ) {
    DEBUG((EFI_D_ERROR, "%a.%d: pLdapAuthProtocol is NULL!! \n",
        __FUNCTION__, __LINE__));
    return;
  }
      
  pLdapAuthProtocol->LdapConfigOp.DeleteLdapConfig();

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Process element's actions from Ldap Client Configuration Menu */
/*! \param[in] *This Pointer to ADV_MENU_HANDLER_PROTOCOL
    \paran[in] QuestionId ID of element, which action we need to process
    \param[in] *Value Pointer to the value of the element's data
    \param[out] *ActionRequest an action request to the top level of the AdvMenu */
/*! \return Status of the operation */
/*! \retval EFI_SUCCESS Success
    \retval EFI_LOAD_ERROR Error to load LdapAuthProtocol 
    \retval EFI_INVALID_PARAMETER Value for the element is NULL */
//------------------------------------------------------------------------------
EFI_STATUS
ProcessLdapFormAction(
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
  
  if (NULL == pLdapAuthProtocol ) {
    DEBUG((EFI_D_ERROR, "%a.%d: pLdapAuthProtocol is NULL!! \n",
      __FUNCTION__, __LINE__));
    return EFI_LOAD_ERROR;
  }
  
  // Check the Value if the action isn't for the Save Ldap Config action element
  if (QuestionId == SAVE_LDAP_CLIENT_CONFIG ||
      QuestionId == USE_LDAP_AUTORIZATION ||
      QuestionId == USE_TLS) {
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
  case USE_LDAP_AUTORIZATION:
    if (FALSE == Value->b)
      pLdapAuthProtocol->LdapConfigOp.SetLdapAuthUsageStatus(NOT_USE_LDAP_AUTH);
    else
      pLdapAuthProtocol->LdapConfigOp.SetLdapAuthUsageStatus(USE_LDAP_AUTH);
    break;
  case USE_TLS:
    if (FALSE == Value->b)
      pLdapAuthProtocol->LdapConfigOp.SetTLSUsage(FALSE);
    else
      pLdapAuthProtocol->LdapConfigOp.SetTLSUsage(TRUE);
    break;
  case ENTER_LDAP_SERVER_IP_ADDR:
    if (pLdapAuthProtocol->LdapConfigOp.SetLdapServerAddr(recvString16) != EFI_SUCCESS) {
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
      ShowErrorPopup(This->GetHiiHandle(This), 
        HiiGetString(This->GetHiiHandle(This), This->GetStringId(INCORRECT_IP_ADDRESS),
        NULL));
    }
    break;
  case ENTER_LDAP_SERVER_PORT:
    DEBUG((EFI_D_ERROR, "%a.%d: recvString16: %s\n", __FUNCTION__, __LINE__, recvString16));
    if (StrLen (recvString16) > 5) {
      // wrong string length
      ldapPort = 0;
    } else {
      ldapPort = StrDecimalToUintn(recvString16);
    }
    if (ldapPort >= 1 && ldapPort <= 65535) {
      if (pLdapAuthProtocol->LdapConfigOp.SetLdapPort(ldapPort) != EFI_SUCCESS) {
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
  case ENTER_LDAP_SERVER_NAME:
    if (pLdapAuthProtocol->LdapConfigOp.SetLdapServerName(recvString16) != EFI_SUCCESS) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error to set name!!!\n", __FUNCTION__, __LINE__));
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
    }
    break;
  case ENTER_SUFFIX:
    DEBUG((EFI_D_ERROR, "%a.%d: SetLdapSuffix(recvString16)\n", __FUNCTION__, __LINE__));
    if (pLdapAuthProtocol->LdapConfigOp.SetLdapSuffix(recvString16) != EFI_SUCCESS) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error to set suffix!!!\n", __FUNCTION__, __LINE__));
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
    }
    break;
  case ENTER_ROOTDN:
    if (pLdapAuthProtocol->LdapConfigOp.SetLdapRootdn(recvString16) != EFI_SUCCESS) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error to set rootdn!!!\n", __FUNCTION__, __LINE__));
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
    }
    break;
  case ENTER_ROOTPW:
    if (pLdapAuthProtocol->LdapConfigOp.SetLdapRootpw(recvString16) != EFI_SUCCESS) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error\n", __FUNCTION__, __LINE__));
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
    } else {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    }

    if (pLdapAuthProtocol->LdapConfigOp.GetSizeOfLdapRootpw() > 0)
      This->SetTokenStrForEntryByQuestionTd(This, ENTER_ROOTPW, fillAdminPasswordTitle);
    else
      This->SetTokenStrForEntryByQuestionTd(This, ENTER_ROOTPW, emptyAdminPasswordTitle);

    break;
  case ENTER_LDAP_PC_BASE:
    if (pLdapAuthProtocol->LdapConfigOp.SetLdapPCBase(recvString16) != EFI_SUCCESS) {
      DEBUG((EFI_D_ERROR, "%a.%d: Error to set pcBase\n", __FUNCTION__, __LINE__));
      HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
    }
    break;
  case SAVE_LDAP_CLIENT_CONFIG:
    Status = pLdapAuthProtocol->LdapConfigOp.SaveLdapConfig();
    {
      EFI_STATUS St;
      HISTORY_HANDLER_PROTOCOL  *HistoryHandlerProtocol;
      St = gBS->LocateProtocol (&gHistoryHandlerProtocolGuid, NULL, 
          (VOID **) &HistoryHandlerProtocol);
      if (!EFI_ERROR (St)) {
        if (HistoryHandlerProtocol != NULL) {
          HistoryHandlerProtocol->AddRecord(
            HistoryHandlerProtocol,
            HEVENT_LDAP_CFG_CHANGE, 
            EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
            EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
        }
      }
    }
    if (Status == EFI_SUCCESS) {
      if (IsNeedToMakeHosts(&pLdapAuthProtocol->LdapConfigOp) == TRUE) {
        SaveHostsVariable(&pLdapAuthProtocol->LdapConfigOp);
      } else {
        ClearHostsVariable();
      }
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
    \retval EFI_LOAD_ERROR Error to load LdapAuthProtocol
    \retval EFI_INVALID_PARAMETER Value for the element is NULL */
//------------------------------------------------------------------------------
EFI_STATUS
FillLdapFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
)
{
  CHAR16        *recvString16 = (CHAR16*)Value;

  DEBUG((EFI_D_ERROR, "%a.%d: QuestionId: %d\n",
      __FUNCTION__, __LINE__, QuestionId));

  if (NULL == pLdapAuthProtocol ) {
    DEBUG((EFI_D_ERROR, "%a.%d: pLdapAuthProtocol is NULL!! \n",
        __FUNCTION__, __LINE__));
    return EFI_LOAD_ERROR;
  }

  if (recvString16 == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: Value = NULL!! \n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
      
  switch(QuestionId){
  case USE_LDAP_AUTORIZATION:
    if (pLdapAuthProtocol->LdapConfigOp.GetLdapAuthUsageStatus() == 
        NOT_USE_LDAP_AUTH) {
        *(BOOLEAN *)Value = FALSE;
    } else {
        *(BOOLEAN *)Value = TRUE;
    }
    break;

  case USE_TLS:
    if (pLdapAuthProtocol->LdapConfigOp.IsUseTLS() == FALSE) {
      *(BOOLEAN *)Value = FALSE;
    } else {
      *(BOOLEAN *)Value = TRUE;
    }
    break;

  case ENTER_LDAP_SERVER_IP_ADDR:
    StrnCpy(recvString16, pLdapAuthProtocol->LdapConfigOp.GetLdapServerAddr(), 
      MAX_INPUT_AREA_SIZE);
    break;

  case ENTER_LDAP_SERVER_PORT:
    UnicodeValueToString(recvString16,
                         0, 
                         pLdapAuthProtocol->LdapConfigOp.GetLdapServerPort(),
                         MAX_PORT_NUM_SIZE);
    break;

  case ENTER_LDAP_SERVER_NAME:
    if(pLdapAuthProtocol->LdapConfigOp.GetSizeOfLdapServerName() > 0) {
      StrnCpy(recvString16, pLdapAuthProtocol->LdapConfigOp.GetLdapServerName(), 
        MAX_INPUT_AREA_SIZE);
    }
    break;

  case ENTER_SUFFIX:
    if (pLdapAuthProtocol->LdapConfigOp.GetSizeOfLdapSuffix() > 0) {
      StrnCpy(recvString16, pLdapAuthProtocol->LdapConfigOp.GetLdapSuffix(), 
        MAX_INPUT_AREA_SIZE);
    }
    break;

  case ENTER_ROOTDN:
    if (pLdapAuthProtocol->LdapConfigOp.GetSizeOfLdapRootdn() > 0) {
      StrnCpy(recvString16, pLdapAuthProtocol->LdapConfigOp.GetLdapRootdn(),
        MAX_INPUT_AREA_SIZE);
    }
    break;

  case ENTER_ROOTPW:
    if (pLdapAuthProtocol->LdapConfigOp.GetSizeOfLdapRootpw() > 0) {
        // Make hash of password
        // Display hash function
    }
    break;

  case ENTER_LDAP_PC_BASE:
    if (pLdapAuthProtocol->LdapConfigOp.GetSizeOfLdapPCBase() > 0) {
      StrnCpy(recvString16, pLdapAuthProtocol->LdapConfigOp.GetLdapPCBase(),
        MAX_INPUT_AREA_SIZE);
    }
    break;

  default:
    // NOP. Unknown QuestionId.
    break;
  }

  if (pLdapAuthProtocol->LdapConfigOp.GetLdapAuthUsageStatus() == NOT_USE_LDAP_AUTH &&
    QuestionId != USE_LDAP_AUTORIZATION) {
    // No need to hide USE_LDAP_AUTORIZATION element
    *ActionRequest = EFI_BROWSER_ACTION_HIDE;
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------
