/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/AdvMenu/AdvMenu.h>
#include <Library/AdvAuthConfigMenu/AdvAuthConfigMenu.h>
#include <Library/LdapClientConfigMenu/LdapClientConfigMenu.h>
#include <Library/AdvCDPLdapConfigMenu/AdvCDPLdapConfigMenu.h>
#include <Library/AdvDiagnosticsConfigMenu/AdvDiagnosticsConfigMenu.h>
#include <Library/TokenViewerLib/AdvTokenViewerMenu.h>
#include <Library/CertViewerLib/AdvCertViewerMenu.h>

#include <Library/AuthModeConfig/AuthModeConfig.h>
#include <Library/RevokeChkConfigLib/RevokeChkConfig.h>
#include <Library/CDPSupportLib/CDPLdapConfig.h>
#include <Library/DiagnosticsConfigLib/DiagnosticsConfig.h>

#include <Protocol/AdvMenuHandlerProto.h>
#include <Library/BIOSLib/Locks.h>
#include <CommonGuiSetup.h>


STATIC EFI_GUID AdvMenuFormGuid            = ADV_MENU_FORM_GUID;
STATIC EFI_GUID LdapMenuFormGuid           = LDAP_MENU_FORM_GUID;
STATIC EFI_GUID AdvAuthConfigMenuGuid      = ADV_AUTH_MENU_FORM_GUID;
STATIC EFI_GUID AdvCDPLdapConfigMenuGuid   = ADV_CDP_LDAP_CONFIG_MENU_FORM_GUID;
STATIC EFI_GUID AdvTokenViewerMenuGuid     = ADV_TOKEN_VIEWER_FORM_GUID;
STATIC EFI_GUID AdvCertViewerMenuGuid      = ADV_CERT_VIEWER_FORM_GUID;
STATIC EFI_GUID AdvDiagnosticsConfigMenuGuid    = ADV_DIAGNOSTICS_CONFIG_MENU_GUID;

EFI_STATUS
ReadAdvMainMenuConf ( 
  IN EFI_QUESTION_ID QuestionId
  )
{
  switch(QuestionId) {
  case ADV_MENU_FORM_PIN_ID: // pin code
    break;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
FillAdvMainFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  CHAR16  *recvString16 = (CHAR16*)Value;
  CHAR16  TmpStr[255];

  if (recvString16 == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: Value = NULL!! \n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  switch(QuestionId) {
  case ADV_MENU_FORM_PIN_ID: //pin code
    {
      EFI_STATUS Status;
      UINT32 Val;

      Status = LocksGetWrongPinTreshold (&Val);
      if (EFI_ERROR(Status)) {
        break;
      }
      UnicodeSPrint(TmpStr, sizeof(TmpStr), L"%d", Val);
      StrnCpy(recvString16, TmpStr, MAX_INPUT_AREA_SIZE);
    }
    break;

  default:
    // NOP. Unknown QuestionId.
    break;
  }

  return EFI_SUCCESS;
}


//------------------------------------------------------------------------------
/*! \brief Calback function, calling for each element on the new form*/
/*! \param[in] *This Pointer to ADV_MENU_HANDLER_PROTOCOL
    \param[in] Action
    \param[in] QuestionId Id of the deleting element on the deleting form
    \param[in] Type
    \param[in] *Value *Value Pointer to the value of the element's data
    \param[out] *ActionRequest an action request to the top level of the AdvMenu
    \paran[in] QuestionId Id of the element on the new form */
//------------------------------------------------------------------------------
EFI_STATUS
AdvMenuStartCallback(
   IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
   IN EFI_BROWSER_ACTION Action,
   IN EFI_QUESTION_ID QuestionId,
   IN UINT8 Type,
   IN EFI_IFR_TYPE_VALUE *Value,
   OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  EFI_GUID   guid;

  This->GetCurrentFormGuid(This, &guid);

  if (CompareGuid(&guid, &AdvAuthConfigMenuGuid) == TRUE) {
    ResetAuthModeConfig ();
    ReadAuthModeConfig();
  }

  if (CompareGuid(&guid, &AdvRevokeChkConfigMenuGuid) == TRUE) {
    ResetReadRevokeChkConfig ();
    ReadRevokeChkConfig();
  }

  if (CompareGuid(&guid, &AdvCDPLdapConfigMenuGuid) == TRUE) {
    ResetCDPLdapConfig ();
    InitCDPLdapConfigFormData(This);
    ReadCDPLdapConfig();
  }

  if (CompareGuid(&guid, &AdvDiagnosticsConfigMenuGuid) == TRUE) {
    ResetDiagnosticsConfig ();
    ReadDiagnosticsConfig();
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Calback function, calling for each deleting element on the deleting form */
/*! \param[in] *This Pointer to ADV_MENU_HANDLER_PROTOCOL
    \paran[in] QuestionId Id of the deleting element on the deleting form
    \param[in] Action
    \param[in] Type
    \param[in] *Value *Value Pointer to the value of the element's data
    \param[out] *ActionRequest an action request to the top level of the AdvMenu
*/
//------------------------------------------------------------------------------
EFI_STATUS
AdvMenuExitCallback(
   IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
   IN EFI_BROWSER_ACTION Action,
   IN EFI_QUESTION_ID QuestionId,
   IN UINT8 Type,
   IN EFI_IFR_TYPE_VALUE *Value,
   OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest 
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  EFI_GUID guid;

  if (This->IsGotoAction(This) != TRUE)
  {
    This->GetCurrentFormGuid(This, &guid);

    if (CompareGuid(&guid, &AdvMenuFormGuid) == TRUE)
    {
      // NOP. No need to do anything. Go back from Advanced menu (the top of a menu tree)
    }
    else if (CompareGuid(&guid, &LdapMenuFormGuid) == TRUE)
    {
      if (PcdGetBool(UseLdapAuth) == TRUE) {
        // Exit to the Advanced menu from the Ldap Client Configuration Menu
        DeleteLdapFormData();
        This->SelectFormByGuid(This, &AdvMenuFormGuid);
        *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
      }
    }
    else if (CompareGuid(&guid, &AdvAuthConfigMenuGuid) == TRUE)
    {
      DeleteAuthModeFormData();
      This->SelectFormByGuid(This, &AdvMenuFormGuid);
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
    }
    else if (CompareGuid(&guid, &AdvRevokeChkConfigMenuGuid) == TRUE)
    {
      DeleteRevokeChkConfigFormData();
      This->SelectFormByGuid(This, &AdvMenuFormGuid);
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
    }
    else if (CompareGuid(&guid, &AdvCDPLdapConfigMenuGuid) == TRUE) {
      DeleteCDPLdapConfigFormData();
      This->SelectFormByGuid(This, &AdvMenuFormGuid);
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
    }
    else if (CompareGuid(&guid, &AdvRemoteCfgTlsConfigMenuGuid) == TRUE)
    {
      DeleteRemoteCfgTlsFormData();
      This->SelectFormByGuid(This, &AdvMenuFormGuid);
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
    }
    else if (CompareGuid(&guid, &AdvDiagnosticsConfigMenuGuid) == TRUE)
    {
      This->SelectFormByGuid(This, &AdvMenuFormGuid);
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
      DeleteDiagnosticsConfigFormData();
    }
    else
    {
      DEBUG((EFI_D_ERROR, "%a.%d: Unknown form guid\n", __FUNCTION__, __LINE__));
      Status = EFI_NOT_FOUND;
    }
   }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief This function handles actions by form elements */
/*! \param[in] *This Pointer to ADV_MENU_HANDLER_PROTOCOL
    \paran[in] QuestionId ID of element, which has generated the action
    \param[in] Action
    \param[in] Type
    \param[in] *Value *Value Pointer to the value of the element's data
    \param[out] *ActionRequest an action request to the top level of the AdvMenu
*/
//------------------------------------------------------------------------------
EFI_STATUS
AdvMenuActionCallback(
   IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
   IN EFI_BROWSER_ACTION Action,
   IN EFI_QUESTION_ID QuestionId,
   IN UINT8 Type,
   IN EFI_IFR_TYPE_VALUE *Value,
   OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest 
   )
{
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_GUID guid;
    
    This->GetCurrentFormGuid(This, &guid);
    
    if (CompareGuid(&guid, &AdvMenuFormGuid) == TRUE) {
        // Process element's actions from Advanced Menu
        switch(QuestionId){
        case LAUNCH_LDAP_CLIENT_CONFIG_MENU:
            This->SelectFormByGuid(This, &LdapMenuFormGuid);
            if (InitLdapFormData(This) != EFI_SUCCESS)
            {
                This->SelectFormByGuid(This, &AdvMenuFormGuid);
                ShowErrorPopup(This->GetHiiHandle(This),
                    HiiGetString(This->GetHiiHandle(This), 
                    STRING_TOKEN(STR_LDAP_CONFIG_ERROR), NULL));
            } else {
                *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
            }
            break;
        case ADV_AUTH_MENU_FORM_ID:
            This->SelectFormByGuid(This, &AdvAuthConfigMenuGuid);
            *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
            break;
        case ADV_REVOKE_CHECK_CONFIG_MENU_ID:
            This->SelectFormByGuid(This, &AdvRevokeChkConfigMenuGuid);
            *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
            break;

        case ADV_MENU_FORM_PIN_ID:
          if (Action == EFI_BROWSER_ACTION_RETRIEVE) {
            Status = FillAdvMainFormElement (
                        This, 
                        QuestionId, 
                        Value, 
                        ActionRequest);
          } else if (Action == EFI_BROWSER_ACTION_CHANGING) {
            if (Value && Value->string) {
              UINT32 Val;
              CHAR8 Str8[255];
              CHAR16 *Str = HiiGetString(
                              This->GetHiiHandle (This), 
                              Value->string, 
                              NULL);

              UnicodeStrToAsciiStr(Str, Str8);
              Str8[7] = 0;		// миллиона должно хватить

              Val = (UINT32)(AsciiStrDecimalToUintn(Str8) & 0x00FFFFFFFF);
              if (Val >= LOCK_VAR_WRONG_PIN_TRESHOLD_MIN && 
                  Val <= LOCK_VAR_WRONG_PIN_TRESHOLD_MAX) {
                LocksSetWrongPinTreshold (Val);
              } else {
                This->SelectFormByGuid(This, &AdvMenuFormGuid);
                *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
              }
            }
          }
          break;

        case ADV_MENU_FORM_INT_TEST_ID:
          This->SelectFormByGuid(This, &AdvMenuFormGuid);
          *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
          break;

        case ADV_CDP_LDAP_CONFIG_MENU_FORM_ID:
          This->SelectFormByGuid(This, &AdvCDPLdapConfigMenuGuid);
          *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
          break;

        case ADV_REMOTE_CFG_TLS_CONFIG_MENU_FORM_ID:
          This->SelectFormByGuid(This, &AdvRemoteCfgTlsConfigMenuGuid);
          if (InitRemoteCfgTlsFormData(This) != EFI_SUCCESS) {
            This->SelectFormByGuid(This, &AdvMenuFormGuid);
            ShowErrorPopup(This->GetHiiHandle(This),
                           HiiGetString(This->GetHiiHandle(This), 
                           STRING_TOKEN(STR_REMOTE_CFG_TLS_CONFIG_ERROR), 
                           NULL));
          } else {
            *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
          }
          break;
        case ADV_DIAGNOSTICS_CONFIG_MENU_ID:
          This->SelectFormByGuid(This, &AdvDiagnosticsConfigMenuGuid);
          *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
          break;
        default:
            break;
        }
    } else if (CompareGuid(&guid, &LdapMenuFormGuid) == TRUE) {
        if (PcdGetBool(UseLdapAuth) == TRUE) {
            if (Action == EFI_BROWSER_ACTION_RETRIEVE) {
                Status = FillLdapFormElement(This, QuestionId, Value, ActionRequest);
            } else if (Action == EFI_BROWSER_ACTION_CHANGING)
                Status = ProcessLdapFormAction(This, QuestionId, Value, ActionRequest);
                if (*ActionRequest == EFI_BROWSER_ACTION_REQUEST_EXIT) {
                    DeleteLdapFormData();
                    This->SelectFormByGuid(This, &AdvMenuFormGuid);
                    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
                }
        }
    } else if (CompareGuid(&guid, &AdvAuthConfigMenuGuid) == TRUE) {
        if (Action == EFI_BROWSER_ACTION_RETRIEVE) {
             Status = FillAuthConfigFormElement(This, QuestionId, Value, ActionRequest);
        } else if (Action == EFI_BROWSER_ACTION_CHANGING) {
            Status = ProcessAuthConfigFormElement(This, QuestionId, Value, ActionRequest);
            if (*ActionRequest == EFI_BROWSER_ACTION_REQUEST_EXIT) {
                    DeleteAuthModeFormData();
                    This->SelectFormByGuid(This, &AdvMenuFormGuid);
                    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
            }
        }
    } else if (CompareGuid(&guid, &AdvRevokeChkConfigMenuGuid) == TRUE) {
        if (Action == EFI_BROWSER_ACTION_RETRIEVE) {
             Status = FillRevokeChkConfigFormElement(This, QuestionId, Value, ActionRequest);
        } else if (Action == EFI_BROWSER_ACTION_CHANGING) {
            Status = ProcessRevokeChkConfigFormElement(This, QuestionId, Value, ActionRequest);
            if (*ActionRequest == EFI_BROWSER_ACTION_REQUEST_EXIT) {
                    DeleteRevokeChkConfigFormData();
                    This->SelectFormByGuid(This, &AdvMenuFormGuid);
                    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
            }
        }
    } else if (CompareGuid(&guid, &AdvCDPLdapConfigMenuGuid) == TRUE) {
      if (Action == EFI_BROWSER_ACTION_RETRIEVE) {
           Status = FillCDPLdapConfigFormElement(This, QuestionId, Value, ActionRequest);
      } else if (Action == EFI_BROWSER_ACTION_CHANGING) {
          Status = ProcessCDPLdapConfigFormAction(This, QuestionId, Value, ActionRequest);
          if (*ActionRequest == EFI_BROWSER_ACTION_REQUEST_EXIT) {
                  DeleteCDPLdapConfigFormData();
                  This->SelectFormByGuid(This, &AdvMenuFormGuid);
                  *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
          }
      }
    } else if (CompareGuid(&guid, &AdvRemoteCfgTlsConfigMenuGuid) == TRUE) {
      if (Action == EFI_BROWSER_ACTION_RETRIEVE) {
           Status = FillRemoteCfgTlsFormElement(This, QuestionId, Value, ActionRequest);
      } else if (Action == EFI_BROWSER_ACTION_CHANGING) {
          Status = ProcessRemoteCfgTlsFormAction(This, QuestionId, Value, ActionRequest);
          if (*ActionRequest == EFI_BROWSER_ACTION_REQUEST_EXIT) {
                  DeleteRemoteCfgTlsFormData();
                  This->SelectFormByGuid(This, &AdvMenuFormGuid);
                  *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
          }
      }
    } else if (CompareGuid(&guid, &AdvDiagnosticsConfigMenuGuid) == TRUE) {
      if (Action == EFI_BROWSER_ACTION_RETRIEVE) {
          Status = FillDiagnosticsConfigFormElement(This, QuestionId, Value, ActionRequest);
      } else if (Action == EFI_BROWSER_ACTION_CHANGING) {
          Status = ProcessDiagnosticsConfigFormElement(This, QuestionId, Value, ActionRequest);
          if (*ActionRequest == EFI_BROWSER_ACTION_REQUEST_EXIT) {
            DeleteDiagnosticsConfigFormData();
            This->SelectFormByGuid(This, &AdvMenuFormGuid);
            *ActionRequest = EFI_BROWSER_ACTION_REQUEST_GOTO;
          }
      }
    } else if (CompareGuid(&guid, &AdvTokenViewerMenuGuid) == TRUE) {
      if (Action == EFI_BROWSER_ACTION_RETRIEVE) {
           ;//Status = FillTokenViewerFormElement(This, QuestionId, Value, ActionRequest);
      } else if (Action == EFI_BROWSER_ACTION_CHANGING) {
          Status = ProcessTokenViewerFormElement(This, QuestionId, Value, ActionRequest);
      }
    } else if (CompareGuid(&guid, &AdvCertViewerMenuGuid) == TRUE) {
      if (Action == EFI_BROWSER_ACTION_RETRIEVE) {
           ;//Status = FillCertViewerFormElement(This, QuestionId, Value, ActionRequest);
      } else if (Action == EFI_BROWSER_ACTION_CHANGING) {
          Status = ProcessCertViewerFormElement(This, QuestionId, Value, ActionRequest);
      }
    } else {
        DEBUG((EFI_D_ERROR, "%a.%d: Unknown form guid\n", __FUNCTION__, __LINE__));
    }
    
    return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Register callback functions for the AdvMenu */
/*! \param[in] Null-terminated list of available strings Ids. You have to use it to make
     multilanguage popups messages */
//------------------------------------------------------------------------------
EFI_STATUS
RegisterAdvMenu(EFI_STRING_ID *idList)
{
    EFI_STATUS Status = EFI_SUCCESS;
    ADV_MENU_HANDLER_PROTOCOL *pAdvMenuHandlerProto;
    
    Status = gBS->LocateProtocol ( &gAdvMenuHandlerProtocolGuid,
                    NULL, (VOID**)&pAdvMenuHandlerProto );

    if (EFI_ERROR(Status)) {
        DEBUG ((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
        __FUNCTION__, __LINE__, Status));
    return Status;
    }
    
    
    pAdvMenuHandlerProto->RegStartCallback( pAdvMenuHandlerProto, AdvMenuStartCallback );
    pAdvMenuHandlerProto->RegActionCallback( pAdvMenuHandlerProto, AdvMenuActionCallback );
    pAdvMenuHandlerProto->RegExitCallback( pAdvMenuHandlerProto, AdvMenuExitCallback );
    
    pAdvMenuHandlerProto->SetStringIdList(idList);
    
    return Status;
}
//------------------------------------------------------------------------------
