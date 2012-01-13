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

#include <Library/AdvRemoteCfgTlsConfigMenu/AdvRemoteCfgTlsConfigMenu.h>
#include <CommonGuiSetup.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <Protocol/RemoteCfgTlsProtocol.h>

#define RCT_STATE_MSG_WIDTH 41

STATIC REMOTE_CFG_TLS_PROTOCOL* gRCTP = NULL;
STATIC REMOTE_CFG_TLS_SETTINGS *gRCTSettings = NULL;
STATIC EFI_HII_HANDLE RCTHiiHandle = NULL;

/**
  Init Remote Config TLS Menu data
  
  @retval EFI_LOAD_ERROR          Can't read RemoteCfgTls service settings
  @retval EFI_SUCCESS             Succesfully stopped
**/
EFI_STATUS
InitRemoteCfgTlsFormData( 
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This
  )
{
  EFI_STATUS Status;

  Status = gBS->LocateProtocol(&gRemoteCfgTlsProtocolGuid,
                               NULL,
                               (VOID **)&gRCTP);
  if (EFI_ERROR(Status) || gRCTP == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d LocateProtocol(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    DEBUG ((EFI_D_ERROR, "%a.%d LocateProtocol(): gRCTP = 0x%X\n", __FUNCTION__, __LINE__, gRCTP));
    return EFI_LOAD_ERROR;
  }

  if (gRCTSettings != NULL) {
    FreePool(gRCTSettings);
    gRCTSettings = NULL;
  }

  Status = gRCTP->GetSettings(gRCTP, &gRCTSettings);
  if (EFI_ERROR(Status) || gRCTSettings == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d GetSettings(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    DEBUG ((EFI_D_ERROR, "%a.%d GetSettings(): gRCTSettings = 0x%X\n", __FUNCTION__, __LINE__, gRCTSettings));
    return EFI_LOAD_ERROR;
  }

  RCTHiiHandle = HiiAddPackages(&gRemoteCfgTlsProtocolGuid, NULL, AdvRemoteCfgTlsConfigMenuStrings, NULL);
  if (RCTHiiHandle == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d RCTHiiHandle = 0x%X\n", __FUNCTION__, __LINE__, RCTHiiHandle));
    return EFI_LOAD_ERROR;
  }

  return EFI_SUCCESS;
}

/**
  Delete Remote Config TLS Menu data
**/
VOID
DeleteRemoteCfgTlsFormData(
  VOID
  )
{
  if (gRCTSettings != NULL) {
    FreePool(gRCTSettings);
    gRCTSettings = NULL;
  }
  if (RCTHiiHandle != NULL) {
    HiiRemovePackages(RCTHiiHandle);
    RCTHiiHandle = NULL;
  }
  return;
}

EFI_STRING
GetRemoteCfgTlsStateString(
  EFI_STATUS RCTStatus
  )
{
  if(REMOTE_CFG_TLS_RUNNING_STATUS(RCTStatus)) {
    return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_RUNNING), NULL);
  } else {
    return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_STOPPED), NULL);
  }
}

EFI_STRING
GetRemoteCfgTlsStateErrorString(
  EFI_STATUS RCTStatus
  )
{
  switch(RCTStatus) {
    case EFI_INVALID_PARAMETER:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_INVALID_PARAMETER), NULL);

    case EFI_NOT_FOUND:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_NOT_FOUND), NULL);

    case EFI_OUT_OF_RESOURCES:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_OUT_OF_RESOURCES), NULL);

    case EFI_LOAD_ERROR:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_LOAD_ERROR), NULL);

    case EFI_NO_MAPPING:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_NO_MAPPING), NULL);

    case EFI_UNSUPPORTED:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_UNSUPPORTED), NULL);

    case EFI_ABORTED:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_ABORTED), NULL);

    case EFI_DEVICE_ERROR:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_DEVICE_ERROR), NULL);

    case EFI_PROTOCOL_ERROR:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_PROTOCOL_ERROR), NULL);

    case EFI_TIMEOUT:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_TIMEOUT), NULL);

    case EFI_NO_RESPONSE:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_NO_RESPONSE), NULL);

    case EFI_NOT_STARTED:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_NOT_STARTED), NULL);

    case EFI_ALREADY_STARTED:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_ALREADY_STARTED), NULL);

    case EFI_NOT_READY:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_NOT_READY), NULL);

    case EFI_SUCCESS:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_SUCCESS), NULL);

    default:
      return HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE_UNKNOWN), NULL);
  }
}

VOID
ShowRCTStatusWithMessage(
  EFI_STRING  Message OPTIONAL
  )
{
  EFI_STATUS Status;
  EFI_STATUS RCTStatus, OldRCTStatus;
  CHAR16 EmptyStr[RCT_STATE_MSG_WIDTH];
  CHAR16 Msg1Str[RCT_STATE_MSG_WIDTH];
  CHAR16 Msg2Str[RCT_STATE_MSG_WIDTH];
  EFI_STRING RctStr = NULL, StateStr = NULL, ErrorStr = NULL;

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  CleanKeyBuffer();
  UnicodeSPrint(EmptyStr, RCT_STATE_MSG_WIDTH * sizeof(CHAR16), L"%*s", RCT_STATE_MSG_WIDTH-1, L"");

  RctStr = HiiGetString(RCTHiiHandle, STRING_TOKEN(STR_RCT_STATE), NULL);
  if (RctStr == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d RctStr = 0x%X\n", __FUNCTION__, __LINE__, RctStr));
    return;
  }

  Status = EFI_NOT_FOUND;
  OldRCTStatus = (EFI_STATUS)(UINTN)(-1);
  do {
    RCTStatus = gRCTP->GetCurrentStatus(gRCTP);

    if (RCTStatus != OldRCTStatus || Status == EFI_NOT_FOUND) {
      OldRCTStatus = RCTStatus;
      StateStr = GetRemoteCfgTlsStateString(RCTStatus);
      if (StateStr == NULL) {
        DEBUG ((EFI_D_ERROR, "%a.%d StateStr = 0x%X\n", __FUNCTION__, __LINE__, StateStr));
        break;
      }
      ErrorStr = GetRemoteCfgTlsStateErrorString(RCTStatus);
      if (ErrorStr == NULL) {
        DEBUG ((EFI_D_ERROR, "%a.%d ErrorStr = 0x%X\n", __FUNCTION__, __LINE__, ErrorStr));
        break;
      }

      UnicodeSPrint(Msg1Str, RCT_STATE_MSG_WIDTH * sizeof(CHAR16), L"%s: %s", RctStr, StateStr);
      UnicodeSPrint(Msg2Str, RCT_STATE_MSG_WIDTH * sizeof(CHAR16), L"(%s)", ErrorStr);

      if (Message != NULL) {
        CreatePopUp(EFI_BLACK | EFI_BACKGROUND_GREEN, NULL, 
          EmptyStr, 
          Message,
          EmptyStr, 
          Msg1Str,
          Msg2Str,
          EmptyStr,
          NULL);
      } else {
        CreatePopUp(EFI_WHITE | EFI_BACKGROUND_BLUE, NULL, 
          EmptyStr, 
          Msg1Str,
          Msg2Str,
          EmptyStr,
          NULL);
      }

      FreePool(StateStr);
      StateStr = NULL;
      FreePool(ErrorStr);
      ErrorStr = NULL;
    }

    if(REMOTE_CFG_TLS_RUNNING_STATUS(RCTStatus)) {
      Status = WaitForEscOrEnter1Sec();
    } else {
      WaitForEscOrEnter();
      break;
    }
  } while (Status != EFI_SUCCESS);

  if (RctStr != NULL) {
    FreePool(RctStr);
    RctStr = NULL;
  }
  if (StateStr != NULL) {
    FreePool(StateStr);
    StateStr = NULL;
  }
  if (ErrorStr != NULL) {
    FreePool(ErrorStr);
    ErrorStr = NULL;
  }
}


/**
  Process element's actions from Remote Config TLS Menu
  
  @param  This                    Pointer to ADV_MENU_HANDLER_PROTOCOL
  @param  QuestionId              ID of element, which action we need to process
  @param  Value                   Pointer to the value of the element's data
  @param  ActionRequest           An action request to the top level of the AdvMenu
  
  @retval EFI_INVALID_PARAMETER   Value for the element is NULL
  @retval EFI_LOAD_ERROR          Error to load RemoteCfgTlsProtocol
  @retval EFI_OUT_OF_RESOURCES    Not enough memory
  @retval EFI_SUCCESS             Success
**/
EFI_STATUS
ProcessRemoteCfgTlsFormAction(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  EFI_STATUS Status;
  EFI_STRING_ID StrId = Value->string;
  CHAR16 *recvString16 = NULL;

  DEBUG ((EFI_D_ERROR, "%a.%d: QuestionId: %d\n", __FUNCTION__, __LINE__, QuestionId));
  
  if (gRCTP == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: gRCTP = 0x%X\n", __FUNCTION__, __LINE__, gRCTP));
    return EFI_LOAD_ERROR;
  }
  if (gRCTSettings == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: gRCTSettings = 0x%X\n", __FUNCTION__, __LINE__, gRCTSettings));
    return EFI_LOAD_ERROR;
  }
  
  // Check the Value if the action dosn't need for string
  if (QuestionId != RCT_SERVER_IP_ADDR && QuestionId != RCT_SERVER_PORT && 
      QuestionId != RCT_CTIMEOUT && QuestionId != RCT_ETIMEOUT && QuestionId != RCT_ATTEMPTS) {
    //PASS
  } else {
    if (StrId == (EFI_STRING_ID)0) {
      DEBUG((EFI_D_ERROR, "%a.%d: StrId = 0x%X\n", __FUNCTION__, __LINE__, StrId));
      return EFI_INVALID_PARAMETER;
    }

    recvString16 = HiiGetString(This->GetHiiHandle(This), StrId, NULL);
    if (recvString16 == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d: recvString16 = 0x%X\n", __FUNCTION__, __LINE__, recvString16));
      return EFI_INVALID_PARAMETER;
    }
  }
  
  switch(QuestionId) {
  case RCT_ENABLED:
    if (Value->b == TRUE) {
      gRCTSettings->Flags |= REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED;
    } else {
      gRCTSettings->Flags &= (~REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED);
    }
    break;
  case RCT_TLS_VERSION:
    if (Value->u8 == 0) {
      gRCTSettings->TlsVersion = REMOTE_CFG_USE_TLS_1_0;
    } else if (Value->u8 == 1) {
      gRCTSettings->TlsVersion = REMOTE_CFG_USE_TLS_1_1;
    } else if (Value->u8 == 2) {
      gRCTSettings->TlsVersion = REMOTE_CFG_USE_TLS_1_2;
#ifdef REMOTE_CFG_USE_NO_CRYPTO
    } else if (Value->u8 == 3) {
      gRCTSettings->TlsVersion = REMOTE_CFG_USE_NO_CRYPTO;
#endif
    } else {
      DEBUG((EFI_D_ERROR, "%a.%d: RCT_TLS_VERSION: Value->u8 = 0x%X\n", __FUNCTION__, __LINE__, Value->u8));
    }
    break;
  case RCT_SERVER_IP_ADDR:
    {
      UINT32 NewNameLen = (UINT32)StrLen(recvString16);
      DEBUG((EFI_D_ERROR, "%a.%d: recvString16 = %s\n", __FUNCTION__, __LINE__, recvString16));
      DEBUG((EFI_D_ERROR, "%a.%d: NewNameLen = %d\n", __FUNCTION__, __LINE__, NewNameLen));
      if (NewNameLen > gRCTSettings->ServerNameLen) {//realloc
        REMOTE_CFG_TLS_SETTINGS *SettingsNew;
        SettingsNew = AllocateZeroPool(sizeof(REMOTE_CFG_TLS_SETTINGS) + NewNameLen);
        if (SettingsNew == NULL) {
          DEBUG ((EFI_D_ERROR, "%a.%d AllocateZeroPool(): SettingsNew = 0x%X\n", __FUNCTION__, __LINE__, SettingsNew));
          return EFI_OUT_OF_RESOURCES;
        }
        CopyMem(SettingsNew, gRCTSettings, gRCTSettings->Length);
        FreePool(gRCTSettings);
        gRCTSettings = SettingsNew;
      }
      UnicodeStrToAsciiStr(recvString16, gRCTSettings->ServerName);
      gRCTSettings->ServerNameLen = NewNameLen;
      gRCTSettings->Length = sizeof(REMOTE_CFG_TLS_SETTINGS) + NewNameLen;
    }
    break;
  case RCT_SERVER_PORT:
    {
      UINTN Port = 0;

      if (StrLen (recvString16) < 10) {
        Port = StrDecimalToUintn(recvString16);
      }
      DEBUG ((EFI_D_ERROR, "%a.%d Port == %d\n", __FUNCTION__, __LINE__, Port));
      if (Port >= REMOTE_CFG_TLS_PORT_MIN && Port <= REMOTE_CFG_TLS_PORT_MAX) {
        gRCTSettings->Port = (UINT16)Port;
      } else {
        HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
        ShowErrorPopup(This->GetHiiHandle(This), 
                        HiiGetString(This->GetHiiHandle(This), 
                        This->GetStringId(INCORRECT_TCP_PORT),
                        NULL));
      }
    }
    break;
  case RCT_INFINITE_CTIMEOUT:
    if (Value->u8 == 0) {
      gRCTSettings->TimeoutConnect = REMOTE_CFG_TLS_TIMEOUT_OFF;
    } else if (Value->u8 == 1) {
      if (gRCTSettings->TimeoutConnect == REMOTE_CFG_TLS_TIMEOUT_OFF || 
          gRCTSettings->TimeoutConnect > REMOTE_CFG_TLS_TIMEOUT_CMAX || 
          gRCTSettings->TimeoutConnect < REMOTE_CFG_TLS_TIMEOUT_MIN) {
        DEBUG ((EFI_D_ERROR, "%a.%d gRCTSettings->TimeoutConnect == %d\n", __FUNCTION__, __LINE__, gRCTSettings->TimeoutConnect));
        gRCTSettings->TimeoutConnect = (60*1);//REMOTE_CFG_TLS_DEFAULT_CTIMEOUT
      }
    } else {
      DEBUG((EFI_D_ERROR, "%a.%d: RCT_INFINITE_CTIMEOUT: Value->u8 = 0x%X\n", __FUNCTION__, __LINE__, Value->u8));
    }
    break;
  case RCT_CTIMEOUT:
    {
      UINTN CTimeout = 0;

      if (StrLen (recvString16) < 10) {
        CTimeout = StrDecimalToUintn(recvString16);
      }
      DEBUG ((EFI_D_ERROR, "%a.%d CTimeout == %d\n", __FUNCTION__, __LINE__, CTimeout));
      if (CTimeout >= REMOTE_CFG_TLS_TIMEOUT_MIN && CTimeout <= REMOTE_CFG_TLS_TIMEOUT_CMAX) {
        gRCTSettings->TimeoutConnect = (UINT32)CTimeout;
      } else {
        HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
        ShowErrorPopup(This->GetHiiHandle(This), 
                       HiiGetString(This->GetHiiHandle(This), 
                       This->GetStringId(CONFIG_INCORRECT_VALUE),
                       NULL));
      }
    }
    break;
  case RCT_INFINITE_ETIMEOUT:
    if (Value->u8 == 0) {
      gRCTSettings->TimeoutExchange = REMOTE_CFG_TLS_TIMEOUT_OFF;
    } else if (Value->u8 == 1) {
      if (gRCTSettings->TimeoutExchange == REMOTE_CFG_TLS_TIMEOUT_OFF || 
          gRCTSettings->TimeoutExchange > REMOTE_CFG_TLS_TIMEOUT_EMAX || 
          gRCTSettings->TimeoutExchange < REMOTE_CFG_TLS_TIMEOUT_MIN) {
        DEBUG ((EFI_D_ERROR, "%a.%d gRCTSettings->TimeoutConnect == %d\n", __FUNCTION__, __LINE__, gRCTSettings->TimeoutExchange));
        gRCTSettings->TimeoutExchange = (60*10);//REMOTE_CFG_TLS_DEFAULT_ETIMEOUT
      }
    } else {
      DEBUG((EFI_D_ERROR, "%a.%d: RCT_INFINITE_ETIMEOUT: Value->u8 = 0x%X\n", __FUNCTION__, __LINE__, Value->u8));
    }
    break;
  case RCT_ETIMEOUT:
    {
      UINTN ETimeout = 0;

      if (StrLen (recvString16) < 10) {
        ETimeout = StrDecimalToUintn(recvString16);
      }
      DEBUG ((EFI_D_ERROR, "%a.%d CTimeout == %d\n", __FUNCTION__, __LINE__, ETimeout));
      if (ETimeout >= REMOTE_CFG_TLS_TIMEOUT_MIN && ETimeout <= REMOTE_CFG_TLS_TIMEOUT_EMAX) {
        gRCTSettings->TimeoutExchange = (UINT32)ETimeout;
      } else {
        HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
        ShowErrorPopup(This->GetHiiHandle(This), 
                       HiiGetString(This->GetHiiHandle(This), 
                       This->GetStringId(CONFIG_INCORRECT_VALUE),
                       NULL));
      }
    }
    break;
  case RCT_INFINITE_ATTEMPTS:
    if (Value->u8 == 0) {
      gRCTSettings->Attempts = REMOTE_CFG_TLS_ATTEMPTS_INFINITE;
    } else if (Value->u8 == 1) {
      if (gRCTSettings->Attempts == REMOTE_CFG_TLS_ATTEMPTS_INFINITE || 
          gRCTSettings->Attempts > REMOTE_CFG_TLS_ATTEMPTS_MAX || 
          gRCTSettings->Attempts < REMOTE_CFG_TLS_ATTEMPTS_MIN) {
        DEBUG ((EFI_D_ERROR, "%a.%d gRCTSettings->Attempts == %d\n", __FUNCTION__, __LINE__, gRCTSettings->Attempts));
        gRCTSettings->Attempts = 100;//REMOTE_CFG_TLS_DEFAULT_ATTEMPTS
      }
    } else {
      DEBUG((EFI_D_ERROR, "%a.%d: RCT_INFINITE_ATTEMPTS: Value->u8 = 0x%X\n", __FUNCTION__, __LINE__, Value->u8));
    }
    break;
  case RCT_ATTEMPTS:
    {
      UINTN Attempts = 0;

      if (StrLen (recvString16) < 10) {
        Attempts = StrDecimalToUintn(recvString16);
      }
      DEBUG ((EFI_D_ERROR, "%a.%d Attempts == %d\n", __FUNCTION__, __LINE__, Attempts));
      if (Attempts >= REMOTE_CFG_TLS_ATTEMPTS_MIN && Attempts <= REMOTE_CFG_TLS_ATTEMPTS_MAX) {
        gRCTSettings->Attempts = (UINT32)Attempts;
      } else {
        HiiSetString(This->GetHiiHandle(This), StrId, L"",NULL);
        ShowErrorPopup(This->GetHiiHandle(This), 
                       HiiGetString(This->GetHiiHandle(This), 
                       This->GetStringId(CONFIG_INCORRECT_VALUE),
                       NULL));
      }
    }
    break;
  case RCT_SHOW_STATE:
    ShowRCTStatusWithMessage(NULL);
    break;
  case RCT_SAVE_CONFIG:
    Status = gRCTP->SetSettings(gRCTP, gRCTSettings);
    DEBUG ((EFI_D_ERROR, "%a.%d SetSettings(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    if (Status == EFI_SUCCESS) {
      ShowRCTStatusWithMessage(HiiGetString(This->GetHiiHandle(This), 
                               This->GetStringId(CONFIG_SAVES_SUCCESS),
                               NULL));
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    } else if (Status == EFI_VOLUME_CORRUPTED) {
      ShowErrorPopup(This->GetHiiHandle(This), 
                     HiiGetString(This->GetHiiHandle(This), 
                     This->GetStringId(CONFIG_SETTINGS_UNSUPPORTED),
                     NULL));
    } else {
      ShowErrorPopup(This->GetHiiHandle(This), 
                     HiiGetString(This->GetHiiHandle(This), 
                     This->GetStringId(CONFIG_SAVES_ERROR),
                     NULL));
    }
    break;
  case RCT_APPLY_CONFIG:
    Status = gRCTP->SetSettings(gRCTP, gRCTSettings);
    DEBUG ((EFI_D_ERROR, "%a.%d SetSettings(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    if (Status == EFI_SUCCESS) {
      Status = gRCTP->Stop(gRCTP);
      DEBUG ((EFI_D_ERROR, "%a.%d RCTP: RCTP->Stop = %r\n", __FUNCTION__, __LINE__, Status));
      Status = gRCTP->Start(gRCTP);
      DEBUG ((EFI_D_ERROR, "%a.%d RCTP: RCTP->Start = %r\n", __FUNCTION__, __LINE__, Status));
      ShowRCTStatusWithMessage(HiiGetString(This->GetHiiHandle(This), 
                               This->GetStringId(CONFIG_APPLY_SUCCESS),
                               NULL));
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    } else if (Status == EFI_VOLUME_CORRUPTED) {
      ShowErrorPopup(This->GetHiiHandle(This), 
                     HiiGetString(This->GetHiiHandle(This), 
                     This->GetStringId(CONFIG_SETTINGS_UNSUPPORTED),
                     NULL));
    } else {
      ShowErrorPopup(This->GetHiiHandle(This), 
                     HiiGetString(This->GetHiiHandle(This), 
                     This->GetStringId(CONFIG_SAVES_ERROR),
                     NULL));
    }
    break;
  default:
    // NOP. Unknown QuestionId.
    break;
  }
  
  return EFI_SUCCESS;
}

/**
  Set a data to the Value of the element
  
  @param  This                    Pointer to ADV_MENU_HANDLER_PROTOCOL
  @param  QuestionId              ID of element, which Value we want to set
  @param  Value                   Pointer to the value of the element's data
  @param  ActionRequest           An action request to the top level of the AdvMenu
  
  @retval EFI_INVALID_PARAMETER   Value for the element is NULL
  @retval EFI_LOAD_ERROR          Error to load RemoteCfgTlsProtocol 
  @retval EFI_SUCCESS             Success
**/
EFI_STATUS
FillRemoteCfgTlsFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  CHAR16 *recvString16 = (CHAR16*)Value;

  DEBUG ((EFI_D_ERROR, "%a.%d: QuestionId: %d\n", __FUNCTION__, __LINE__, QuestionId));

  if (gRCTP == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: gRCTP = 0x%X\n", __FUNCTION__, __LINE__, gRCTP));
    return EFI_LOAD_ERROR;
  }
  if (gRCTSettings == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: gRCTSettings = 0x%X\n", __FUNCTION__, __LINE__, gRCTSettings));
    return EFI_LOAD_ERROR;
  }
  if (recvString16 == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: Value = 0x%X\n", __FUNCTION__, __LINE__, Value));
    return EFI_INVALID_PARAMETER;
  }

  switch(QuestionId){
  case RCT_ENABLED:
    if ((gRCTSettings->Flags & REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED) == 0) {
      Value->b = FALSE;
    } else {
      Value->b = TRUE;
    }
    break;
  case RCT_TLS_VERSION:
    if (gRCTSettings->TlsVersion == REMOTE_CFG_USE_TLS_1_0) {
      Value->u8 = 0;
    } else if (gRCTSettings->TlsVersion == REMOTE_CFG_USE_TLS_1_1) {
      Value->u8 = 1;
    } else if (gRCTSettings->TlsVersion == REMOTE_CFG_USE_TLS_1_2) {
      Value->u8 = 2;
#ifdef REMOTE_CFG_USE_NO_CRYPTO
    } else if (gRCTSettings->TlsVersion == REMOTE_CFG_USE_NO_CRYPTO) {
      Value->u8 = 3;
#endif
    } else {
      Value->u8 = 0;
    }
    if ((gRCTSettings->Flags & REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED) == 0) {
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    }
    break;
  case RCT_SERVER_IP_ADDR:
    AsciiStrToUnicodeStr(gRCTSettings->ServerName, recvString16);
    DEBUG((EFI_D_ERROR, "%a.%d: recvString16 = %s\n", __FUNCTION__, __LINE__, recvString16));
    if ((gRCTSettings->Flags & REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED) == 0) {
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    }
    break;
  case RCT_SERVER_PORT:
    UnicodeValueToString(recvString16, 0, (INT64)gRCTSettings->Port, 5);
    DEBUG((EFI_D_ERROR, "%a.%d: recvString16 = %s\n", __FUNCTION__, __LINE__, recvString16));
    if ((gRCTSettings->Flags & REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED) == 0) {
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    }
    break;
  case RCT_INFINITE_CTIMEOUT:
    if (gRCTSettings->TimeoutConnect == REMOTE_CFG_TLS_TIMEOUT_OFF) {
      Value->u8 = 0;
    } else {
      Value->u8 = 1;
    }
    if ((gRCTSettings->Flags & REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED) == 0) {
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    }
    break;
  case RCT_CTIMEOUT:
    UnicodeValueToString(recvString16, 0, (INT64)gRCTSettings->TimeoutConnect, 0);
    DEBUG((EFI_D_ERROR, "%a.%d: recvString16 = %s\n", __FUNCTION__, __LINE__, recvString16));
    if ((gRCTSettings->Flags & REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED) == 0 || 
      gRCTSettings->TimeoutConnect == REMOTE_CFG_TLS_TIMEOUT_OFF) {
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    }
    break;
  case RCT_INFINITE_ETIMEOUT:
    if (gRCTSettings->TimeoutExchange == REMOTE_CFG_TLS_TIMEOUT_OFF) {
      Value->u8 = 0;
    } else {
      Value->u8 = 1;
    }
    if ((gRCTSettings->Flags & REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED) == 0) {
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    }
    break;
  case RCT_ETIMEOUT:
    UnicodeValueToString(recvString16, 0, (INT64)gRCTSettings->TimeoutExchange, 0);
    DEBUG((EFI_D_ERROR, "%a.%d: recvString16 = %s\n", __FUNCTION__, __LINE__, recvString16));
    if ((gRCTSettings->Flags & REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED) == 0 || 
      gRCTSettings->TimeoutExchange == REMOTE_CFG_TLS_TIMEOUT_OFF) {
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    }
    break;
  case RCT_INFINITE_ATTEMPTS:
    if (gRCTSettings->Attempts == REMOTE_CFG_TLS_ATTEMPTS_INFINITE) {
      Value->u8 = 0;
    } else {
      Value->u8 = 1;
    }
    if ((gRCTSettings->Flags & REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED) == 0) {
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    }
    break;
  case RCT_ATTEMPTS:
    UnicodeValueToString(recvString16, 0, (INT64)gRCTSettings->Attempts, 0);
    DEBUG((EFI_D_ERROR, "%a.%d: recvString16 = %s\n", __FUNCTION__, __LINE__, recvString16));
    if ((gRCTSettings->Flags & REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED) == 0 || 
      gRCTSettings->Attempts == REMOTE_CFG_TLS_ATTEMPTS_INFINITE) {
      *ActionRequest = EFI_BROWSER_ACTION_HIDE;
    }
    break;
  default:
    // NOP. Unknown QuestionId.
    break;
  }
  
  return EFI_SUCCESS;
}
