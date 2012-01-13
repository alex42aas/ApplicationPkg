/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <CommonGuiSetup.h>
#include "AdvMenuHandlerDxe.h"

static ADV_MENU_HANDLER_PRIVATE_DATA gAdvMenuHandlerPrivateData;
static VOID *StartOpCodeHandle, *EndOpCodeHandle;
static EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;

static EFI_GUID AdvMenuFormGuid = ADV_MENU_FORM_GUID;

static EFI_STRING_ID *listOfStringId;

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
  IN EFI_FORM_ID FormId
  )
{
  EFI_IFR_GUID_LABEL *StartLabel;
  EFI_IFR_GUID_LABEL *EndLabel;
  EFI_GUID FormSetGuid = FORMSET_ADVANCED_MODE_GUID;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  
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
  StartLabel->Number       = LABEL_ADVANCED_MODE_PAGE_LIST_START;

  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      EndOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_ADVANCED_MODE_PAGE_LIST_END;
  
  Status = EFI_SUCCESS;
  
  HiiUpdateForm(gAdvMenuHandlerPrivateData.CurrentHiiHandle, &FormSetGuid, 
    FormId, StartOpCodeHandle, EndOpCodeHandle);
  
_exit:  
  return Status;
}



EFI_STATUS
EFIAPI
SetupCfgData(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN MULTIBOOT_CONFIG *MbCfg,
  IN EFI_HII_HANDLE HiiHandle
  )
{
  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  gAdvMenuHandlerPrivateData.CurrentCfg = MbCfg;
  gAdvMenuHandlerPrivateData.CurrentHiiHandle = HiiHandle;
  return EFI_SUCCESS;
}

//------------------------------------------------------------------------------
/*! If FormGuid isn't specified the form with ADV_MENU_FORM_GUID will be shown  */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
ShowMenu(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN OPTIONAL EFI_GUID *FormGuid
  )
{
  MULTIBOOT_FORM *AdvMenuForm;
  LIST_ENTRY *ListEntry;
  MULTIBOOT_ENTRY *Entry;
  EFI_STRING_ID HelpToken, Token;
  EFI_QUESTION_ID QuestionId;
  EFI_GUID FormSetGuid = FORMSET_ADVANCED_MODE_GUID;
  EFI_STATUS Status;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  UINT8 *OpCodeData;

  if (NULL == FormGuid)
    This->SelectFormByGuid(This, &AdvMenuFormGuid);
  else
    This->SelectFormByGuid(This, FormGuid);

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (gAdvMenuHandlerPrivateData.CurrentCfg == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  
  while(1) {
        DEBUG((EFI_D_INFO, "%a.%d guid=%g\n", 
            __FUNCTION__, __LINE__, &gAdvMenuHandlerPrivateData.AdvMenuFormGuid));
        AdvMenuForm = GetFormByGuid(gAdvMenuHandlerPrivateData.CurrentCfg, 
            &gAdvMenuHandlerPrivateData.AdvMenuFormGuid);
        if (NULL == AdvMenuForm) {
            DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
            return EFI_ABORTED;
        }
  
        DEBUG((EFI_D_INFO, "FormTitle: %s; FormId=0x%X\n", 
            AdvMenuForm->Title, AdvMenuForm->Id));

        Status = AllocateHiiResources((EFI_FORM_ID)AdvMenuForm->Id);
        if (EFI_ERROR(Status)) {
            DEBUG((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
            return Status;
        }

        ListEntry = AdvMenuForm->EntryHead.ForwardLink;

        if (listOfStringId && listOfStringId[ADV_MENU_TITLE] != 0) {
          HiiSetString(gAdvMenuHandlerPrivateData.CurrentHiiHandle,
            listOfStringId[ADV_MENU_TITLE], AdvMenuForm->Title,
            NULL);
        }

        while (ListEntry != &AdvMenuForm->EntryHead) {
            Entry = _CR( ListEntry, MULTIBOOT_ENTRY, ListEntry );

            if (Entry->Help != NULL)
                HelpToken = HiiSetString (gAdvMenuHandlerPrivateData.CurrentHiiHandle, 
                                0, Entry->Help, NULL);
            else
                HelpToken = HiiSetString (gAdvMenuHandlerPrivateData.CurrentHiiHandle, 
                                0, L"", NULL);

            Token = HiiSetString (gAdvMenuHandlerPrivateData.CurrentHiiHandle, 
            0, Entry->Name, NULL);
            QuestionId = (EFI_QUESTION_ID) (Entry->Index);
#if 1
            DEBUG((EFI_D_INFO, "%a.%d Entry->Name=%s Entry->Index=0x%X\n", 
            __FUNCTION__, __LINE__, Entry->Name, Entry->Index));
#endif
            switch (Entry->MenuItemType) {
            case MenuItemAction:
                if (NULL == HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
                    HelpToken, EFI_IFR_FLAG_CALLBACK, 0)) {
                    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
                    return EFI_OUT_OF_RESOURCES;
                }
                break;

            case MenuItemEmptyAction:
                if (NULL == HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
                    HelpToken, 0, 0)) {
                    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
                    return EFI_OUT_OF_RESOURCES;
                }
                break;

            case MenuItemListBox:
                DEBUG((EFI_D_INFO, "%a.%d MenuInfo=%a\n", 
                    __FUNCTION__, __LINE__, Entry->MenuInfo));
                Status = VfrCreateOneOfFromString(
                    gAdvMenuHandlerPrivateData.CurrentHiiHandle, StartOpCodeHandle,
                    Token, QuestionId, Entry->MenuInfo, Entry->Help);
                if (EFI_ERROR(Status)) {
                    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
                    return Status;
                }
                break;
    
            case MenuItemCheckbox:
                if (NULL == HiiCreateCheckBoxOpCode(StartOpCodeHandle, QuestionId, 0,
                    0, Token, HelpToken, EFI_IFR_FLAG_CALLBACK, 0, NULL)) {
                    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
                    return EFI_OUT_OF_RESOURCES;
                }
                break;
            
            case MenuItemNumericString:
                OpCodeData = HiiCreateStringOpCode(StartOpCodeHandle, QuestionId, 0,
                    0, Token, HelpToken, EFI_IFR_FLAG_CALLBACK, 0, MIN_INPUT_AREA_SIZE, MAX_INPUT_AREA_SIZE, NULL);
                    
                if (NULL == OpCodeData) {
                    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
                    return EFI_OUT_OF_RESOURCES;
                }

                ((EFI_IFR_STRING *) OpCodeData)->Flags = EFI_IFR_STRING_NUMERIC;
                
                break;
                
            case MenuItemString:
                if (NULL == HiiCreateStringOpCode(StartOpCodeHandle, QuestionId, 0,
                    0, Token, HelpToken, EFI_IFR_FLAG_CALLBACK, 0, MIN_INPUT_AREA_SIZE, MAX_INPUT_AREA_SIZE, NULL)) {
                    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
                    return EFI_OUT_OF_RESOURCES;
                }
                break;
                
            case MenuItemPassword:
                if (NULL == VfrCreatePasswordOpCode(StartOpCodeHandle, PASSWORD_MIN_LEN,
                    PASSWORD_MAX_LEN, QuestionId, 0, 0, Token, HelpToken)) {
                    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
                    return EFI_OUT_OF_RESOURCES;
                }
                Entry->NameToken = Token; // Save for the future
                break;
                
            case MenuItemDotString:
                OpCodeData = HiiCreateStringOpCode(StartOpCodeHandle, QuestionId, 0,
                    0, Token, HelpToken, EFI_IFR_FLAG_CALLBACK, 0, MIN_INPUT_AREA_SIZE, MAX_INPUT_AREA_SIZE, NULL);
                    
                if (NULL == OpCodeData) {
                    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
                    return EFI_OUT_OF_RESOURCES;
                }

                ((EFI_IFR_STRING *) OpCodeData)->Flags = EFI_IFR_STRING_NUMERIC_DOT;
                break;
                
            case MenuItemLabel:
                if (NULL == HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
                    HelpToken, EFI_IFR_FLAG_READ_ONLY, 0)) {
                    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
                    return EFI_OUT_OF_RESOURCES;
                }
                break;
      
            default:
                return EFI_INVALID_PARAMETER;
            }

            HiiUpdateForm(gAdvMenuHandlerPrivateData.CurrentHiiHandle, &FormSetGuid, 
                (EFI_FORM_ID)AdvMenuForm->Id, StartOpCodeHandle, EndOpCodeHandle);

//_next_entry:    
            ListEntry  = ListEntry->ForwardLink;
        }

        Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
            (VOID **) &gFormBrowser2);
            if (EFI_ERROR (Status)) {
                DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
                goto _exit;
        }

        ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
        Status = EFI_SUCCESS;
  
        DEBUG((EFI_D_INFO, "Now start showing the form!\n"));

        do {
            Status = gFormBrowser2->SendForm(gFormBrowser2, 
                &gAdvMenuHandlerPrivateData.CurrentHiiHandle, 1,
                &FormSetGuid, (EFI_FORM_ID)AdvMenuForm->Id, NULL, &ActionRequest);
#if 0    
            DEBUG((EFI_D_INFO, "%a.%d: bFormExitFlag=%d\n",
                __FUNCTION__, __LINE__, bFormExitFlag));
            if (bFormExitFlag) {
                Status = EFI_SUCCESS;
                break;
            }
#endif    
        } while (!gAdvMenuHandlerPrivateData.bFormExit);
        
_exit:
        DestroyHiiResources();
        
        gAdvMenuHandlerPrivateData.bFormExit = FALSE;
        if (gAdvMenuHandlerPrivateData.bGotoAction != FALSE)
            gAdvMenuHandlerPrivateData.bGotoAction = FALSE;
        else
            break;
    }
  
  return Status;
}


EFI_STATUS
EFIAPI
InternalCallback (
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *HiiCfgAccess,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  DEBUG((EFI_D_INFO, "%a.%d Action=%X QId=%X\n", 
    __FUNCTION__, __LINE__, Action, QuestionId));
  switch (Action) {
  case EFI_BROWSER_ACTION_FORM_OPEN:
    if (gAdvMenuHandlerPrivateData.StartCallback) {
      gAdvMenuHandlerPrivateData.StartCallback(This, Action,
        QuestionId, Type, Value, ActionRequest);
    }
    break;
    
  case EFI_BROWSER_ACTION_FORM_CLOSE:
    gAdvMenuHandlerPrivateData.bFormExit = TRUE;
    if (gAdvMenuHandlerPrivateData.ExitCallback) {
      DEBUG((EFI_D_INFO, "gAdvMenuHandlerPrivateData.ExitCallback:\n"));
      gAdvMenuHandlerPrivateData.ExitCallback(This, Action,
        QuestionId, Type, Value, ActionRequest);      
    }
    break;

  case EFI_BROWSER_ACTION_CHANGING:
  case EFI_BROWSER_ACTION_CHANGED:
  case EFI_BROWSER_ACTION_RETRIEVE:
    if (gAdvMenuHandlerPrivateData.ActionCallback) {
      gAdvMenuHandlerPrivateData.ActionCallback(This, Action,
        QuestionId, Type, Value, ActionRequest);
    }
    break;
    
  default:
    DEBUG((EFI_D_ERROR, "%a.%d Unknown action: %X\n", 
      __FUNCTION__, __LINE__, Action));  
    break;
  }
  
  if (*ActionRequest == EFI_BROWSER_ACTION_REQUEST_GOTO) {
    DEBUG ((EFI_D_INFO, "%a.%d EFI_BROWSER_ACTION_REQUEST_GOTO\n",  __FUNCTION__, __LINE__));
    gAdvMenuHandlerPrivateData.bGotoAction = TRUE;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
  }
  
  return EFI_SUCCESS;
}

EFI_HII_HANDLE
EFIAPI 
GetHiiHandle(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This
  )
{
  (VOID)This;
  return gAdvMenuHandlerPrivateData.CurrentHiiHandle;
}


EFI_STATUS
EFIAPI RegisterStartCallback(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN ADV_MENU_CALLBACK StartCallback
  )
{
  gAdvMenuHandlerPrivateData.StartCallback = StartCallback;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI RegisterExitCallback(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN ADV_MENU_CALLBACK ExitCallback
  )
{
  gAdvMenuHandlerPrivateData.ExitCallback = ExitCallback;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI RegisterActionCallback(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN ADV_MENU_CALLBACK ActionCallback
  )
{
  gAdvMenuHandlerPrivateData.ActionCallback = ActionCallback;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI SelectFormByGuid(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_GUID *FormGuid
  )
{
  MULTIBOOT_FORM *AdvMenuForm;

  if (FormGuid == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  CopyMem(&gAdvMenuHandlerPrivateData.AdvMenuFormGuid, FormGuid, sizeof(EFI_GUID));

  AdvMenuForm = GetFormByGuid(gAdvMenuHandlerPrivateData.CurrentCfg, FormGuid);
  if (AdvMenuForm == NULL) {
    return EFI_ABORTED;
  }

  gAdvMenuHandlerPrivateData.CurrentCfg->CurrentForm = AdvMenuForm;

  return EFI_SUCCESS;
}

//------------------------------------------------------------------------------
/*! \brief Get a guid of the current form */
/*! Copy the guid to avoid an unexpected access to the internal data */
/*! \param[in] *This pointer to ADV_MENU_HANDLER_PROTOCOL
    \param[out] *FormGuid pointer to the received guid of the form */
/*! \return Pointer to the received guid of the form */    
//------------------------------------------------------------------------------
EFI_GUID*
EFIAPI GetCurrentFormGuid(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_GUID *FormGuid
  )
{
  CopyMem(FormGuid, &gAdvMenuHandlerPrivateData.AdvMenuFormGuid, sizeof(EFI_GUID));
  return FormGuid;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check flag of a loading of a new form */
/*! \param[in] *This pointer to ADV_MENU_HANDLER_PROTOCOL */
/*! \return TRUE if load a new form, FALSE otherwise */
//------------------------------------------------------------------------------
BOOLEAN
EFIAPI IsGotoAction(IN CONST ADV_MENU_HANDLER_PROTOCOL *This)
{
    return gAdvMenuHandlerPrivateData.bGotoAction;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set the list of string IDs */
/*! Register a list of IDs. You have to use this list, because
    advMenu forms can't get access to string.uni directly */
//------------------------------------------------------------------------------
VOID
EFIAPI SetStringIdList(
  EFI_STRING_ID *idList
  )
{
  listOfStringId = idList;
  
  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a string Id */
/*! You have to use this string Id to create a popup message. */
/*! \param[in] Number of a string in the list */
/*! \return ID of a string */
//------------------------------------------------------------------------------
EFI_STRING_ID
EFIAPI GetStringId(
  UINTN stringNum
  )
{
  if (listOfStringId != NULL && stringNum <= NUM_ADV_MENU_STRINGS - 1) {
    return listOfStringId[stringNum];
  }
  
  return 0;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set token string for the multiboot entry by question ID */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI SetTokenStrForEntryByQuestionTd(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN CHAR16 *TokenStr
  )
{
  MULTIBOOT_ENTRY *entry;

  if (TokenStr == NULL)
    return EFI_INVALID_PARAMETER;

  entry = FindEntryOnCurrentFormByIndex(gAdvMenuHandlerPrivateData.CurrentCfg, (UINTN)QuestionId);
  if (entry != NULL) {
      // Update the entry name
      StrCpy(entry->Name, TokenStr);
      // Update Name in the binary data in the Hii data base
      HiiSetString (gAdvMenuHandlerPrivateData.CurrentHiiHandle, 
                  entry->NameToken, entry->Name, NULL);
      return EFI_SUCCESS;
  }

  return EFI_ABORTED;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get token string the multiboot entry by question ID */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI GetTokenStrForEntryByQuestionTd(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  OUT CHAR16 **TokenStr
  )
{
  MULTIBOOT_ENTRY *entry;

  if (TokenStr == NULL || *TokenStr != NULL)
    return EFI_INVALID_PARAMETER;

  entry = FindEntryOnCurrentFormByIndex(gAdvMenuHandlerPrivateData.CurrentCfg, (UINTN)QuestionId);
  if (entry != NULL) {
    DEBUG((EFI_D_INFO, "%a.%d %s\n", __FUNCTION__, __LINE__, entry->Name));
    *TokenStr = AllocateZeroPool(StrSize(entry->Name));
    StrCpy(*TokenStr, entry->Name);
    return EFI_SUCCESS;
  }

  DEBUG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));

  return EFI_ABORTED;
}
//------------------------------------------------------------------------------

EFI_STATUS
EFIAPI
AdvMenuHandlerInit (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  ADV_MENU_HANDLER_PROTOCOL *pAdvMenuHandlerProtocol;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  ZeroMem(&gAdvMenuHandlerPrivateData, sizeof(gAdvMenuHandlerPrivateData));

  CopyMem(&gAdvMenuHandlerPrivateData.AdvMenuFormGuid, &AdvMenuFormGuid, sizeof(EFI_GUID));

  pAdvMenuHandlerProtocol = &gAdvMenuHandlerPrivateData.AdvMenuHandlerProtocol;

  pAdvMenuHandlerProtocol->SetupCfgData       = SetupCfgData;
  pAdvMenuHandlerProtocol->ShowMenu           = ShowMenu;
  pAdvMenuHandlerProtocol->InternalCallback   = InternalCallback;
  pAdvMenuHandlerProtocol->GetHiiHandle       = GetHiiHandle;
  pAdvMenuHandlerProtocol->SelectFormByGuid   = SelectFormByGuid;
  pAdvMenuHandlerProtocol->GetCurrentFormGuid = GetCurrentFormGuid;
  pAdvMenuHandlerProtocol->IsGotoAction       = IsGotoAction;
  pAdvMenuHandlerProtocol->GetStringId        = GetStringId;
  pAdvMenuHandlerProtocol->SetStringIdList    = SetStringIdList;
  
  pAdvMenuHandlerProtocol->RegStartCallback = RegisterStartCallback;
  pAdvMenuHandlerProtocol->RegActionCallback = RegisterActionCallback;
  pAdvMenuHandlerProtocol->RegExitCallback = RegisterExitCallback;

  pAdvMenuHandlerProtocol->SetTokenStrForEntryByQuestionTd = SetTokenStrForEntryByQuestionTd;
  pAdvMenuHandlerProtocol->GetTokenStrForEntryByQuestionTd = GetTokenStrForEntryByQuestionTd;
  
  Status = gBS->InstallProtocolInterface( 
    &gAdvMenuHandlerPrivateData.DriverHandle, 
    &gAdvMenuHandlerProtocolGuid,
    EFI_NATIVE_INTERFACE,
    &gAdvMenuHandlerPrivateData.AdvMenuHandlerProtocol
    );

  DEBUG((EFI_D_INFO, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


