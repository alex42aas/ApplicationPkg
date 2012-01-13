/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library\Lib\LoadingParamsCtrl.h>

STATIC EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
STATIC VOID *StartOpCodeHandle, *EndOpCodeHandle;
STATIC EFI_HII_HANDLE CurrentHiiHandle;
STATIC BOOLEAN bFormExit;
STATIC MULTIBOOT_ENTRY *CurDefaultEntry;


typedef struct _T_MODULE_EFI_VAR_REC {
  UINT16 ModuleId;
  CHAR8 DevPath[MULTIBOOT_MAX_STRING];
  CHAR8 Args[MULTIBOOT_MAX_STRING];
} MODULE_EFI_VAR_REC;


extern GUID gVendorGuid;


EFI_STATUS
GetModuleSavedVar(
  IN UINT16 ModuleId,
  IN OUT MODULE_EFI_VAR_REC *ModRec
  )
{
  EFI_STATUS Status;
  CHAR16 VarName[40];
  UINTN Size;

  if (ModRec == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  UnicodeSPrint(VarName, sizeof(VarName), L"ModRec_%04X_%04d", 
    (UINT16)(CurDefaultEntry->Index & 0xFFFF),ModuleId);
  Size = sizeof(MODULE_EFI_VAR_REC);
  Status = gRT->GetVariable(VarName, &gVendorGuid, NULL,
      &Size, ModRec);
  DEBUG((EFI_D_ERROR, "Read: %s Status = %r\n", VarName, Status));
  return Status;
}


EFI_STATUS
SetModuleVar(
  IN MODULE_EFI_VAR_REC *ModRec
  )
{
  EFI_STATUS Status;
  CHAR16 VarName[40];

  if (ModRec == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  UnicodeSPrint(VarName, sizeof(VarName), L"ModRec_%04X_%04d", 
    (UINT16)(CurDefaultEntry->Index & 0xFFFF), ModRec->ModuleId);
  Status = gRT->SetVariable (VarName, &gVendorGuid,
                EFI_VARIABLE_NON_VOLATILE |
                EFI_VARIABLE_BOOTSERVICE_ACCESS,
                sizeof(MODULE_EFI_VAR_REC), 
                ModRec);
  DEBUG((EFI_D_ERROR, "Save: %s Status = %r\n", VarName, Status));
  return Status;
}


STATIC
VOID
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

STATIC
EFI_STATUS
AllocateHiiResources(
  VOID
  )
{
  EFI_IFR_GUID_LABEL *StartLabel;
  EFI_IFR_GUID_LABEL *EndLabel;
  EFI_GUID FormSetGuid = FORMSET_DBG_LOAD_PARAMS_GUID;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_FORM_ID FormId = DBG_LOAD_PARAMS_PAGE_ID;
  
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
  StartLabel->Number       = LABEL_DBG_LOAD_PARAMS_LIST_START;

  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      EndOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_DBG_LOAD_PARAMS_LIST_END;
  
  Status = EFI_SUCCESS;
  
  HiiUpdateForm(CurrentHiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  
_exit:  
  return Status;
}

EFI_STATUS
RetriveFormData(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  CHAR16 *Str16;
  UINT16 Idx;
  MULTIBOOT_MODULE *Module;
  LIST_ENTRY *ListEntry;

  Str16 = (CHAR16*)Value;
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (QuestionId < DBG_LOAD_PARAMS_START || QuestionId > DBG_LOAD_PARAMS_END) {
    return EFI_SUCCESS;
  }
  
  Idx = DBG_LOAD_PARAMS_START;
  ListEntry = CurDefaultEntry->ModuleHead.ForwardLink;

  while (ListEntry != &CurDefaultEntry->ModuleHead) {
    Module = _CR( ListEntry, MULTIBOOT_MODULE, ListEntry);
    if (Idx == QuestionId) {
      UnicodeSPrint(Str16, sizeof(Module->DevPath), L"%s",
          Module->DevPath);
      break;
    }
    Idx++;
    if (Idx == QuestionId) {
      UnicodeSPrint(Str16, sizeof(Module->Args), L"%s",
          StrLen(Module->Args) ? Module->Args : L"-");
      break;
    }
    Idx++;
    ListEntry = ListEntry->ForwardLink;
  }

  return EFI_SUCCESS;
}


EFI_STATUS
UdateFormStrings(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  CHAR16 *Str16;
  UINT16 Idx;
  MULTIBOOT_MODULE *Module;
  LIST_ENTRY *ListEntry;

  if (Type != EFI_IFR_TYPE_STRING) {
    return EFI_SUCCESS;
  }  

  Str16 = HiiGetString(CurrentHiiHandle, Value->string, NULL);
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (QuestionId < DBG_LOAD_PARAMS_START || QuestionId > DBG_LOAD_PARAMS_END) {
    return EFI_SUCCESS;
  }
  
  Idx = DBG_LOAD_PARAMS_START;
  ListEntry = CurDefaultEntry->ModuleHead.ForwardLink;

  while (ListEntry != &CurDefaultEntry->ModuleHead) {
    Module = _CR( ListEntry, MULTIBOOT_MODULE, ListEntry);
    if (Idx == QuestionId) {
      UnicodeSPrint(Module->DevPath, sizeof(Module->DevPath), L"%s",
        Str16);
      break;
    }
    Idx++;
    if (Idx == QuestionId) {
      UnicodeSPrint(Module->Args, sizeof(Module->Args), L"%s",
        Str16);
      break;
    }    
    
    Idx++;
    ListEntry = ListEntry->ForwardLink;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
LoadingParamsCtrPageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
   EFI_STATUS Status;

  (VOID)Status;
  if (ActionRequest == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (EFI_BROWSER_ACTION_FORM_CLOSE == Action) {
    bFormExit = TRUE;
    return EFI_SUCCESS;
  }
  if (EFI_BROWSER_ACTION_FORM_OPEN == Action) {
    return EFI_SUCCESS;
  }
  if (EFI_BROWSER_ACTION_RETRIEVE == Action) {
    return RetriveFormData(This, Action, QuestionId, Type, Value, 
      ActionRequest);
  }
  if (Action != EFI_BROWSER_ACTION_CHANGING) {
    return EFI_SUCCESS;
  }
  
  UdateFormStrings(This, Action, QuestionId, Type, Value, ActionRequest);
  return EFI_SUCCESS;
}

EFI_STATUS
UpdateModulesCfgStrings(
  VOID
  )
{
  MULTIBOOT_MODULE *Module;
  LIST_ENTRY *ListEntry;
  EFI_STATUS Status;
  MODULE_EFI_VAR_REC ModRec;
  UINT16 ModuleId;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  ListEntry = CurDefaultEntry->ModuleHead.ForwardLink;
  ModuleId = 0;

  while (ListEntry != &CurDefaultEntry->ModuleHead) {
    Module = _CR( ListEntry, MULTIBOOT_MODULE, ListEntry);
    Status = GetModuleSavedVar(ModuleId, &ModRec);
    if (!EFI_ERROR(Status)) {    
      UnicodeSPrint(Module->DevPath, sizeof(Module->DevPath), L"%a",
        ModRec.DevPath);
      UnicodeSPrint(Module->Args, sizeof(Module->Args), L"%a",
         AsciiStrLen(ModRec.Args) ? ModRec.Args : "-");
    }
    ModuleId++;
    ListEntry = ListEntry->ForwardLink;
  }

  return EFI_SUCCESS;
}


EFI_STATUS
UpdateModulesVars(
  VOID
  )
{
  MULTIBOOT_MODULE *Module;
  LIST_ENTRY *ListEntry;
  EFI_STATUS Status;
  MODULE_EFI_VAR_REC ModRec;
  UINT16 ModuleId;

  ListEntry = CurDefaultEntry->ModuleHead.ForwardLink;
  ModuleId = 0;
  
  while (ListEntry != &CurDefaultEntry->ModuleHead) {
    Module = _CR( ListEntry, MULTIBOOT_MODULE, ListEntry);

    ModRec.ModuleId = ModuleId;
    AsciiSPrint(ModRec.DevPath, sizeof(ModRec.DevPath), "%s",
        Module->DevPath);
    AsciiSPrint(ModRec.Args, sizeof(ModRec.Args), "%s",
        Module->Args);
    Status = SetModuleVar(&ModRec);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!!!!\n", __FUNCTION__, __LINE__));
    }
    
    ModuleId++;
    ListEntry = ListEntry->ForwardLink;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
LoadingParamsCtrPage(
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_ENTRY *DefaultEntry
  )
{
  EFI_STATUS Status = EFI_ABORTED;
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_GUID FormSetGuid = FORMSET_DBG_LOAD_PARAMS_GUID;
  EFI_FORM_ID FormId = DBG_LOAD_PARAMS_PAGE_ID;
  MULTIBOOT_MODULE     *Module;
  LIST_ENTRY           *ListEntry;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  CHAR16 TmpStr16[255];
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  if (DefaultEntry == NULL || HiiHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if(IsListEmpty(&DefaultEntry->ModuleHead)) {
    return EFI_INVALID_PARAMETER;
  }
  
  CurrentHiiHandle = HiiHandle;
  CurDefaultEntry = DefaultEntry;

  Status = AllocateHiiResources();
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  UpdateModulesCfgStrings();

  QuestionId = DBG_LOAD_PARAMS_START;
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

  ListEntry = DefaultEntry->ModuleHead.ForwardLink;

  while (ListEntry != &DefaultEntry->ModuleHead) {
    Module = _CR( ListEntry, MULTIBOOT_MODULE, ListEntry);

    DEBUG((EFI_D_ERROR, "%a.%d Module->DevPath=%s\n", 
      __FUNCTION__, __LINE__, Module->DevPath));
    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"Path: ");
    Token = HiiSetString(HiiHandle, 0, TmpStr16, NULL);
    
    HiiCreateStringOpCode (StartOpCodeHandle, 
          QuestionId++, 0, 0, 
          Token, HelpToken,
          EFI_IFR_FLAG_CALLBACK /*QuestionFlags*/,
          EFI_IFR_STRING_MULTI_LINE /*StringFlags*/,
          0, MULTIBOOT_MAX_STRING - 1, NULL);    

    DEBUG((EFI_D_ERROR, "%a.%d Module->Args=%s\n", 
      __FUNCTION__, __LINE__, Module->Args));
    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"Args: ");
    Token = HiiSetString(HiiHandle, 0, TmpStr16, NULL);

    HiiCreateStringOpCode (StartOpCodeHandle, 
          QuestionId++, 0, 0, 
          Token, HelpToken,
          EFI_IFR_FLAG_CALLBACK /*QuestionFlags*/,
          EFI_IFR_STRING_MULTI_LINE /*StringFlags*/,
          0, MULTIBOOT_MAX_STRING - 1, NULL);
    
    ListEntry = ListEntry->ForwardLink;
  }

  HiiUpdateForm(CurrentHiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);

  Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
    (VOID **) &gFormBrowser2);
  DEBUG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
  if (EFI_ERROR (Status)) {
    goto _exit;
  }

  ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
  Status = EFI_SUCCESS;
  bFormExit = FALSE;

  do {
    Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1,
      &FormSetGuid, FormId, NULL, &ActionRequest);      
    DEBUG((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));  
    if (bFormExit) {
      Status = EFI_SUCCESS;
      break;
    }
  } while (1);
  
_exit:
  DestroyHiiResources();
  UpdateModulesVars();
  return Status;
}

