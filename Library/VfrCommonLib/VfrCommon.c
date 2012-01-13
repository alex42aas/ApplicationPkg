/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/VfrCommon.h>


extern EFI_HII_DATABASE_PROTOCOL *gHiiDatabase;
static VOID *CurrentFormBuffer, *CurrentStringBuffer;


typedef struct {
  UINT8  *Buffer;
  UINTN  BufferSize;
  UINTN  Position;
} HII_LIB_OPCODE_BUFFER;


EFI_STATUS
SetFormBrowserRefreshFlag(
  VOID
  )
{
  UINT8 Flag = 1;
  return gRT->SetVariable (L"FormRefresh", &gEfiGlobalVariableGuid,
    EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS, 
    sizeof(Flag), &Flag);
}

static EFI_STATUS
EFIAPI
InternalHiiUpdateDataFromFormPackage (
  IN  EFI_GUID               *FormSetGuid, OPTIONAL
  IN  EFI_FORM_ID            FormId,
  IN  EFI_HII_PACKAGE_HEADER *Package,
  IN  HII_LIB_OPCODE_BUFFER  *OpCodeBufferStart,
  IN  HII_LIB_OPCODE_BUFFER  *OpCodeBufferEnd,    OPTIONAL
  OUT EFI_HII_PACKAGE_HEADER *TempPackage
  )
{
  UINTN                     AddSize;
  UINT8                     *BufferPos;
  EFI_HII_PACKAGE_HEADER    PackageHeader;
  UINTN                     Offset;
  EFI_IFR_OP_HEADER         *IfrOpHdr;
//  EFI_IFR_OP_HEADER         *UpdateIfrOpHdr;
  BOOLEAN                   GetFormSet;
  BOOLEAN                   GetForm;
  BOOLEAN                   Updated;
  UINTN                     UpdatePackageLength;
  //HII_LIB_OPCODE_BUFFER     *TmpOpCodeBuffer;

  CopyMem (TempPackage, Package, sizeof (EFI_HII_PACKAGE_HEADER));
  UpdatePackageLength = sizeof (EFI_HII_PACKAGE_HEADER);
  BufferPos           = (UINT8 *) (TempPackage + 1);

  //DEBUG((EFI_D_ERROR, "%a.%d Package->Length=%d\n", 
  //  __FUNCTION__, __LINE__, Package->Length));
  //DumpBytes((UINT8*)(Package + 1), Package->Length);

  CopyMem (&PackageHeader, Package, sizeof (EFI_HII_PACKAGE_HEADER));
  IfrOpHdr   = (EFI_IFR_OP_HEADER *)((UINT8 *) Package + sizeof (EFI_HII_PACKAGE_HEADER));
  Offset     = sizeof (EFI_HII_PACKAGE_HEADER);
  GetFormSet = (BOOLEAN) ((FormSetGuid == NULL) ? TRUE : FALSE);
  GetForm    = FALSE;
  Updated    = FALSE;

  //DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  while (Offset < PackageHeader.Length) {
    CopyMem (BufferPos, IfrOpHdr, IfrOpHdr->Length);
    
    //TmpOpCodeBuffer     = (HII_LIB_OPCODE_BUFFER*)BufferPos;
    //BufferPos           += IfrOpHdr->Length;
    //UpdatePackageLength += IfrOpHdr->Length;    
    
    //DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
    //
    // Find the matched FormSet and Form
    //
    if ((IfrOpHdr->OpCode == EFI_IFR_FORM_SET_OP) && (FormSetGuid != NULL)) {
      if (CompareGuid((GUID *)(VOID *)&((EFI_IFR_FORM_SET *) IfrOpHdr)->Guid, FormSetGuid)) {
        GetFormSet = TRUE;
      } else {
        GetFormSet = FALSE;
      }
    } else if (IfrOpHdr->OpCode == EFI_IFR_FORM_OP) {
      if (CompareMem (&((EFI_IFR_FORM *) IfrOpHdr)->FormId, &FormId, sizeof (EFI_FORM_ID)) == 0) {
        GetForm = TRUE;
      } else {
        GetForm = FALSE;
      }
    }
    //DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
    //
    // The matched Form is found, and Update data in this form
    //
    if (!GetFormSet || !GetForm) {
      Offset   += IfrOpHdr->Length;
      IfrOpHdr = (EFI_IFR_OP_HEADER *) ((CHAR8 *) (IfrOpHdr) + IfrOpHdr->Length);
      continue;
    }
    AddSize = IfrOpHdr->Length;
    DEBUG((EFI_D_ERROR, "%a.%d AddSize=%d\n",
      __FUNCTION__, __LINE__, AddSize));
    DumpBytes(BufferPos, AddSize);
    Offset   += IfrOpHdr->Length;
    IfrOpHdr = (EFI_IFR_OP_HEADER *) ((CHAR8 *) (IfrOpHdr) + IfrOpHdr->Length);
  }

  //
  // Go to the next Op-Code
  //
  

//_done:  
  
  if (!Updated) {
    //
    // The updated opcode buffer is not found.
    //
    return EFI_NOT_FOUND;
  }
  //
  // Update the package length.
  //
  PackageHeader.Length = (UINT32) UpdatePackageLength;
  CopyMem (TempPackage, &PackageHeader, sizeof (EFI_HII_PACKAGE_HEADER));

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
HiiRetriveFormData (
  IN EFI_HII_HANDLE  HiiHandle,           
  IN EFI_GUID        *FormSetGuid,        OPTIONAL
  IN EFI_FORM_ID     FormId,
  IN VOID            *StartOpcodeHandle,
  IN VOID            *EndOpcodeHandle     OPTIONAL
  )
{
  EFI_STATUS                   Status;
  EFI_HII_PACKAGE_LIST_HEADER  *HiiPackageList;
  UINT32                       PackageListLength;  
  UINT32                       Offset;
  EFI_HII_PACKAGE_LIST_HEADER  *UpdatePackageList;
  UINTN                        BufferSize;
  UINT8                        *UpdateBufferPos;
  EFI_HII_PACKAGE_HEADER       *Package;
  EFI_HII_PACKAGE_HEADER       *TempPacakge;
  EFI_HII_PACKAGE_HEADER       PackageHeader;
  BOOLEAN                      Updated;
  HII_LIB_OPCODE_BUFFER        *OpCodeBufferStart;
  HII_LIB_OPCODE_BUFFER        *OpCodeBufferEnd;
  
  //
  // Input update data can't be NULL.
  //
  ASSERT (HiiHandle != NULL);
  ASSERT (StartOpcodeHandle != NULL);
  UpdatePackageList = NULL;
  TempPacakge       = NULL;
  HiiPackageList    = NULL;
  
  //
  // Restrive buffer data from Opcode Handle
  //
  OpCodeBufferStart = (HII_LIB_OPCODE_BUFFER *) StartOpcodeHandle;
  OpCodeBufferEnd   = (HII_LIB_OPCODE_BUFFER *) EndOpcodeHandle;
  
  //
  // Get the orginal package list
  //
  BufferSize = 0;
  HiiPackageList   = NULL;
  Status = gHiiDatabase->ExportPackageLists (gHiiDatabase, HiiHandle, &BufferSize, HiiPackageList);
  //
  // The return status should always be EFI_BUFFER_TOO_SMALL as input buffer's size is 0.
  //
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return Status;
  }

  HiiPackageList = AllocatePool (BufferSize);
  if (HiiPackageList == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Finish;
  }

  Status = gHiiDatabase->ExportPackageLists (gHiiDatabase, HiiHandle, &BufferSize, HiiPackageList);
  if (EFI_ERROR (Status)) {
    goto Finish;
  }

  //
  // Calculate and allocate space for retrieval of IFR data
  //
  BufferSize += OpCodeBufferStart->Position;
  UpdatePackageList = AllocateZeroPool (BufferSize);
  if (UpdatePackageList == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Finish;
  }
  
  //
  // Allocate temp buffer to store the temp updated package buffer
  //
  TempPacakge = AllocateZeroPool (BufferSize);
  if (TempPacakge == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Finish;
  }

  UpdateBufferPos = (UINT8 *) UpdatePackageList;

  //
  // Copy the package list header
  //
  CopyMem (UpdateBufferPos, HiiPackageList, sizeof (EFI_HII_PACKAGE_LIST_HEADER));
  UpdateBufferPos += sizeof (EFI_HII_PACKAGE_LIST_HEADER);
  
  //
  // Go through each package to find the matched pacakge and update one by one
  //
  Updated = FALSE;
  Offset  = sizeof (EFI_HII_PACKAGE_LIST_HEADER);
  PackageListLength = ReadUnaligned32 (&HiiPackageList->PackageLength);
  while (Offset < PackageListLength) {
    Package = (EFI_HII_PACKAGE_HEADER *) (((UINT8 *) HiiPackageList) + Offset);
    CopyMem (&PackageHeader, Package, sizeof (EFI_HII_PACKAGE_HEADER));
    Offset += Package->Length;

    if (Package->Type == EFI_HII_PACKAGE_FORMS) {
      //
      // Check this package is the matched package.
      //
      Status = InternalHiiUpdateDataFromFormPackage (FormSetGuid, FormId, Package, OpCodeBufferStart, OpCodeBufferEnd, TempPacakge);
      //
      // The matched package is found. Its pacakge buffer will be updated by the input new data.
      //
      if (!EFI_ERROR(Status)) {
        //
        // Set Update Flag
        //        
        Updated = TRUE;
        //
        // Add updated package buffer
        //
        Package = TempPacakge;
      }
    }

    //
    // Add pacakge buffer
    //
    CopyMem (&PackageHeader, Package, sizeof (EFI_HII_PACKAGE_HEADER));
    CopyMem (UpdateBufferPos, Package, PackageHeader.Length);
    UpdateBufferPos += PackageHeader.Length;
  }

#if 0  
  if (Updated) {
    //
    // Update package list length
    //
    BufferSize = UpdateBufferPos - (UINT8 *) UpdatePackageList;
    WriteUnaligned32 (&UpdatePackageList->PackageLength, (UINT32) BufferSize);
    
    //
    // Update Pacakge to show form
    //
    Status = gHiiDatabase->UpdatePackageList (gHiiDatabase, HiiHandle, UpdatePackageList);
  } else {
    //
    // Not matched form is found and updated.
    //
    Status = EFI_NOT_FOUND;
  }
#endif  

Finish:
  if (HiiPackageList != NULL) {
    FreePool (HiiPackageList);
  }
  
  if (UpdatePackageList != NULL) {
    FreePool (UpdatePackageList);
  }
  
  if (TempPacakge != NULL) {
    FreePool (TempPacakge);
  }

  return Status; 
}



UINT8 *
VfrGetBufferPtr(
  VOID *StartOpCodeHandle
  )
{
  HII_LIB_OPCODE_BUFFER *pBuff;

  pBuff = (HII_LIB_OPCODE_BUFFER*)StartOpCodeHandle;
  return pBuff->Buffer;
}

UINTN
VfrGetBufferSize(
  VOID *StartOpCodeHandle
  )
{
  HII_LIB_OPCODE_BUFFER *pBuff;

  pBuff = (HII_LIB_OPCODE_BUFFER*)StartOpCodeHandle;
  return pBuff->BufferSize;
}

UINTN
VfrGetPosition(
  VOID *StartOpCodeHandle
  )
{
  HII_LIB_OPCODE_BUFFER *pBuff;

  pBuff = (HII_LIB_OPCODE_BUFFER*)StartOpCodeHandle;
  return pBuff->Position;
}




extern UINT8 *
InternalHiiCreateOpCode (
  IN VOID *OpCodeHandle,
  IN VOID *OpCodeTemplate,
  IN UINT8 OpCode,
  IN UINTN OpCodeSize
  );
extern UINTN
InternalHiiOpCodeHandlePosition (
  IN VOID  *OpCodeHandle
  );

extern UINT8 *
InternalHiiOpCodeHandleBuffer (
  IN VOID  *OpCodeHandle
  );
  
extern UINT8 *
InternalHiiCreateOpCodeExtended (
  IN VOID   *OpCodeHandle,
  IN VOID   *OpCodeTemplate,
  IN UINT8  OpCode,
  IN UINTN  OpCodeSize,
  IN UINTN  ExtensionSize,
  IN UINT8  Scope
  );
  
extern UINT8 *
InternalHiiAppendOpCodes (
  IN VOID  *OpCodeHandle,
  IN VOID  *RawOpCodeHandle
  );
  
  
UINT8 *
EFIAPI
VfrCreatePasswordOpCode(
  IN VOID *OpCodeHandle,
  IN UINT16 MinSize,
  IN UINT16 MaxSize,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_VARSTORE_ID VarStoreId,
  IN UINT16 VarOffset,
  IN EFI_STRING_ID Prompt,
  IN EFI_STRING_ID Help
)
{
  EFI_IFR_PASSWORD OpCode;
  UINTN Position;

#if 0
MsgDebugPrint("%a.%d:QuestionId=%x VarOffset=%d\n", 
  __FUNCTION__, __LINE__, QuestionId, VarOffset);
#endif

  ZeroMem (&OpCode, sizeof (OpCode));
  OpCode.MinSize = MinSize;
  OpCode.MaxSize = MaxSize;
  OpCode.Question.QuestionId = QuestionId;
  OpCode.Question.VarStoreId = VarStoreId;
  OpCode.Question.Flags = EFI_IFR_FLAG_CALLBACK;
  OpCode.Question.VarStoreInfo.VarOffset = VarOffset;
  
  OpCode.Question.Header.Prompt = Prompt;
  OpCode.Question.Header.Help = Help;


  Position = InternalHiiOpCodeHandlePosition (OpCodeHandle);
#if 0
MsgDebugPrint("%a.%d:Position=%d\n", 
  __FUNCTION__, __LINE__, Position);
WaitForKP();
#endif  
  if (NULL == InternalHiiCreateOpCodeExtended (OpCodeHandle, &OpCode, EFI_IFR_PASSWORD_OP,
    sizeof (OpCode), 0, 1)) {
#if 0
MsgDebugPrint("%a.%d: error!\n", __FUNCTION__, __LINE__);
WaitForKP();
#endif
    return NULL;
  }

  HiiCreateEndOpCode (OpCodeHandle);
  //HiiFreeOpCodeHandle(PasswdHandler);
  return InternalHiiOpCodeHandleBuffer (OpCodeHandle) + Position;
}


UINT8 *
EFIAPI
VfrCreateRefreshOpCode (
  IN VOID *OpCodeHandle,
  IN UINT8 Interval
  )
{
  EFI_IFR_REFRESH  OpCode;
  UINTN Position;
  VOID *RefreshOpCodeHandle;

  RefreshOpCodeHandle = HiiAllocateOpCodeHandle ();
  ZeroMem (&OpCode, sizeof (OpCode));
  OpCode.RefreshInterval = Interval;
  
  InternalHiiCreateOpCode (RefreshOpCodeHandle, &OpCode, EFI_IFR_REFRESH_OP,
    sizeof (OpCode));

  Position = InternalHiiOpCodeHandlePosition (OpCodeHandle);
  InternalHiiCreateOpCodeExtended (OpCodeHandle, &OpCode, EFI_IFR_REFRESH_OP,
    sizeof (OpCode), 0, 1);
  //InternalHiiAppendOpCodes (OpCodeHandle, RefreshOpCodeHandle);
  HiiCreateEndOpCode (OpCodeHandle);
  HiiFreeOpCodeHandle(RefreshOpCodeHandle);
  return InternalHiiOpCodeHandleBuffer (OpCodeHandle) + Position;
}


UINT8 *
VfrCreateRefreshNumericTimeOut(
  IN VOID *StartOpCodeHandle,
  IN UINT8 ToVal,
  EFI_QUESTION_ID Qid,
  EFI_STRING_ID Prompt,
  EFI_STRING_ID Help
  )
{
  VOID *DefaultOpCodeHandle;
  UINT8 *RetVal;

  DefaultOpCodeHandle = HiiAllocateOpCodeHandle ();
  RetVal = HiiCreateDefaultOpCode (DefaultOpCodeHandle,
    EFI_HII_DEFAULT_CLASS_STANDARD, EFI_IFR_NUMERIC_SIZE_1, ToVal);
  if (NULL == RetVal) {
    goto _exit;
  }

  RetVal = HiiCreateNumericOpCode (StartOpCodeHandle, Qid, 0, 0, Prompt, Help,
    EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK,
    EFI_IFR_NUMERIC_SIZE_1 | EFI_IFR_DISPLAY_UINT_DEC,
    0, 255, 0, DefaultOpCodeHandle
    );
  if (NULL == RetVal) {
    goto _exit;
  }
  RetVal = VfrCreateRefreshOpCode (StartOpCodeHandle, 1);
  HiiFreeOpCodeHandle (DefaultOpCodeHandle);

_exit:
  return RetVal;
}


VOID
VfrShowAction(
  IN EFI_BROWSER_ACTION Action
  )
{
  switch (Action) {
  case EFI_BROWSER_ACTION_CHANGING:
    MsgDebugPrint("Action: EFI_BROWSER_ACTION_CHANGING\n");
    break;
    
  case EFI_BROWSER_ACTION_CHANGED:
    MsgDebugPrint("Action: EFI_BROWSER_ACTION_CHANGED\n");
    break;
    
  case EFI_BROWSER_ACTION_RETRIEVE:
    MsgDebugPrint("Action: EFI_BROWSER_ACTION_RETRIEVE\n");
    break;
    
  case EFI_BROWSER_ACTION_FORM_OPEN:
    MsgDebugPrint("Action: EFI_BROWSER_ACTION_FORM_OPEN\n");
    break;
    
  case EFI_BROWSER_ACTION_FORM_CLOSE:
    MsgDebugPrint("Action: EFI_BROWSER_ACTION_FORM_CLOSE\n");
    break;
    
  default:
    MsgDebugPrint("Action: Unknown\n");
  }
}


static VOID
EFIAPI
GetNextLanguage (
  IN OUT CHAR8      **LangCode,
  OUT CHAR8         *Lang
  )
{
  UINTN  Index;
  CHAR8  *StringPtr;

  ASSERT (LangCode != NULL);
  ASSERT (*LangCode != NULL);
  ASSERT (Lang != NULL);

  Index = 0;
  StringPtr = *LangCode;
  while (StringPtr[Index] != 0 && StringPtr[Index] != ';') {
    Index++;
  }

  CopyMem (Lang, StringPtr, Index);
  Lang[Index] = 0;

  if (StringPtr[Index] == ';') {
    Index++;
  }
  *LangCode = StringPtr + Index;
}


EFI_STATUS
SetupBestLanguage(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *CurrentLang
  )
{
  CHAR8 *LanguageString, *Lang, *LangCode;
  CHAR8 *PlatformSupportedLanguages, *BestLanguage;
  BOOLEAN bNotFound;

  LanguageString = HiiGetSupportedLanguages (HiiHandle);
  if (LanguageString == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Lang = AllocatePool (AsciiStrSize (LanguageString));
  if (Lang == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  for (bNotFound = TRUE, LangCode = LanguageString; *LangCode != 0;) {
    GetNextLanguage (&LangCode, Lang);
    if (0 == AsciiStrCmp(Lang, CurrentLang)) {
      bNotFound = FALSE;
      break;
    }
  }
  if (bNotFound) {
    return EFI_INVALID_PARAMETER;
  }

  PlatformSupportedLanguages = GetEfiGlobalVariable (L"PlatformLangCodes");
  if (PlatformSupportedLanguages == NULL) {
    PlatformSupportedLanguages = AllocateCopyPool (
        AsciiStrSize ((CHAR8 *) PcdGetPtr (
            PcdUefiVariableDefaultPlatformLangCodes)),
        (CHAR8 *) PcdGetPtr (PcdUefiVariableDefaultPlatformLangCodes));
    if (PlatformSupportedLanguages == NULL) {
      return EFI_INVALID_PARAMETER;
    }
  }

  BestLanguage = GetBestLanguage(PlatformSupportedLanguages, FALSE, Lang, NULL);

  if (BestLanguage == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  return gRT->SetVariable (L"PlatformLang", &gEfiGlobalVariableGuid,
    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
    EFI_VARIABLE_RUNTIME_ACCESS, AsciiStrSize (BestLanguage), Lang);
}

VOID
VfrFwVersionString(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR16 *StrBeforeVer,
  IN EFI_STRING_ID FwVersionStringId,
  IN CHAR16 *StrAfterVer
  )
{
  //EFI_STRING_ID TokenToUpdate;
  CHAR16 NewString[256], *StringBuffer; //, *FwInfoStr;
  CHAR8 *FwInfoStr;
  T_FIRMWARE_INFO FwInfo;
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
  
  StringBuffer = HiiGetString (HiiHandle, FwVersionStringId/*STR_FW_VERSION*/, NULL);
  if (NULL == StringBuffer) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return;
  }
  
  GetFirmwareInfo(&FwInfo);
#if 0
  FwInfoStr = FirmwareInfo2String(&FwInfo);
#else
  FwInfoStr = FwInfo.FwVerStr;
#endif
  UnicodeSPrint(NewString, sizeof(NewString), L"%s %s %a %s", 
    StringBuffer, StrBeforeVer ? StrBeforeVer : L"", 
    FwInfoStr, StrAfterVer ? StrAfterVer : L"");
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
  
  //TokenToUpdate = STRING_TOKEN (STR_FW_VERSION);
  HiiSetString (HiiHandle, FwVersionStringId /*TokenToUpdate*/, NewString, NULL);
}


VOID
TestForLanguage(
  IN EFI_HII_HANDLE HiiHandle
  )
{
#if 1
  (VOID)HiiHandle;
#else
  CHAR8 *LanguageString, *Lang, *LangCode;
  CHAR8 *PlatformSupportedLanguages, *BestLanguage;
  UINTN Index;
  EFI_STATUS Status;

  MsgDebugPrint("Start test for languages...\n");

  LanguageString = HiiGetSupportedLanguages (HiiHandle);
  if (LanguageString == NULL) {
    MsgDebugPrint("%a.%d: error!", __FUNCTION__, __LINE__);
    return;
  }

  Lang = AllocatePool (AsciiStrSize (LanguageString));
  if (Lang == NULL) {
    MsgDebugPrint("%a.%d: error!", __FUNCTION__, __LINE__);
    return;
  }

  Index = 0;
  LangCode = LanguageString;
  while (*LangCode != 0) {
    GetNextLanguage (&LangCode, Lang);
    MsgDebugPrint("%a --> %a\n", LangCode, Lang);
    if (Index == 1) { /* ru-RU */
      break;
    }
    Index++;
  }

  PlatformSupportedLanguages = GetEfiGlobalVariable (L"PlatformLangCodes");
  if (PlatformSupportedLanguages == NULL) {
    MsgDebugPrint("%a.%d: error!", __FUNCTION__, __LINE__);
    PlatformSupportedLanguages = AllocateCopyPool (
      AsciiStrSize ((CHAR8 *)
        PcdGetPtr (PcdUefiVariableDefaultPlatformLangCodes)),
      (CHAR8 *) PcdGetPtr (PcdUefiVariableDefaultPlatformLangCodes)
      );
    if (PlatformSupportedLanguages == NULL) {
      MsgDebugPrint("%a.%d: error!", __FUNCTION__, __LINE__);
      return;
    }
  }

  BestLanguage = GetBestLanguage(PlatformSupportedLanguages, FALSE, Lang, NULL);
  if (BestLanguage == NULL) {
    return;
  }

  Status = gRT->SetVariable (L"PlatformLang", &gEfiGlobalVariableGuid,
    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
    EFI_VARIABLE_RUNTIME_ACCESS, AsciiStrSize (BestLanguage), Lang);
    
  if (EFI_ERROR(Status)) {
    MsgDebugPrint("%a.%d: error!", __FUNCTION__, __LINE__);
  } else {
    MsgDebugPrint("Well done!\n");
  }
#endif
}


EFI_STATUS
VfrCreateOneOfFromString(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId,
  IN CHAR16 *ListStr,
  IN OPTIONAL CHAR16 *HelpStr
  )
{
  VOID *OptionsOpCodeHandle = NULL, *Opt;
  EFI_STATUS Status = EFI_ABORTED;
  EFI_STRING_ID Str16_Id, HelpStrId;
  UINTN Idx, Len;
  CHAR16 *CurStr, *TmpPtr;
  CHAR16 Str16[256];
  
  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (OptionsOpCodeHandle == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  if (HelpStr != NULL)
    HelpStrId = HiiSetString (HiiHandle, 0, HelpStr, NULL);
  else
    HelpStrId = HiiSetString (HiiHandle, 0, L"", NULL);

  Len = StrLen(ListStr);
  for (Idx = 0, CurStr = ListStr; CurStr < ListStr + Len; Idx++) {
    TmpPtr = StrStr(CurStr, L"/");
    if (TmpPtr) {
      *TmpPtr = '\0';
    }    
    UnicodeSPrint(Str16, sizeof(Str16), L"%s", CurStr);
    if (TmpPtr) {
      *TmpPtr = '/';
      CurStr = TmpPtr + 1;
    } else {
      CurStr = ListStr + Len;
    }    
    
    Str16_Id = HiiSetString (HiiHandle, 0, Str16, NULL);
    Opt = HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
      Str16_Id, 0, EFI_IFR_NUMERIC_SIZE_1, Idx);
    if (Opt == NULL) {
      goto _exit;
    }    
  }

  if (Idx == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  
  Status = HiiCreateOneOfOpCode (
      StartOpCodeHandle, QuestionId, 0, 0,
      Caption, HelpStrId,
      EFI_IFR_FLAG_CALLBACK | EFI_IFR_FLAG_OPTIONS_ONLY,
      EFI_IFR_NUMERIC_SIZE_1,
      OptionsOpCodeHandle,
      NULL
      ) == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;

_exit:
  if (OptionsOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (OptionsOpCodeHandle);
  }
  return Status;
}


EFI_STATUS
VfrCreateGrayIfNotSecurityOpCode (
  IN VOID *OpCodeHandle,
  IN EFI_GUID *PermissionGuid
  )
{
  EFI_IFR_SECURITY OpCode;
  EFI_IFR_GRAY_OUT_IF OpCodeIf;
  EFI_IFR_NOT OpCodeNot;
  VOID *GrayOutIfHandle = NULL;
  VOID *SecurityOpCodeHandle = NULL;
  VOID *NotOpCodeHandle = NULL;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;

  NotOpCodeHandle = HiiAllocateOpCodeHandle ();
  ZeroMem (&OpCodeNot, sizeof(EFI_IFR_NOT));

  GrayOutIfHandle = HiiAllocateOpCodeHandle ();
  ZeroMem (&OpCodeIf, sizeof(EFI_IFR_GRAY_OUT_IF));

  SecurityOpCodeHandle = HiiAllocateOpCodeHandle ();
  ZeroMem (&OpCode, sizeof (OpCode));
  CopyMem(&OpCode.Permissions, PermissionGuid, sizeof (EFI_GUID));

  if (NULL == InternalHiiCreateOpCode (GrayOutIfHandle, &OpCodeIf, 
      EFI_IFR_GRAY_OUT_IF_OP, sizeof (OpCodeIf))) {
    goto _exit;
  }

  if (NULL == InternalHiiCreateOpCode (SecurityOpCodeHandle, &OpCode, 
      EFI_IFR_SECURITY_OP, sizeof (OpCode))) {
    goto _exit;
  }

  if (NULL == InternalHiiCreateOpCode (NotOpCodeHandle, &OpCodeNot, 
    EFI_IFR_NOT_OP, sizeof (OpCodeNot))) {
    goto _exit;
  }

  if (NULL == InternalHiiCreateOpCodeExtended (OpCodeHandle, &OpCodeIf, 
      EFI_IFR_GRAY_OUT_IF_OP, sizeof (OpCodeIf), 0, 1)) {
    goto _exit;
  }
  
  if (NULL == InternalHiiCreateOpCodeExtended (OpCodeHandle, &OpCode, 
      EFI_IFR_SECURITY_OP, sizeof (OpCode), 0, 1)) {
    goto _exit;
  }

  if (NULL == InternalHiiCreateOpCodeExtended (OpCodeHandle, &OpCodeNot, 
      EFI_IFR_NOT_OP, sizeof (OpCodeNot), 0, 0)) {
    goto _exit;
  }
  
  
  if (NULL != HiiCreateEndOpCode (OpCodeHandle)) {
    Status = EFI_SUCCESS;
  }

_exit:

  if (SecurityOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle(SecurityOpCodeHandle);
  }
  if (NotOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle(NotOpCodeHandle);
  }
  if (GrayOutIfHandle != NULL) {
    HiiFreeOpCodeHandle(GrayOutIfHandle);
  }
  return Status;
}


EFI_STATUS
VfrCreateGraySecAction (
  IN VOID *OpCodeHandle,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_STRING_ID Token, 
  IN EFI_STRING_ID HelpToken,  
  IN EFI_GUID *PermissionGuid
  )
{
  EFI_STATUS Status;
  
  Status = VfrCreateGrayIfNotSecurityOpCode (OpCodeHandle, PermissionGuid);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
    return Status;
  }
  if (NULL == HiiCreateActionOpCode(OpCodeHandle, QuestionId, Token,
      HelpToken, EFI_IFR_FLAG_CALLBACK, 0)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  HiiCreateEndOpCode (OpCodeHandle);
  return EFI_SUCCESS;
}


EFI_STATUS
VfrCreateGraySecCheckBox (
  IN VOID *OpCodeHandle,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_STRING_ID Token, 
  IN EFI_STRING_ID HelpToken,
  IN UINT8 CheckBoxFlags,
  IN EFI_GUID *PermissionGuid
  )
{
  EFI_STATUS Status;
  
  Status = VfrCreateGrayIfNotSecurityOpCode (OpCodeHandle, PermissionGuid);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  if (NULL == HiiCreateCheckBoxOpCode (
        OpCodeHandle, 
        QuestionId, 
        0, 
        0, 
        Token, 
        HelpToken, 
        EFI_IFR_FLAG_CALLBACK,
        CheckBoxFlags, //(Flags & SETUP_FLAG_DBG_LOAD_PARAMS) ? EFI_IFR_CHECKBOX_DEFAULT : 0, 
        NULL)) {
    return EFI_OUT_OF_RESOURCES;
  }
  HiiCreateEndOpCode (OpCodeHandle);
  return EFI_SUCCESS;
}

