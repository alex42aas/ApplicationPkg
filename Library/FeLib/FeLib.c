/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/FeLib.h>

#define LOG(MSG)      DEBUG(MSG)

static EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
static VOID *StartOpCodeHandle, *EndOpCodeHandle;
static EFI_HII_HANDLE CurrentHiiHandle;
static EFI_DEVICE_PATH_PROTOCOL *CurDevPath;
static CHAR16 SelectedString[MAX_FE_STRING_LEN];
static CHAR16 *UpperFolder;
static CHAR16 CurrentDevicePath[MAX_FE_STRING_LEN];
static FS_OBJECT_DESC *pObjDesc;
static int ObjDescCount;
static BOOLEAN bFormExitFlag, bRefreshForm;
static int CurrentEvent;
static int SavedStartQId;
static int CurrentFsLevel;
static BOOLEAN SaveParamsFlag;
STATIC UINTN FeMode;


STATIC 
VOID
UpdateSelectedString(
  IN CHAR16 *Fname
  )
{
  StrCpy(SelectedString, Fname);
}


static VOID
DestroyFsObjDesc(
  VOID
  )
{
  int i;
  
  for (i = 0; (pObjDesc != NULL) && (i < ObjDescCount); i++) {
    if (pObjDesc[i].Fname) {
      if (pObjDesc[i].Fname != FsUtilsDotDotStr()) {
        FreePool(pObjDesc[i].Fname);
      }
    }
    if (pObjDesc[i].Fattr) {
      FreePool(pObjDesc[i].Fattr);
    }
  }
  if (pObjDesc) {
    FreePool(pObjDesc);
    pObjDesc = NULL;
  }
  ObjDescCount = 0;
}


CHAR16 *
FeGetSelectedString(
  VOID
  )
{
  return SelectedString;
}


EFI_DEVICE_PATH_PROTOCOL*
FeGetCurDevPath(
  VOID
  )
{
  return CurDevPath;
}


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
  IN EFI_GUID *FormSetGuid,
  IN EFI_FORM_ID FormId,
  IN UINT16 FeStartLabel,
  IN UINT16 FeEndLabel
  )
{
  EFI_IFR_GUID_LABEL *StartLabel;
  EFI_IFR_GUID_LABEL *EndLabel;
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
  StartLabel->Number       = FeStartLabel;

  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      EndOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = FeEndLabel;

  Status = EFI_SUCCESS;

  HiiUpdateForm(CurrentHiiHandle, FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);

_exit:
  return Status;
}

STATIC
INTN
FeCompareFsStringListElem(
  IN FS_OBJECT_DESC *Right,
  IN FS_OBJECT_DESC *Left
  )
{
  if (Right->bDirectory && !Left->bDirectory) {
    return -1;
  } else if (!Right->bDirectory && Left->bDirectory) {
    return 1;
  } else {
    INTN Res = StrNoCaseCompare(Right->Fname, Left->Fname);
    return Res;
  }
}

STATIC
VOID
FeQuickSortFsStringList(
  IN INTN Low,
  IN INTN High
  )
{
  INTN i;
  INTN j;
  STATIC FS_OBJECT_DESC FsMedianObj;
  STATIC FS_OBJECT_DESC FsTmpObj;

  LOG((EFI_D_INFO, "FeQuickSortFsStringList, Low=%d, High=%d\n", Low, High));

  i = Low;
  j = High;
  CopyMem(&FsMedianObj, &pObjDesc[(Low+High)/2], sizeof(FS_OBJECT_DESC));
  
  do {
    while (FeCompareFsStringListElem(&pObjDesc[i], &FsMedianObj) < 0) {
      i++;
    }
    while (FeCompareFsStringListElem(&pObjDesc[j], &FsMedianObj) > 0) {
      j--;
    }
    
    if (i <= j) {
      if (i < j && (FeCompareFsStringListElem(&pObjDesc[i], &pObjDesc[j]) != 0)) {
        CopyMem(&FsTmpObj, &pObjDesc[i], sizeof(FS_OBJECT_DESC));
        CopyMem(&pObjDesc[i], &pObjDesc[j], sizeof(FS_OBJECT_DESC));
        CopyMem(&pObjDesc[j], &FsTmpObj, sizeof(FS_OBJECT_DESC));
      }

      i++;
      j--;
    }
  } while (i < j);
  
  if (Low < j) {
    FeQuickSortFsStringList(Low, j);
  }
  if (i < High) {
    FeQuickSortFsStringList(i, High);
  }
}

STATIC
VOID
FeQuickSortFsStringListTest(
  VOID
  )
{
  INTN i;
  UINT64 RndVal;
  BOOLEAN IsSortedRight;
  STATIC int PrevObjDescCount;
  STATIC FS_OBJECT_DESC *PrevObjDesc;
  STATIC FS_OBJECT_DESC TestObjDesc[25];
  STATIC CHAR16 TestStrings[25][25];

  for (i = 0; i < 20; i++) {
    RndVal = AsmReadTsc();
    LOG((EFI_D_INFO, "RndVal = %LX\n", RndVal));
    UnicodeSPrint(TestStrings[i], 25, L"%LX", RndVal);
    TestObjDesc[i].Fname = TestStrings[i];
    TestObjDesc[i].Fattr = L"";
    TestObjDesc[i].bDirectory = ((RndVal % 3) == 0)?TRUE:FALSE;
  }
 
  PrevObjDescCount = ObjDescCount;
  PrevObjDesc = pObjDesc;
  ObjDescCount = 25;
  pObjDesc = TestObjDesc;

  for (i = 0; i < ObjDescCount; i++) {
    LOG((EFI_D_INFO, "pObjDesc[%2d] = %s %s\n", i, pObjDesc[i].Fname, pObjDesc[i].bDirectory ? L" <DIR>" : L""));
  }

  FeQuickSortFsStringList(0, (ObjDescCount - 1));

  LOG((EFI_D_INFO, "After sorting:\n"));
  for (i = 0; i < ObjDescCount; i++) {
    LOG((EFI_D_INFO, "pObjDesc[%2d] = %s %s\n", i, pObjDesc[i].Fname, pObjDesc[i].bDirectory ? L" <DIR>" : L""));
  }

  IsSortedRight = TRUE;
  for (i = 1; i < ObjDescCount; i++) {
    if (FeCompareFsStringListElem(&pObjDesc[i], &pObjDesc[i-1]) < 0) {
      IsSortedRight = FALSE;
      break;
    }
  }
  LOG((EFI_D_INFO, "Sorting result is %s\n", IsSortedRight ? L"OK" : L"bad"));

  ObjDescCount = PrevObjDescCount;
  pObjDesc = PrevObjDesc;
}

static EFI_STATUS
FeObtainFsStringList(
  IN EFI_DEVICE_PATH_PROTOCOL *DevPath,
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_GUID *FormSetGuid,
  IN EFI_FORM_ID FormId,
  IN EFI_QUESTION_ID FeQuidStart
  )
{
  CHAR16 MenuStr[255];
  EFI_STATUS Status;
  EFI_STRING_ID Token, Help;
  EFI_STRING_ID TokenSave = 0;
  EFI_STRING_ID HelpSave = 0;
  EFI_QUESTION_ID QuestionId;
  int i;
  
  QuestionId = (EFI_QUESTION_ID) (FeQuidStart);

  Help = HiiSetString (HiiHandle, 0, L"", NULL);
  UnicodeSPrint(MenuStr, sizeof(MenuStr), L"%s", CurrentDevicePath);
  Token = HiiSetString (HiiHandle, 0, MenuStr, NULL);
  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId++,
      Token, Help, EFI_IFR_FLAG_READ_ONLY /*EFI_IFR_FLAG_CALLBACK*/, 0);

  DestroyFsObjDesc();
  
  LOG ((EFI_D_INFO, "%a.%d CurrentDevicePath=%s\n", __FUNCTION__, __LINE__, CurrentDevicePath));

  Status = LibFsGetObjectsCount(DevPath, CurrentDevicePath, &ObjDescCount, FALSE, 
      CurrentFsLevel == 0 ? FALSE : TRUE);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }
  if (ObjDescCount == 0) {
    UnicodeSPrint(MenuStr, sizeof(MenuStr), L"<         >");
    Token = HiiSetString (HiiHandle, 0, MenuStr, NULL);
    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId++,
      Token, Help, EFI_IFR_FLAG_CALLBACK, 0);

    if(FeGetSaveParamsFlag())
    { 
      HiiCreateActionOpCode(StartOpCodeHandle, QuestionId++,
				TokenSave, HelpSave, EFI_IFR_FLAG_CALLBACK, 0);
    }
    goto _exit;
  }
  pObjDesc = (FS_OBJECT_DESC*) AllocateZeroPool(sizeof(FS_OBJECT_DESC) * ObjDescCount);
  if (NULL == pObjDesc) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = LibFsGetObjectsList(DevPath, CurrentDevicePath, pObjDesc, FALSE, 
      CurrentFsLevel == 0 ? FALSE : TRUE);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }
  
  UpdateSelectedString(L"");

  FeQuickSortFsStringList(0, (ObjDescCount - 1));
  
  for (i = 0; i < ObjDescCount; i++) {
    //UnicodeSPrint(MenuStr, sizeof(MenuStr), L"%a%a", pObjDesc[i].Fname,
    UnicodeSPrint(MenuStr, sizeof(MenuStr), L"%s%a", pObjDesc[i].Fname,
      pObjDesc[i].bDirectory ? " <DIR>" : "");
    Token = HiiSetString (HiiHandle, 0, MenuStr, NULL);
    if (pObjDesc[i].Fattr) {
      Help = HiiSetString (HiiHandle, 0, pObjDesc[i].Fattr, NULL);
    } else {
      Help = HiiSetString (HiiHandle, 0, L"", NULL);
    }
    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId++,
      Token, Help, EFI_IFR_FLAG_CALLBACK, 0);
  }

  if(FeGetSaveParamsFlag())
  { 
    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId++,
				TokenSave, HelpSave, EFI_IFR_FLAG_CALLBACK, 0);
  }
_exit:  
  HiiUpdateForm(HiiHandle, FormSetGuid, FormId,
    StartOpCodeHandle, EndOpCodeHandle);
  
  return EFI_SUCCESS;
}


STATIC
EFI_STATUS
FeObtainUsbDriveList(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_GUID *FormSetGuid,
  IN EFI_FORM_ID FormId,
  IN EFI_QUESTION_ID FeQuidStart
  )
{
  EFI_STATUS Status = EFI_ABORTED;
  EFI_QUESTION_ID QuestionId;
  EFI_STRING_ID Token, HelpToken;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  CHAR16 FilePath[256];
  UINTN NumberHandles, Index, UsbDevCount;  
  EFI_HANDLE *pFsp;
  CHAR16 *TempStr;
  CHAR16 *HelpString;

  LOG ((EFI_D_INFO, "%a.%d Entry\n", __FUNCTION__, __LINE__));
  
  gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL,
      &NumberHandles, &pFsp);
  LOG ((EFI_D_INFO, "%a.%d NumberHandles = %d\n", __FUNCTION__, __LINE__, NumberHandles));
  
  QuestionId = FeQuidStart + 1;
  UsbDevCount = 0;
  for (Index = 0; Index < NumberHandles; Index++) {
    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    Status = gBS->HandleProtocol(pFsp[Index], &gEfiDevicePathProtocolGuid, (VOID *) &DevicePath);
    if (Status != EFI_SUCCESS) {
      DEBUG ((EFI_D_ERROR, "%a.%d Error! Index = %d\n", __FUNCTION__, __LINE__, Index));
      continue;
    }

    TempStr = DevicePathToStr(DevicePath);
    if (StrStr(TempStr, L"USB") == NULL) {
      LOG ((EFI_D_INFO, "%a.%d Passed DevicePath = %s\n", __FUNCTION__, __LINE__, TempStr));
      continue;
    }
    
    LOG ((EFI_D_INFO, "%a.%d DevicePath = %s\n", __FUNCTION__, __LINE__, TempStr));
    HelpString = AllocateZeroPool(StrSize(TempStr) + StrSize(L"Device Path : "));
    StrCat(HelpString, L"Device Path : ");
    StrCat(HelpString, TempStr);
    HelpToken = HiiSetString(HiiHandle, 0, HelpString, NULL);
    Token = HiiSetString(HiiHandle, 0, L"USB HDD", NULL);

    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token, HelpToken, 
        EFI_IFR_FLAG_CALLBACK, 0);
    QuestionId++;
    UsbDevCount++;
  }
  
  if (UsbDevCount == 0) {
    DEBUG ((EFI_D_ERROR, "%a.%d Usb Devices not found\n", __FUNCTION__, __LINE__));
    return EFI_NO_MEDIA;
  }
  
  if (UsbDevCount == 1) {
    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    for (Index = 0; Index < NumberHandles; Index++) {
      Status = gBS->HandleProtocol(pFsp[Index], &gEfiDevicePathProtocolGuid, (VOID *) &DevicePath);
      if (EFI_ERROR (Status)) {
        DEBUG ((EFI_D_ERROR, "%a.%d Error! Index = %d\n", __FUNCTION__, __LINE__, Index));
        return Status;
      }
      TempStr = DevicePathToStr(DevicePath);
      if (StrStr(TempStr, L"USB") != NULL) {
        LOG ((EFI_D_INFO, "%a.%d Index = %d; DevicePath = %s\n", __FUNCTION__, __LINE__, Index, TempStr));
        CurDevPath = DevicePath;
        UnicodeSPrint(FilePath, sizeof(FilePath), L"%s:\\", USB_PATH_SHORT_NAME);
        StrCpy(CurrentDevicePath, FilePath);
        FeMode = FE_MODE_BROWSE;
        return EFI_SUCCESS;
      }
    }
    return EFI_NOT_FOUND;
  }

  HiiUpdateForm(HiiHandle, FormSetGuid, FormId, StartOpCodeHandle, EndOpCodeHandle);
  Status = EFI_SUCCESS;

  LOG ((EFI_D_INFO, "%a.%d Status = 0x%0X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
FeLibSetDevicePath(
  IN CHAR16 *Path
  )
{
  if (Path == NULL || StrLen(Path) > MAX_FE_STRING_LEN) {
    return EFI_INVALID_PARAMETER;
  }
  StrCpy(CurrentDevicePath, Path);
  return EFI_SUCCESS;
}


EFI_STATUS
FeCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  EFI_STATUS Status;
  UINTN Len;
  CHAR16 *TmpPtr16;

  if (ActionRequest == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  LOG((EFI_D_INFO, "%a.%d: Action=0x%x\n", __FUNCTION__, __LINE__, Action));

  if (EFI_BROWSER_ACTION_FORM_CLOSE == Action) {
    bFormExitFlag = TRUE;
    return EFI_SUCCESS;
  }
  if (EFI_BROWSER_ACTION_FORM_OPEN == Action) {
    return EFI_SUCCESS;
  }
  if (Action != EFI_BROWSER_ACTION_CHANGING) {
    return EFI_SUCCESS;
  }  

  if (FeMode == FE_MODE_DEV_SELECT) {
    CHAR16 *TmpStr;
    CurrentEvent = QuestionId - SavedStartQId;
    TmpStr = FsDescTableGetShortNameByNum(CurrentEvent);
    UnicodeSPrint(CurrentDevicePath, sizeof(CurrentDevicePath), L"%s:\\", TmpStr);
    LOG((EFI_D_INFO, "%a.%d: CurrentEvent = %X {%X, %X} TmpStr=%s\n", 
        __FUNCTION__, __LINE__, CurrentEvent, QuestionId, SavedStartQId, TmpStr));
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    return EFI_SUCCESS;
  } 
  
  if (FeMode == FE_MODE_USB_DRIVE_SELECT) {
    EFI_HANDLE *pFsp;
    EFI_DEVICE_PATH_PROTOCOL *DevPath;
    UINT8 *pFspUsbDevIdxarr = NULL;
    UINTN NumberHandles, DevIndex, i, j;
    CHAR16 *TempStr;
    CHAR16 FilePath[256];
    
    DevIndex = QuestionId - SavedStartQId - 1;
    LOG ((EFI_D_INFO, "%a.%d DevIndex = %d\n", __FUNCTION__, __LINE__, DevIndex));
    gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &NumberHandles, &pFsp);
    if (DevIndex >= NumberHandles) {
      DEBUG ((EFI_D_ERROR, "%a.%d DevIndex (%d) >= NumberHandles (%d)\n", __FUNCTION__, __LINE__,
          DevIndex, NumberHandles));
      return EFI_ABORTED;
    }
    pFspUsbDevIdxarr = AllocateZeroPool(NumberHandles);
    for (i = 0, j = 0; i < NumberHandles; i++) {
      Status = gBS->HandleProtocol(pFsp[i], &gEfiDevicePathProtocolGuid, (VOID *) &DevPath);
      if (EFI_ERROR(Status)) {      
        DEBUG ((EFI_D_ERROR, "%a.%d Error! i = %d\n", __FUNCTION__, __LINE__, i));
        FreePool(pFspUsbDevIdxarr);
        return Status;
      }
      TempStr = DevicePathToStr(DevPath);
      if (StrStr(TempStr, L"USB") != NULL) {
        LOG ((EFI_D_INFO, "%a.%d i = %d; TempStr = %s;\n", __FUNCTION__, __LINE__, i, TempStr));
        pFspUsbDevIdxarr[j++] = (UINT8)i;
      }
    }
    
    i = pFspUsbDevIdxarr[DevIndex];
    Status = gBS->HandleProtocol(pFsp[i], &gEfiDevicePathProtocolGuid, (VOID *) &DevPath);
    if (EFI_ERROR(Status)) {      
      DEBUG ((EFI_D_ERROR, "%a.%d Error! i = %d\n", __FUNCTION__, __LINE__, i));
      FreePool(pFspUsbDevIdxarr);
      return Status;
    }
    TempStr = DevicePathToStr(DevPath);
    LOG ((EFI_D_INFO, "%a.%d DevIndex = %d; TempStr = %s;\n", __FUNCTION__, __LINE__, DevIndex, TempStr));
    
    FreePool(pFspUsbDevIdxarr);
    CurDevPath = DevPath;
    UnicodeSPrint(FilePath, sizeof(FilePath), L"%s:\\", USB_PATH_SHORT_NAME);
    StrCpy(CurrentDevicePath, FilePath);
    FeMode = FE_MODE_BROWSE;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    bRefreshForm = TRUE;
    return EFI_SUCCESS;
  }
  
  if (FeMode == FE_MODE_BROWSE) {
    CurrentEvent = QuestionId - SavedStartQId - 1;
    if (ObjDescCount == 0) {
      LOG ((EFI_D_INFO, "%a.%d \n", __FUNCTION__, __LINE__));
      return EFI_SUCCESS;
    }

    LOG ((EFI_D_INFO, "%a.%d CurrentEvent = %d, ObjDescCount = %d\n", 
        __FUNCTION__, __LINE__, CurrentEvent, ObjDescCount));
    if (CurrentEvent >= ObjDescCount) {
      if (FeGetSaveParamsFlag()) {
        UnicodeSPrint(SelectedString, sizeof(SelectedString), L"%s%a%a",
            CurrentDevicePath, CurrentFsLevel == 0 ? "" : "\\", 
            DefaultFileName);
        DEBUG((EFI_D_INFO, "%a.%d: SelectedString=%s\n", __FUNCTION__, __LINE__, SelectedString));
        *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
        return EFI_SUCCESS;
      }

      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_SUCCESS;
    }

    LOG((EFI_D_INFO, "SelectedString=%s\n", SelectedString));

    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;

    Len = StrLen(CurrentDevicePath);
    if (!pObjDesc[CurrentEvent].bDirectory) {
      UnicodeSPrint(SelectedString, sizeof(SelectedString), L"%s%a%s",
          CurrentDevicePath, CurrentFsLevel == 0 ? "" : "\\", 
          pObjDesc[CurrentEvent].Fname);
      return EFI_SUCCESS;
    }

    UpperFolder = pObjDesc[CurrentEvent].Fname;
    
    if (StrCmp(pObjDesc[CurrentEvent].Fname, L"..") == 0) {
      LOG ((EFI_D_INFO, "%a.%d Return to Upper Level...\n", __FUNCTION__, __LINE__));
      if (CurrentFsLevel == 0) {
        DEBUG ((EFI_D_ERROR, "%a.%d Fatal error!!!\n", __FUNCTION__, __LINE__));
        return EFI_INVALID_PARAMETER;
      }
      LOG ((EFI_D_INFO, "f--> %s Len=%d\n", CurrentDevicePath, Len));
      TmpPtr16 = CurrentDevicePath + Len - 1;
      if (*TmpPtr16 == L'\\') {
        TmpPtr16--;
      }
      while (TmpPtr16 > CurrentDevicePath && *TmpPtr16 != '\\') {
        TmpPtr16--;
        LOG((EFI_D_INFO, "*TmpPtr16=0x%X\n", *TmpPtr16));
      }
      if (TmpPtr16 == CurrentDevicePath) {
        DEBUG((EFI_D_ERROR, "%a.%d Fatal error!!!\n", __FUNCTION__, __LINE__));
        return EFI_NOT_FOUND;
      }
      TmpPtr16[1] = '\0';
      CurrentFsLevel--;
    } else {   
      LOG((EFI_D_INFO, "%a.%d CurrentDevicePath=%s\n",
        __FUNCTION__, __LINE__, CurrentDevicePath));
      CurrentFsLevel++;
      UnicodeSPrint(CurrentDevicePath + Len, sizeof(CurrentDevicePath) - Len,
          L"%a%s", CurrentDevicePath[Len - 1] == L'\\' ? "" : "\\", UpperFolder);
    }
    bRefreshForm = TRUE;
    
    LOG ((EFI_D_INFO, "%a CurrentDevicePath=%s CurrentFsLevel=%d\n",
        pObjDesc[CurrentEvent].bDirectory ? "DIR" : "FILE", 
        CurrentDevicePath, CurrentFsLevel));
    return EFI_SUCCESS;
  }
 
  return EFI_ABORTED;
}


STATIC
EFI_STATUS
FeDevicesStringList(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_GUID *FormSetGuid,
  IN EFI_FORM_ID FormId,
  IN EFI_QUESTION_ID FeQuidStart
  )
{
  CHAR16 MenuStr[255];
  EFI_STRING_ID Token, Help;
  EFI_QUESTION_ID QuestionId;
  UINTN Idx, Amount;
  
  QuestionId = (EFI_QUESTION_ID) (FeQuidStart);

  Amount = FsDescTableGetItemsCount();

  LOG((EFI_D_INFO, "Amount = %d\n", Amount));
  if (Amount == 0) {
    return EFI_ABORTED;
  }
  
  for (Idx = 0; Idx < Amount; Idx++) {
    
    UnicodeSPrint(MenuStr, sizeof(MenuStr), L"%s", 
      FsDescTableGetShortNameByNum(Idx));

    LOG((EFI_D_INFO, "\t%d .... %s\n", Idx, MenuStr));
    
    Token = HiiSetString (HiiHandle, 0, MenuStr, NULL);
    Help = HiiSetString (HiiHandle, 0, FsDescTableGetFullName(MenuStr), NULL); // /TODO: obtain full name    
    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId++,
      Token, Help, EFI_IFR_FLAG_CALLBACK, 0);     
  }

  HiiUpdateForm(HiiHandle, FormSetGuid, FormId,
    StartOpCodeHandle, EndOpCodeHandle);
  return EFI_SUCCESS;
}

EFI_STATUS	FeDevicesListPrint(VOID)
{
  CHAR16 MenuStr[255];
  UINTN Idx, Amount;
  
  Amount = FsDescTableGetItemsCount();

  if (Amount == 0) {
    return EFI_ABORTED;
  }
  
  DEBUG((EFI_D_INFO, "\tFilesystem devices:\n"));
  for (Idx = 0; Idx < Amount; Idx++) {
    
    UnicodeSPrint(MenuStr, sizeof(MenuStr), L"%s", 
      FsDescTableGetShortNameByNum(Idx));

    DEBUG((EFI_D_INFO, "\t%d .... %s ... %s\n", Idx, MenuStr, FsDescTableGetFullName(MenuStr)));
    
  }

  return EFI_SUCCESS;
}


EFI_STATUS
FeLibSelectFromDevice(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_GUID *FormSetGuid,
  IN EFI_FORM_ID FormId,
  IN EFI_QUESTION_ID FeQuidStart,
  IN UINT16 FeStartLabel,
  IN UINT16 FeEndLabel
  )
{
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_INVALID_PARAMETER;
  
  LOG((EFI_D_INFO, "%a.%d Start\n", __FUNCTION__, __LINE__));

  CurrentHiiHandle = HiiHandle;
  SavedStartQId = FeQuidStart;
  CurrentFsLevel = 0;
  FeMode = FE_MODE_DEV_SELECT;
  CurrentDevicePath[0] = L'\0';

  UpdateSelectedString(L"");
  
  do {
    bRefreshForm = FALSE;
    bFormExitFlag = FALSE;    

    Status = AllocateHiiResources(FormSetGuid, FormId, FeStartLabel,
      FeEndLabel);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", __FUNCTION__, __LINE__, Status));
      goto _exit;
    }

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

    Status = FeDevicesStringList(HiiHandle, FormSetGuid, FormId, FeQuidStart);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_NOT_FOUND;
    }

    Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
      (VOID **) &gFormBrowser2);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", __FUNCTION__, __LINE__, Status));
      goto _exit;
    }

    do {
      ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;

      Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1, FormSetGuid,
          FormId, NULL, &ActionRequest);
      LOG((EFI_D_INFO, "%a.%d: bFormExitFlag=%a\n", __FUNCTION__, __LINE__,
          bFormExitFlag ? "TRUE" : "FALSE"));
    } while (!bFormExitFlag);
    LOG((EFI_D_INFO, "%a.%d: bRefreshForm=%a\n", __FUNCTION__, __LINE__,
      bRefreshForm ? "TRUE" : "FALSE"));
  } while (bRefreshForm);
_exit:
  DestroyFsObjDesc();
  DestroyHiiResources();

  if (StrLen(CurrentDevicePath) == 0) {
    return EFI_ABORTED;
  }
  
  return FeLibTest(HiiHandle, FormSetGuid, FormId, FeQuidStart, FeStartLabel, FeEndLabel);
}

BOOLEAN
FeGetSaveParamsFlag(
  VOID
  )
{
  return SaveParamsFlag;
}

VOID
FeSetSaveParamsFlag(
  BOOLEAN flag
  )
{
  SaveParamsFlag = flag;
}

EFI_STATUS
FeLibTest(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_GUID *FormSetGuid,
  IN EFI_FORM_ID FormId,
  IN EFI_QUESTION_ID FeQuidStart,
  IN UINT16 FeStartLabel,
  IN UINT16 FeEndLabel
  )
{  
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_INVALID_PARAMETER;
  EFI_FILE_HANDLE File;

  LOG((EFI_D_INFO, "%a.%d Start\n", __FUNCTION__, __LINE__));

  if (CurrentDevicePath == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  
  LOG ((EFI_D_INFO, "%a.%d CurrentDevicePath=%s\n", __FUNCTION__, __LINE__, CurrentDevicePath));

  File = LibFsOpenFile16(CurrentDevicePath, EFI_FILE_MODE_READ, 0);
  if (File) {
    LibFsCloseFile(File);
  } else {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_READY;
  }

  CurrentHiiHandle = HiiHandle;
  SavedStartQId = FeQuidStart;
  CurrentFsLevel = 0;
  FeMode = FE_MODE_BROWSE;
  CurDevPath = NULL;
  UpdateSelectedString(L"");
  
  do {
    bRefreshForm = FALSE;
    bFormExitFlag = FALSE;

    if (StrLen(CurrentDevicePath) == 0) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!", __FUNCTION__, __LINE__));
      goto _exit;
    }

    Status = AllocateHiiResources(FormSetGuid, FormId, FeStartLabel, FeEndLabel);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", __FUNCTION__, __LINE__, Status));
      goto _exit;
    }

    Status = FeObtainFsStringList(NULL, HiiHandle, FormSetGuid, FormId, FeQuidStart);
    if (EFI_ERROR(Status)) {
      goto _exit;
    }

    Status = gBS->LocateProtocol(&gEfiFormBrowser2ProtocolGuid, NULL, (VOID **) &gFormBrowser2);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", __FUNCTION__, __LINE__, Status));
      goto _exit;
    }

    do {
      ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;

      Status = gFormBrowser2->SendForm (gFormBrowser2, &HiiHandle, 1, FormSetGuid,
          FormId, NULL, &ActionRequest);
      LOG((EFI_D_INFO, "%a.%d: bFormExitFlag=%a\n", __FUNCTION__, __LINE__,
          bFormExitFlag ? "TRUE" : "FALSE"));
      if (Status != EFI_SUCCESS) {
        DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        bFormExitFlag = TRUE;
        goto _exit;
      }
    } while (!bFormExitFlag);
    LOG((EFI_D_INFO, "%a.%d: bRefreshForm=%a\n", __FUNCTION__, __LINE__,
        bRefreshForm ? "TRUE" : "FALSE"));
  } while (bRefreshForm);

_exit:
  DestroyFsObjDesc();
  DestroyHiiResources();
  return Status;
}


EFI_STATUS
FeLibTestWithDevPath(
  IN CHAR16 *DevicePath,
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_GUID *FormSetGuid,
  IN EFI_FORM_ID FormId,
  IN EFI_QUESTION_ID FeQuidStart,
  IN UINT16 FeStartLabel,
  IN UINT16 FeEndLabel
  )
{
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_INVALID_PARAMETER;
  
  LOG((EFI_D_INFO, "%a.%d Start\n", __FUNCTION__, __LINE__));

  if (DevicePath != NULL) {
    if (CurrentDevicePath == NULL) {
      DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_NOT_FOUND;
    }
    StrCpy(CurrentDevicePath, DevicePath);
  }
  
  CurrentHiiHandle = HiiHandle;
  SavedStartQId = FeQuidStart;
  CurrentFsLevel = 0;
  CurDevPath = NULL;
  FeMode = FE_MODE_USB_DRIVE_SELECT;
  UpdateSelectedString(L"");
  
  do {
    DEBUG ((EFI_D_ERROR, "%a.%d \n", __FUNCTION__, __LINE__));
    bRefreshForm = FALSE;
    bFormExitFlag = FALSE;
    
    if (FeMode == FE_MODE_USB_DRIVE_SELECT) { 
      Status = AllocateHiiResources(FormSetGuid, FormId, FeStartLabel, FeEndLabel);
      if (EFI_ERROR(Status)) {
        DEBUG ((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", __FUNCTION__, __LINE__, Status));
        goto _exit;
      }
      Status = FeObtainUsbDriveList(HiiHandle, FormSetGuid, FormId, FeQuidStart);
      if (EFI_ERROR(Status)) {
        DEBUG ((EFI_D_ERROR, "%a.%d Error! \n", __FUNCTION__, __LINE__));
        goto _exit;
      }
    }
    
    if (FeMode == FE_MODE_BROWSE) {
      Status = AllocateHiiResources(FormSetGuid, FormId, FeStartLabel, FeEndLabel);
      if (EFI_ERROR(Status)) {
        DEBUG ((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", __FUNCTION__, __LINE__, Status));
        goto _exit;
      }
      Status = FeObtainFsStringList(CurDevPath, HiiHandle, FormSetGuid, FormId, FeQuidStart);
      if (EFI_ERROR(Status)) {
        DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        goto _exit;
      }
    }
    
    Status = gBS->LocateProtocol(&gEfiFormBrowser2ProtocolGuid, NULL, (VOID **) &gFormBrowser2);
    if (EFI_ERROR(Status)) {
      DEBUG ((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", __FUNCTION__, __LINE__, Status));
      goto _exit;
    }
    
    do {
      LOG ((EFI_D_INFO, "%a.%d \n", __FUNCTION__, __LINE__));
      ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
      Status = gFormBrowser2->SendForm (gFormBrowser2, &HiiHandle, 1, FormSetGuid, 
          FormId, NULL, &ActionRequest);
      if (Status != EFI_SUCCESS) {
        DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        bFormExitFlag = TRUE;
        goto _exit;
      }
    } while (!bFormExitFlag);
  } while (bRefreshForm);

_exit:
  DestroyFsObjDesc();
  DestroyHiiResources();
  return Status;
}
