/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/Lib/History.h>
#include <Library/Lib/Users.h>
#include <Library/Lib/AdminMainPage.h>
#include <Protocol/HistoryHandlerProto.h>
#include "HistoryStrings.h"


#define LOG(MSG)

STATIC MULTIBOOT_CONFIG *CurrentConfig;
STATIC EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
STATIC EFI_HII_HANDLE CurrentHiiHandle;
STATIC VOID *StartOpCodeHandle, *EndOpCodeHandle;

STATIC HISTORY_RECORD *pLastFoundHistoryRecord;
STATIC HISTORY_STORAGE gHistoryStorage;
STATIC UINT32 gHistoryRecId;

STATIC BOOLEAN bFormExitFlag, bRefreshForm;
STATIC int CurrentEvent;
STATIC UINT8 DefautSeverityNum;
STATIC UINT8 AutoCleanOnVal;
STATIC BOOLEAN bAddRecordQuite = FALSE;
STATIC HISTORY_HANDLER_PROTOCOL *gHistoryHandlerProtocol;



VOID
HistorySetAddRecordQuietFlag (
  BOOLEAN bFlag
  )
{
  bAddRecordQuite = bFlag;
}

STATIC 
USER_INFO *
GetLdapUsrInfo (
  VOID
);

STATIC
EFI_STATUS
FindUserRecordByIdWrapper (
  IN UINT8 UserId
  )
{
  EFI_STATUS Status;
  UsersStorageSetDummyReadFlag(TRUE);
  Status = UserFindRecordById(UserId);
  UsersStorageSetDummyReadFlag(FALSE);
  return Status;
}

STATIC
VOID
HistoryShowRecord (
  IN HISTORY_RECORD *pRec
  )
{
  if (pRec == NULL) {
    return;
  }

  LOG((EFI_D_ERROR, "pRec->RecId=0x%X\n", pRec->RecId));
  LOG((EFI_D_ERROR, "pRec->TimeStamp=0x%X\n", pRec->TimeStamp));
  LOG((EFI_D_ERROR, "pRec->EventCode=0x%X\n", pRec->EventCode));
  LOG((EFI_D_ERROR, "pRec->UserId=0x%X\n", pRec->UserId));
  LOG((EFI_D_ERROR, "pRec->Severity=0x%X\n", pRec->Severity));
  LOG((EFI_D_ERROR, "pRec->Flags=0x%X\n", pRec->Flags));
}

STATIC
UINTN
HistoryCountUnloaded (
  VOID
  )
{
  HISTORY_RECORD *pRec;
  UINTN Count;
  BOOLEAN bStart;
  
  for (Count = 0, bStart = TRUE; ; ) {
    pRec = HistoryGetNextRecord(bStart);
    if (bStart) {
      bStart = FALSE;
    }
    if (!pRec) {
      break;
    }
#if 0   /* DEBUG */
    HistoryShowRecord(pRec);
#endif  /* DEBUG */
    LOG((EFI_D_ERROR, "%a.%d Flags=0x%X\n", __FUNCTION__, __LINE__, pRec->Flags));
    if (pRec->Flags & HISTORY_RECORD_FLAG_CLEAN_EN) {
      continue;
    }
    Count++;
  }
  return Count;
}

STATIC
UINTN
HistoryCountUnloadedButNoDebug (
  VOID
  )
{
  HISTORY_RECORD *pRec;
  UINTN Count;
  BOOLEAN bStart;
  
  for (Count = 0, bStart = TRUE; ; ) {
    pRec = HistoryGetNextRecord(bStart);
    if (bStart) {
      bStart = FALSE;
    }
    if (!pRec) {
      break;
    }
#if 0   /* DEBUG */
    HistoryShowRecord(pRec);
#endif  /* DEBUG */
    LOG((EFI_D_ERROR, "%a.%d Flags=0x%X\n", __FUNCTION__, __LINE__, pRec->Flags));
    if (pRec->Flags & HISTORY_RECORD_FLAG_CLEAN_EN) {
      continue;
    }
    if (pRec->Severity & SEVERITY_LVL_DEBUG) {
      continue;
    }
    if (pRec->EventCode == HEVENT_OUTSWAP_HISTORY_TO_USB) {
      continue;
    }    
    Count++;
  }
  return Count;
}



STATIC
BOOLEAN
HistoryStorageOverflow (
  VOID
  )
{ 
  UINTN CntUnloaded, TotalRecords;

  CntUnloaded = HistoryCountUnloaded();
  TotalRecords = gHistoryStorage.DataLen / HISTORY_RECORD_SIZE;

  if (gHistoryStorage.Flags & HISTORY_FLAGS_OVERFLOW) {
    return TRUE;
  }
    
  if (TotalRecords >= HISTORY_RECORDS_AMOUNT) {
    if (CntUnloaded == TotalRecords) {
      return TRUE;
    }
    if ((gHistoryStorage.Flags & HISTORY_FLAGS_AUTO_CLEAN_EN) == 0) {
      return TRUE;
    }
  }
  LockAdminMenu(0);
  return FALSE;
}

VOID
HistoryCheckOverflow (
  VOID
  )
{
  if (EFI_SUCCESS != HistoryStorageGetData(&gHistoryStorage)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    MsgInternalError(INT_ERR_WHILE_READ_HISTORY_STORAGE);
  }
  if (HistoryStorageOverflow()) {
    ShowErrorPopup(CurrentHiiHandle, 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BIOS_LOG_FULL), NULL));
    while (1) {
      BeepCode(MEMORY_ERR_CODE, MEMORY_ERR_CODE_LEN, ERR_BEEP_FREQ,
        LONG_ERR_BEEP_MS, SHORT_ERR_BEEP_MS, ERR_BEEP_DELAY);

      MicroSecondDelay(500000);
    }
  }
}


STATIC
UINT8 
GetHighestSetBitNum (
  IN UINT8 Val
  )
{
  if (Val & 0xF0) {
    if (Val & 0xC0) {
      return Val & 0x80 ? 7 : 6;
    } else {
      return Val & 0x20 ? 5 : 4;
    }
  } else if (Val &0x0C) {
    return Val & 0x8 ? 3 : 2;
  }
  return Val & 0x2 ? 1 : 0;
}

STATIC
EFI_STRING_ID
HistoryGetSeverityString (
  IN UINT8 Severity
  )
{
  EFI_STRING_ID SeverityStr[] = { 
//STRING_TOKEN(STR_UNKNOWN_EVENT),
    STRING_TOKEN(STR_SEVERITY_EMERGENCY),
    STRING_TOKEN(STR_SEVERITY_ALERT),
    STRING_TOKEN(STR_SEVERITY_CRITICAL),
    STRING_TOKEN(STR_SEVERITY_ERROR),
    STRING_TOKEN(STR_SEVERITY_WARNING),
    STRING_TOKEN(STR_SEVERITY_NOTICE),
    STRING_TOKEN(STR_SEVERITY_INFO),
    STRING_TOKEN(STR_SEVERITY_DEBUG)
  };
  UINT8 Num;
  
  Num = GetHighestSetBitNum(Severity);
  if (Num >= 8) {
    return STRING_TOKEN(STR_UNKNOWN_EVENT);
  }
  return SeverityStr[Num];
}


STATIC
CHAR8 *
HistoryGetEventString (
  IN UINT16 EventCode
  )
{
  STATIC CHAR8 Str8[255];
  
  AsciiSPrint(Str8, sizeof(Str8), "%s 0x%04X", 
    HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_EVENT), NULL), EventCode);
  return Str8;
}

STATIC
CHAR16 *
HistoryGetEventString16 (
  IN UINT16 EventCode
  )
{
  STATIC CHAR16 Str16[255];
  
  UnicodeSPrint(Str16, sizeof(Str16), L"%s 0x%04X", 
    HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_EVENT), NULL), EventCode);
  return Str16;
}


STATIC
VOID
DestroyHiiResources (
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
AllocateHiiResources (
  VOID
  )
{
  EFI_IFR_GUID_LABEL *StartLabel;
  EFI_IFR_GUID_LABEL *EndLabel;
  EFI_GUID FormSetGuid = FORMSET_HISTORY_GUID;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_FORM_ID FormId = HISTORY_PAGE_ID;
  
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
  StartLabel->Number       = LABEL_HISTORY_LIST_START;

  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      EndOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_HISTORY_LIST_END;
  
  Status = EFI_SUCCESS;
  
  HiiUpdateForm(CurrentHiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  
_exit:  
  return Status;
}


EFI_STATUS
HistoryPageCallback (
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  EFI_STATUS Status;

  if (ActionRequest == NULL) {
    return EFI_INVALID_PARAMETER;
  }

#if 0
  LOG((EFI_D_ERROR, "%a.%d: Action=0x%x\n", __FUNCTION__, __LINE__, Action));
#endif

  if (EFI_BROWSER_ACTION_FORM_CLOSE == Action) {
    if (QuestionId >= HISTORY_VIEW_DEL_REC_START && 
        QuestionId <= HISTORY_VIEW_DEL_REC_END) {  
      bRefreshForm = CurrentEvent == HISTORY_VIEW_CLEAN_ID ? 
        FALSE : TRUE;
    }
    bFormExitFlag = TRUE;
    return EFI_SUCCESS;
  }
  if (EFI_BROWSER_ACTION_FORM_OPEN == Action) {
    return EFI_SUCCESS;
  }
  if (Action != EFI_BROWSER_ACTION_CHANGING) {
    return EFI_SUCCESS;
  }

  CurrentEvent = QuestionId;
  
  if (Value == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  if (gHistoryHandlerProtocol == NULL) {
    Status = gBS->LocateProtocol (
              &gHistoryHandlerProtocolGuid, 
              NULL, 
              (VOID **) &gHistoryHandlerProtocol
              );
  }

  if (gHistoryHandlerProtocol) {
    gHistoryHandlerProtocol->LockOp (gHistoryHandlerProtocol);
  }
  

  switch (QuestionId) {
  case HISTORY_CLEAN_ALL_ID:
    {
      UINTN i, RecordsCount, OkCnt;
      
      RecordsCount = gHistoryStorage.DataLen / sizeof(HISTORY_RECORD);
      LOG((EFI_D_ERROR, "RecordsCount=%d\n", RecordsCount));

      if (0 == RecordsCount) {
        ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_HISTORY_LOG_EMPTY), NULL));
        break;
      }
      
      if (HistoryCountUnloaded() == RecordsCount) {
        ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_HISTORY_NEED_TO_OUTSWAP), NULL));
        break;
      }

      gST->ConOut->ClearScreen(gST->ConOut);
      ShowInfoPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_WAIT_FOR_CLEANING_HISTORY), NULL));

      for (i = 0, OkCnt = 0, Status = EFI_SUCCESS; i < RecordsCount; i++) {
        Status = HistoryCleanByNum(0, FALSE);
        if (EFI_WARN_DELETE_FAILURE == Status) {
          HISTORY_RECORD *pRec;

          pRec = HistoryGetLastFoundedRecord();
          LOG((EFI_D_ERROR, "%a.%d: Status=0x%X i=%d\n", 
           __FUNCTION__, __LINE__, Status, i));
#if 0          
          LOG((EFI_D_ERROR, "//////////////////////////////////\n"));
          HistoryShowRecord(pRec);
#endif          
          continue; /* it is non loaded record */
        }

        if (EFI_ERROR(Status)) {
          LOG((EFI_D_ERROR, "%a.%d: Status=0x%X i=%d\n", 
             __FUNCTION__, __LINE__, Status, i));
#if 0          
          ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle,
            STRING_TOKEN(STR_HISTORY_RECORDS_DEL_ERROR), NULL));
#endif

          break;
        }
        OkCnt++;
        LOG((EFI_D_ERROR, "%a.%d: OkCnt=%d i=%d\n", 
           __FUNCTION__, __LINE__, OkCnt, i));
      }
      if (EFI_ERROR(Status)) {
        OkCnt = 0;
      }
      Status = HistoryStorageSetRawData(gHistoryStorage.Data, 
        gHistoryStorage.DataLen);

      gST->ConOut->ClearScreen(gST->ConOut);
      if (OkCnt && !EFI_ERROR(Status)) {
        ShowSuccessPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_HISTORY_RECORDS_DEL_SUCCESS), NULL));
      } else {
        ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_HISTORY_RECORDS_DEL_ERROR), NULL));        
      }
    }
    break;
    
  case HISTORY_VIEW_CLEAN_ID:
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;
  
  case HISTORY_OUTSWAP_TO_USB_ID:
    if (HistoryCountUnloaded() == 0) {
      ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_HISTORY_NO_REC_TO_OUTSWAP), NULL));
      break;
    }
    gST->ConOut->ClearScreen(gST->ConOut);
    ShowInfoPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_WAIT_FOR_SAVING_HISTORY), NULL));

    Status = HistoryOutswapToUSB();

    HistorySetAddRecordQuietFlag(TRUE);
    HistoryAddRecord(HEVENT_OUTSWAP_HISTORY_TO_USB, GetCurrentUserId(),
        SEVERITY_LVL_DEBUG, EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
    HistorySetAddRecordQuietFlag(FALSE);

    gST->ConOut->ClearScreen(gST->ConOut);
    if (EFI_ERROR(Status)) {
      ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_ERR_DATA_STORE), NULL));
    } else {
      ShowSuccessPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_DATA_STORE_SUCCESS), NULL));
    }
    break;
  
  case HISTORY_SEVERITY_LEVEL_ID:
    HistoryStorageGetData (&gHistoryStorage);
    if (Value->u8) {
      gHistoryStorage.CurSeverity = ((Value->u8 - 1) << 1) + 1;
    }
    HistoryFlush ();
    HistorySetAddRecordQuietFlag(TRUE);
    HistoryAddRecord(
        HEVENT_HISTORY_SEVERITY_LVL_CHANGE, 
        GetCurrentUserId(),
        SEVERITY_LVL_ALERT, 
        HISTORY_RECORD_FLAG_RESULT_OK |
        HISTORY_RECORD_FLAG_NO_REREAD);
    HistorySetAddRecordQuietFlag(FALSE);
    bRefreshForm = TRUE;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;
  
  case HISTORY_ENABLE_AUTO_CLEAN_ID:
    HistoryStorageGetData (&gHistoryStorage);
    if (Value->u8 == AutoCleanOnVal) {
      gHistoryStorage.Flags |= HISTORY_FLAGS_AUTO_CLEAN_EN;
    } else {
      gHistoryStorage.Flags &= ~HISTORY_FLAGS_AUTO_CLEAN_EN;
    }
    HistoryFlush ();
    HistorySetAddRecordQuietFlag(TRUE);
    HistoryAddRecord(
        HEVENT_HISTORY_AUTO_CLR_CHANGE, 
        GetCurrentUserId(),
        SEVERITY_LVL_INFO, 
        HISTORY_RECORD_FLAG_RESULT_OK);
    HistorySetAddRecordQuietFlag(FALSE);
    break;
  
  default:
    if (QuestionId > HISTORY_VIEW_DEL_REC_START && 
        QuestionId <= HISTORY_VIEW_DEL_REC_END) {
      LOG((EFI_D_ERROR, "%a.%d --> HistoryCleanByNum (%d)\n",
        __FUNCTION__, __LINE__, 
        (UINT32)(QuestionId - 1 - HISTORY_VIEW_DEL_REC_START)));
      Status = HistoryCleanByNumRev (
        (UINTN)(QuestionId - 1 - HISTORY_VIEW_DEL_REC_START), TRUE);
      if (EFI_ERROR(Status) || Status == EFI_WARN_DELETE_FAILURE) {
        ShowErrorPopup(CurrentHiiHandle, 
          HiiGetString(CurrentHiiHandle, 
            STRING_TOKEN(STR_HISTORY_ERR_RECORD_DEL), NULL));
      } else {
        *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
        CurrentEvent = HISTORY_VIEW_CLEAN_ID;
      }
    }
    break;
  }
  if (gHistoryHandlerProtocol) {
    gHistoryHandlerProtocol->UnLockOp (gHistoryHandlerProtocol);
  }
  HistoryStorageOverflow();
  return EFI_SUCCESS;
}


EFI_STATUS
HistoryStoragePresent (
  VOID
  )
{
  SetStorageAttributes(STORAGE_WRITE_ONLY_ATTR);
  return StoragePresent(HISTORY_STORAGE_VAR_NAME, &gHistoryStorageGuid);
}


EFI_STATUS
HistoryStorageInitEmpty (
  VOID
  )
{
  EFI_STATUS Status;

  LOG((EFI_D_ERROR, "%a.%d: Start\n", __FUNCTION__, __LINE__));
  Status = StorageInitEmpty(HISTORY_STORAGE_VAR_NAME, &gHistoryStorageGuid,
    NULL, 0, NULL, FALSE);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d: Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  gHistoryStorage.CurSeverity = SEVERITY_LVL_DEFAULT;
  gHistoryStorage.DataLen = 0;
#if 0  
  return gRT->SetVariable(HISTORY_STORAGE_VAR_NAME, &gHistoryStorageGuid,
    STORAGE_WRITE_ONLY_ATTR, sizeof(HISTORY_STORAGE), (UINT8*)&gHistoryStorage);
#else
  SetStorageAttributes(STORAGE_WRITE_ONLY_ATTR);
  Status = StorageSetRawData2(&gHistoryStorageGuid,
    HISTORY_STORAGE_VAR_NAME, (UINT8*)&gHistoryStorage,
    sizeof(HISTORY_STORAGE) - HISTORY_SIZE,
    (sizeof(HISTORY_STORAGE) + HISTORY_MAX_CARD_SIZE) / 
      HISTORY_MAX_CARD_SIZE + 1, 
    sizeof(HISTORY_STORAGE),
    HISTORY_MAX_CARD_SIZE, FALSE);
#endif
  return Status;
}


EFI_STATUS
HistoryStorageGetData (
  IN OUT HISTORY_STORAGE *HistoryStorage
  )
{
  EFI_STATUS Status;
  STORAGE_DATA StorageData;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
#if 0  
  Status = StorageGetData(HISTORY_STORAGE_VAR_NAME, &gHistoryStorageGuid,
    (UINT8*)&gHistoryStorage, sizeof(HISTORY_STORAGE));
#else
  StorageData.Data = (UINT8*)&gHistoryStorage;
  SetStorageAttributes(STORAGE_WRITE_ONLY_ATTR);
  Status = StorageGetData2(&gHistoryStorageGuid, HISTORY_STORAGE_VAR_NAME,
    &StorageData, sizeof(HISTORY_STORAGE));  
#endif
  if (StorageData.DataLen < (sizeof(HISTORY_STORAGE) - HISTORY_SIZE)) {
    return EFI_ABORTED;
  }
  gHistoryStorage.DataLen = StorageData.DataLen - 
    (sizeof(HISTORY_STORAGE) - HISTORY_SIZE);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  if (HistoryStorage != NULL) {
    if (HistoryStorage != &gHistoryStorage) {
      LOG((EFI_D_ERROR, "%a.%d \n", __FUNCTION__, __LINE__));
      CopyMem (HistoryStorage, &gHistoryStorage, sizeof(HISTORY_STORAGE));
      LOG((EFI_D_ERROR, "%a.%d \n", __FUNCTION__, __LINE__));
    }
  }
  return Status;
}


EFI_STATUS
HistoryStorageCheckIntegrity (
  VOID
  )
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return StorageCheckIntegrity(HISTORY_STORAGE_VAR_NAME, &gHistoryStorageGuid,
    (UINT8*)&gHistoryStorage, sizeof(HISTORY_STORAGE), &gHistoryStorage.DataLen, 
    &gHistoryStorage.CsType);
}


EFI_STATUS
HistoryStorageSetRawData (
  IN UINT8 *RawData,
  IN UINTN RawDataLen
  )
{
  EFI_STATUS Status;
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
#if 0  
  return StorageSetRawData(HISTORY_STORAGE_VAR_NAME, &gHistoryStorageGuid,
    (UINT8*)&gHistoryStorage, 
    //sizeof(gHistoryStorage.Data), 
    sizeof(HISTORY_STORAGE),
    &gHistoryStorage.DataLen, &gHistoryStorage.CsType, RawData, RawDataLen);
#else
  if (RawData == NULL || RawDataLen > HISTORY_SIZE) {
    return EFI_INVALID_PARAMETER;
  }

  DEBUG((EFI_D_ERROR, "RawDataLen=%d\n", RawDataLen));
  DEBUG((EFI_D_ERROR, "sizeof(HISTORY_STORAGE)=%d\n", sizeof(HISTORY_STORAGE)));
  
  CopyMem(gHistoryStorage.Data, RawData, RawDataLen);
  gHistoryStorage.DataLen = (UINT32)(RawDataLen & 0xFFFFFFFF);
  SetStorageAttributes(STORAGE_WRITE_ONLY_ATTR);
  Status = StorageSetRawData2(&gHistoryStorageGuid, HISTORY_STORAGE_VAR_NAME,
    (UINT8*)&gHistoryStorage,
    sizeof(HISTORY_STORAGE) - HISTORY_SIZE + gHistoryStorage.DataLen,
    (sizeof(HISTORY_STORAGE) + HISTORY_MAX_CARD_SIZE) / 
      HISTORY_MAX_CARD_SIZE + 1,
    sizeof(HISTORY_STORAGE),
    HISTORY_MAX_CARD_SIZE,
    FALSE);
#endif
  return Status; 
}


HISTORY_RECORD *
HistoryGetLastFoundedRecord (
  VOID
  )
{
  return pLastFoundHistoryRecord;
}


STATIC
EFI_STATUS
HistoryFindRecordByFieldsMask (
  IN UINT32 Mask,
  IN VOID *Value
  )
{
//  EFI_STATUS Status;
  UINTN TotalLen, RecordSize;
  UINT32 *TmpPtr32;
  UINT16 *TmpPtr16;
  UINT8 *DataPtr, *TmpPtr8;
  HISTORY_RECORD *pRec;
  UINTN Index, *TmpPtrN;
  
  LOG((EFI_D_ERROR, "%a.%d Start Mask=0x%08X\n", 
    __FUNCTION__, __LINE__, Mask));
  
  pLastFoundHistoryRecord = NULL;

  if (gHistoryStorage.DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d: gHistoryStorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, gHistoryStorage.DataLen));
    return EFI_NOT_FOUND;
  }
  
  TotalLen = gHistoryStorage.DataLen;
  DataPtr = gHistoryStorage.Data;
  
  TmpPtr8 = (UINT8*)Value;
  TmpPtr16 = (UINT16*)Value;
  TmpPtr32 = (UINT32*)Value;
  TmpPtrN = (UINTN*)Value;
  
  Index = 0;
  
  while (TotalLen) {
    pRec = (HISTORY_RECORD*)DataPtr;
    RecordSize = sizeof(HISTORY_RECORD);
    //LOG((EFI_D_ERROR, "RecordSize=%d\n", RecordSize));

    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, "%a.%d: Attention!!! History storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }

    if ((Mask & HISTORY_FIELD_REC_ID) && pRec->RecId == *TmpPtr32) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    if ((Mask & HISTORY_FIELD_TIME_STAMP) && pRec->TimeStamp == *TmpPtr32) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    if ((Mask & HISTORY_FIELD_EVENT_CODE) && pRec->EventCode == *TmpPtr16) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    if ((Mask & HISTORY_FIELD_USER_ID) && pRec->UserId == *TmpPtr8) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    if ((Mask & HISTORY_FIELD_SEVERITY) && pRec->Severity == *TmpPtr8) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    if ((Mask & HISTORY_FIELD_FLAGS) && pRec->Flags == *TmpPtr8) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    
    if ((Mask & HISTORY_SEARCH_BY_NUM) && Index == *TmpPtrN) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    
    TotalLen -= RecordSize;
    DataPtr += RecordSize;
    Index++;
  }
  LOG((EFI_D_ERROR, "%a.%d EFI_NOT_FOUND\n", __FUNCTION__, __LINE__));
  return EFI_NOT_FOUND;
}


EFI_STATUS
HistoryFindRecordByRecNum (
  IN UINTN RecNum
  )
{
  EFI_STATUS Status;
  
  LOG((EFI_D_ERROR, "%a.%d RecNum=0x%X\n", __FUNCTION__, __LINE__, RecNum));
  Status = HistoryFindRecordByFieldsMask(HISTORY_SEARCH_BY_NUM, &RecNum);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
HistoryFindRecordById (
  IN UINT32 HistoryRecId
  )
{
  EFI_STATUS Status;
  
  LOG((EFI_D_ERROR, "%a.%d HistoryRecId=0x%X\n", __FUNCTION__, __LINE__, HistoryRecId));
  Status = HistoryFindRecordByFieldsMask(HISTORY_FIELD_REC_ID, &HistoryRecId);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

EFI_STATUS
HistoryFindRecordByUserId(
  IN UINT8 UserId
  )
{
  EFI_STATUS Status;
  
  LOG((EFI_D_ERROR, "%a.%d UserId=0x%X\n", __FUNCTION__, __LINE__, UserId));
  Status = HistoryFindRecordByFieldsMask(HISTORY_FIELD_USER_ID, &UserId);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
HistoryFindRecordByTimeStamp (
  IN UINT32 TimeStamp
  )
{
  EFI_STATUS Status;
  
  LOG((EFI_D_ERROR, "%a.%d TimeStamp=0x%X\n", __FUNCTION__, __LINE__, TimeStamp));
  Status = HistoryFindRecordByFieldsMask(HISTORY_FIELD_TIME_STAMP, &TimeStamp);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
HistoryFindRecordByEventCode (
  IN UINT16 EventCode
  )
{
  EFI_STATUS Status;
  
  LOG((EFI_D_ERROR, "%a.%d EventCode=0x%X\n", __FUNCTION__, __LINE__, EventCode));
  Status = HistoryFindRecordByFieldsMask(HISTORY_FIELD_EVENT_CODE, &EventCode);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


STATIC
EFI_STATUS
ObtainNewHistoryRecordId (
  IN OUT UINT32 *pRecId
  )
{
  UINT32 i;
  BOOLEAN bHaveNewId;
  
  for (i = 0, bHaveNewId = FALSE; i <= 0xFFFFFFFF; i++) {
/* Zero value of gHistoryRecId will be reserved */
    if (gHistoryRecId == 0) {
      gHistoryRecId++;
    }
    if (EFI_SUCCESS == HistoryFindRecordById(gHistoryRecId)) {
      gHistoryRecId++;
    } else {
      bHaveNewId = TRUE;
      break;
    }
  }
  if (!bHaveNewId) {
    return EFI_OUT_OF_RESOURCES;
  }

  LOG((EFI_D_ERROR, "%a.%d: gHistoryRecId=0x%02X\n", 
    __FUNCTION__, __LINE__, gHistoryRecId));
  
  *pRecId = gHistoryRecId;
  gHistoryRecId++;
  return EFI_SUCCESS;
}


EFI_STATUS
HistoryCommonInit (
  IN EFI_HII_HANDLE HiiHandle
  )
{
  EFI_STATUS Status;

  bFormExitFlag = FALSE;
  bRefreshForm = FALSE;
  
  CurrentEvent = 0;
  
  //ZeroMem(&gHistoryStorage, sizeof(HISTORY_STORAGE));
  if (CurrentConfig == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  CurrentHiiHandle = HiiHandle;

  Status = gBS->LocateProtocol (
              &gHistoryHandlerProtocolGuid, 
              NULL, 
              (VOID **) &gHistoryHandlerProtocol
              );
  LOG ((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  
  return EFI_SUCCESS;
}


STATIC
EFI_STATUS
HistoryListPageStringsRev (
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_STRING_ID Title,
  EFI_QUESTION_ID StartQId
  )
{
//  EFI_STATUS Status;
  UINTN TotalLen, RecordSize;
  UINT8 *DataPtr;
  HISTORY_RECORD *pRec;
  UINTN Index;
  EFI_STATUS Status;
  USER_INFO *pUser;
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_GUID FormSetGuid = FORMSET_HISTORY_GUID;
  EFI_FORM_ID FormId = HISTORY_PAGE_ID;
  CHAR16 TmpStr16[255], *Str16;
  CHAR16 HelpStr16[255];
  EFI_TIME EfiTime;
//  UINT32 Index;
  USER_INFO UnknownUsr, AmtUsr, SuUsr;
  
  LOG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));

  UnknownUsr.UserId = USER_UNKNOWN_ID;
  Str16 = HiiGetString(HiiHandle, STRING_TOKEN(STR_USR_NAME_UNKNOWN), NULL);
  StrCpy(UnknownUsr.UserName, Str16);
  StrCpy(UnknownUsr.UserFIO, Str16);

  AmtUsr.UserId = USER_AMT_ID;
  StrCpy(AmtUsr.UserName, L"AMT");
  StrCpy(AmtUsr.UserFIO, L"AMT");

  SuUsr.UserId = USER_SU_ID;
  StrCpy(SuUsr.UserName, L"Super");
  StrCpy(SuUsr.UserFIO, L"Super");
  
  if (EFI_SUCCESS != AllocateHiiResources()) {
    return EFI_OUT_OF_RESOURCES;
  }
  
#if 0
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
#else
  HelpToken = STRING_TOKEN(STR_HISTORY_PRESS_ENTER_TO_DELETE); //HiiSetString (HiiHandle, 0, L"", NULL);
#endif

  QuestionId = (EFI_QUESTION_ID)StartQId;

  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Title,
        HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);
  HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  QuestionId++;
  
  Index = 1;
  
  pRec = HistoryGetNextRecord(TRUE);
  if (NULL == pRec) {
    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, STRING_TOKEN(STR_EMPTY),
        HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  }   

  if (gHistoryStorage.DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d: gHistoryStorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, gHistoryStorage.DataLen));
    return EFI_NOT_FOUND;
  }

  RecordSize = sizeof(HISTORY_RECORD);
  TotalLen = gHistoryStorage.DataLen;
  DataPtr = gHistoryStorage.Data + TotalLen - RecordSize;
  
  Index = TotalLen / RecordSize;
  
  while (TotalLen) {
    pRec = (HISTORY_RECORD*)DataPtr;
    
    //LOG((EFI_D_ERROR, "RecordSize=%d\n", RecordSize));

    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, "%a.%d: Attention!!! History storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }

    if (pRec->UserId == USER_UNKNOWN_ID) {
      pUser = &UnknownUsr;
    } else if (pRec->UserId == USER_AMT_ID) {
      pUser = &AmtUsr;
    } else if (pRec->UserId == USER_SU_ID) {
      pUser = &SuUsr;
    } else {
      Status = FindUserRecordByIdWrapper(pRec->UserId);
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
        //return Status;
        pUser = &UnknownUsr;
      } else {
        pUser = UserGetLastFoundedInfo();
      }
    }
    if (pUser == NULL) {
      LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
      return EFI_NOT_FOUND;
    }

    ConvU32ToEfiTime(pRec->TimeStamp, &EfiTime);

    Str16 = HiiGetString(CurrentHiiHandle, 
      HistoryGetSeverityString(pRec->Severity), NULL);

    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), 
      L"[%a] %04d %02d.%02d.%04d %02d:%02d:%02d %s %s %s 0x%04X %s",
      pRec->Flags & HISTORY_RECORD_FLAG_CLEAN_EN ? "X" : " ",
      Index--,
      EfiTime.Day, EfiTime.Month, EfiTime.Year, EfiTime.Hour, EfiTime.Minute,
      EfiTime.Second,
      pUser->UserName, pUser->UserFIO,
      Str16,
      pRec->EventCode,
      pRec->Flags & HISTORY_RECORD_FLAG_RESULT_OK ? 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_SUCCESS), NULL) : 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_ERROR), NULL)
      );
    
    LOG((EFI_D_ERROR, "::-->%s\n", TmpStr16));
  
    Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
    LOG((EFI_D_ERROR, "%a.%d Token = %d\n",
      __FUNCTION__, __LINE__, Token));

    UnicodeSPrint (HelpStr16, sizeof (HelpStr16), L"%s\n\n%s\n\n%s %s", 
      HiiGetString (
        HiiHandle,
        STRING_TOKEN(STR_HISTORY_PRESS_ENTER_TO_DELETE),
        NULL),
      HiiGetString (
        HiiHandle,
        GetHistoryStringByIdx (pRec->EventCode),
        NULL),
      HiiGetString (
        HiiHandle,
        STRING_TOKEN (STR_HEVENT_RESULT_STATUS),
        NULL
        ),
      pRec->Flags & HISTORY_RECORD_FLAG_RESULT_OK ? 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_SUCCESS), NULL) : 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_ERROR), NULL)
      );

    DEBUG ((EFI_D_ERROR, "%a.%d HelpStr16 = %s\n",
      __FUNCTION__, __LINE__, HelpStr16));

    HelpToken = HiiSetString (HiiHandle, 0, HelpStr16, NULL);

    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, EFI_IFR_FLAG_CALLBACK, 0);

    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
    //pRec = HistoryGetNextRecord(FALSE);
    QuestionId++;

    TotalLen -= RecordSize;
    DataPtr -= RecordSize;
    //Index--;
  }
  LOG((EFI_D_ERROR, "%a.%d EFI_NOT_FOUND\n", __FUNCTION__, __LINE__));
  return EFI_SUCCESS;
}


EFI_STATUS
HistoryFindRecordByRecNumRev (
  IN UINTN RecNum
  )
{
  UINTN TotalLen, RecordSize;
  UINT8 *DataPtr;
  HISTORY_RECORD *pRec;
  UINTN Index;
  
  LOG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));
  pRec = HistoryGetNextRecord(TRUE);  
  if (gHistoryStorage.DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d: gHistoryStorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, gHistoryStorage.DataLen));
    return EFI_NOT_FOUND;
  }

  RecordSize = sizeof(HISTORY_RECORD);
  TotalLen = gHistoryStorage.DataLen;
  DataPtr = gHistoryStorage.Data + TotalLen - RecordSize;
  
  Index = 0;
  
  while (TotalLen) {
    pRec = (HISTORY_RECORD*)DataPtr;
    if (Index == RecNum) {
      pLastFoundHistoryRecord = pRec;
      return EFI_SUCCESS;
    }
    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, "%a.%d: Attention!!! History storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }

    TotalLen -= RecordSize;
    DataPtr -= RecordSize;
    Index++;
  }
  LOG((EFI_D_ERROR, "%a.%d EFI_NOT_FOUND\n", __FUNCTION__, __LINE__));
  return EFI_NOT_FOUND;
}



STATIC
EFI_STATUS
HistoryListPageStrings (
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_STRING_ID Title,
  EFI_QUESTION_ID StartQId
  )
{
  EFI_STATUS Status;
  HISTORY_RECORD *pRec;
  USER_INFO *pUser;
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_GUID FormSetGuid = FORMSET_HISTORY_GUID;
  EFI_FORM_ID FormId = HISTORY_PAGE_ID;
  CHAR16 TmpStr16[255], *Str16;
  CHAR16 HelpStr16[255];
  EFI_TIME EfiTime;
  UINT32 Index;
  USER_INFO UnknownUsr, AmtUsr, SuUsr;
  
  LOG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));

  UnknownUsr.UserId = USER_UNKNOWN_ID;
  Str16 = HiiGetString(HiiHandle, STRING_TOKEN(STR_USR_NAME_UNKNOWN), NULL);
  StrCpy(UnknownUsr.UserName, Str16);
  StrCpy(UnknownUsr.UserFIO, Str16);

  AmtUsr.UserId = USER_AMT_ID;
  StrCpy(AmtUsr.UserName, L"AMT");
  StrCpy(AmtUsr.UserFIO, L"AMT");

  SuUsr.UserId = USER_SU_ID;
  StrCpy(SuUsr.UserName, L"Super");
  StrCpy(SuUsr.UserFIO, L"Super");
  
  if (EFI_SUCCESS != AllocateHiiResources()) {
    return EFI_OUT_OF_RESOURCES;
  }
  
#if 1
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);  
#else
  HelpToken = STRING_TOKEN(STR_HISTORY_PRESS_ENTER_TO_DELETE); //HiiSetString (HiiHandle, 0, L"", NULL);
#endif

  QuestionId = (EFI_QUESTION_ID)StartQId;

  HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Title,
        HelpToken, EFI_IFR_FLAG_READ_ONLY | EFI_IFR_FLAG_CALLBACK, 0);
  HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  QuestionId++;
  
  Index = 1;
  
  pRec = HistoryGetNextRecord(TRUE);
  if (NULL == pRec) {
    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, STRING_TOKEN(STR_EMPTY),
        HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  }

  // just for base up to date
  UserFindRecordById (USER_SPECIAL_ID);

  while (pRec != NULL) {
    if (pRec->UserId == USER_UNKNOWN_ID) {
      pUser = &UnknownUsr;
    } else if (pRec->UserId == USER_AMT_ID) {
      pUser = &AmtUsr;
    } else if (pRec->UserId == USER_SU_ID) {
      pUser = &SuUsr;
    } else {
      Status = FindUserRecordByIdWrapper(pRec->UserId);
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
        //return Status;
        pUser = &UnknownUsr;
      } else {
        pUser = UserGetLastFoundedInfo();
      }
    }
    if (pUser == NULL) {
      LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
      return EFI_NOT_FOUND;
    }

    ConvU32ToEfiTime(pRec->TimeStamp, &EfiTime);

    Str16 = HiiGetString(CurrentHiiHandle, 
      HistoryGetSeverityString(pRec->Severity), NULL);

    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), 
      L"[%a] %04d %02d.%02d.%04d %02d:%02d:%02d %s %s %s 0x%04X %s",
      pRec->Flags & HISTORY_RECORD_FLAG_CLEAN_EN ? "X" : " ",
      Index++,
      EfiTime.Day, EfiTime.Month, EfiTime.Year, EfiTime.Hour, EfiTime.Minute,
      EfiTime.Second,
      pUser->UserName, pUser->UserFIO,
      Str16,
      pRec->EventCode,
      pRec->Flags & HISTORY_RECORD_FLAG_RESULT_OK ? 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_SUCCESS), NULL) : 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_ERROR), NULL)
      );
    
    LOG((EFI_D_ERROR, "::-->%s\n", TmpStr16));
  
    Token = HiiSetString (HiiHandle, 0, TmpStr16, NULL);
    LOG((EFI_D_ERROR, "%a.%d Token = %d\n",
      __FUNCTION__, __LINE__, Token));

    UnicodeSPrint (HelpStr16, sizeof (HelpStr16), L"%s\n\n%s\n\n%s %s", 
      HiiGetString (
        HiiHandle,
        STRING_TOKEN(STR_HISTORY_PRESS_ENTER_TO_DELETE),
        NULL),
      HiiGetString (
        HiiHandle,
        GetHistoryStringByIdx (pRec->EventCode),
        NULL),
      HiiGetString (
        HiiHandle,
        STRING_TOKEN (STR_HEVENT_RESULT_STATUS),
        NULL
        ),
      pRec->Flags & HISTORY_RECORD_FLAG_RESULT_OK ? 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_SUCCESS), NULL) : 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_ERROR), NULL)
      );

    DEBUG ((EFI_D_ERROR, "%a.%d HelpStr16 = %s\n",
      __FUNCTION__, __LINE__, HelpStr16));

    HelpToken = HiiSetString (HiiHandle, 0, HelpStr16, NULL);

    HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
        HelpToken, EFI_IFR_FLAG_CALLBACK, 0);

    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
    pRec = HistoryGetNextRecord(FALSE);
    QuestionId++;
  }

  return EFI_SUCCESS;
}


STATIC
EFI_STATUS
CreateOneOfAutoClean (
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId
  )
{
  EFI_STRING_ID StrFirst, StrSecond;
  //UINT8 Val;
  VOID *OptionsOpCodeHandle;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  
  LOG((EFI_D_ERROR, "%a.%d QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, QuestionId));

  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (OptionsOpCodeHandle == NULL) {
    goto _exit;
  }

  AutoCleanOnVal = gHistoryStorage.Flags & HISTORY_FLAGS_AUTO_CLEAN_EN ? 0 : 1;
  
  StrFirst = HiiSetString (HiiHandle, 0, 
    gHistoryStorage.Flags & HISTORY_FLAGS_AUTO_CLEAN_EN ? L"On" : L"Off", NULL);
  //Val = gHistoryStorage.Flags & HISTORY_FLAGS_AUTO_CLEAN_EN ? 0 : 1;
  
  if (NULL == HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    StrFirst, 0, EFI_IFR_NUMERIC_SIZE_1, 0)) {
    LOG((EFI_D_ERROR, "%a.%d error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  
  StrSecond = HiiSetString (HiiHandle, 0, 
    gHistoryStorage.Flags & HISTORY_FLAGS_AUTO_CLEAN_EN ? L"Off" : L"On", NULL);
  //Val = gHistoryStorage.Flags & HISTORY_FLAGS_AUTO_CLEAN_EN ? 1 : 0;
  
  if (NULL == HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    StrSecond, 0, EFI_IFR_NUMERIC_SIZE_1, 
    1)) {
    LOG((EFI_D_ERROR, "%a.%d error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  Status =  HiiCreateOneOfOpCode (StartOpCodeHandle, QuestionId, 
    0,  0, Caption, STRING_TOKEN (STR_NULL_STRING), 
    EFI_IFR_FLAG_CALLBACK | EFI_IFR_FLAG_OPTIONS_ONLY,
    EFI_IFR_NUMERIC_SIZE_1, OptionsOpCodeHandle, NULL
    ) == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
_exit:  
  if (OptionsOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (OptionsOpCodeHandle);
  }
  return Status;
}


STATIC
EFI_STATUS
CreateOneOfNumericSequence (
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId,
  IN VOID **OptionsOpCodeHandle,
  IN UINTN HowMuch
  )
{
  UINTN i;
  CHAR16 Str16[10];
  //EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  
  LOG((EFI_D_ERROR, "%a.%d QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, QuestionId));
  LOG((EFI_D_ERROR, "%a.%d gHistoryStorage.CurSeverity=%X\n", 
    __FUNCTION__, __LINE__, gHistoryStorage.CurSeverity));
  
  if (gHistoryStorage.CurSeverity == 0) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  *OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (*OptionsOpCodeHandle == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  

  DefautSeverityNum = GetHighestSetBitNum(gHistoryStorage.CurSeverity);
  /*UnicodeSPrint(Str16, sizeof(Str16), L"%d", DefautSeverityNum);
  if (NULL == HiiCreateOneOfOptionOpCode (*OptionsOpCodeHandle,
    HiiSetString (HiiHandle, 0, Str16, NULL), 0, EFI_IFR_NUMERIC_SIZE_1, 0)) {
    LOG((EFI_D_ERROR, "%a.%d error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }*/

  for (i = 0; i < HowMuch; i++) {
    UnicodeSPrint(Str16, sizeof(Str16), L"%d", i);
    if (NULL == HiiCreateOneOfOptionOpCode (*OptionsOpCodeHandle,
      HiiSetString (HiiHandle, 0, Str16, NULL), 0, EFI_IFR_NUMERIC_SIZE_1, 
      (UINT8)i == DefautSeverityNum ? 0 : (UINT64)(1 << i))) {
      LOG((EFI_D_ERROR, "%a.%d error!\n", __FUNCTION__, __LINE__));
      return EFI_OUT_OF_RESOURCES;
    }
  }
  return EFI_SUCCESS;
}


STATIC
EFI_STATUS
SeverityLevelOneOfString (
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId
  )
{
  VOID *OptionsOpCodeHandle = NULL;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  
  LOG((EFI_D_ERROR, "%a.%d QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, QuestionId));

  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (OptionsOpCodeHandle == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  
/*
1.Ошибка системы (emergency) — 0x0
2.Тревога (alert) — 0x1 
3.Критическая (critical) — 0x2 
4.Ошибка (error) — 0x3 
5.Предупреждение (warning) — 0x4 
6.Уведомление (notice) — 0x5 
7.Информация (info) — 0x6
8.Отладочная (debug) — 0x7
*/

#if 1
  Status = CreateOneOfNumericSequence(HiiHandle, StartOpCodeHandle,
    Caption, QuestionId, &OptionsOpCodeHandle, HISTORY_MAX_LVL);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
#endif

  Status =  HiiCreateOneOfOpCode (StartOpCodeHandle, QuestionId, 
    0,  0, Caption,
    STRING_TOKEN (STR_NULL_STRING), 
    EFI_IFR_FLAG_CALLBACK | EFI_IFR_FLAG_OPTIONS_ONLY,
    EFI_IFR_NUMERIC_SIZE_1, OptionsOpCodeHandle, NULL
    ) == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
  
_exit:  
  if (OptionsOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (OptionsOpCodeHandle);
  }
  return Status;
}


EFI_STATUS
HistoryControlPage (
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  EFI_GUID FormSetGuid = FORMSET_HISTORY_GUID;
  EFI_FORM_ID FormId = HISTORY_PAGE_ID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID HelpToken;
  
  do {  
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    
    if (EFI_SUCCESS != HistoryCommonInit(HiiHandle)) {
      return EFI_INVALID_PARAMETER;
    }

    if (EFI_SUCCESS != AllocateHiiResources()) {
      return EFI_OUT_OF_RESOURCES;
    }
    
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

    HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
    
    HiiCreateActionOpCode(StartOpCodeHandle, 
      (EFI_QUESTION_ID)HISTORY_CLEAN_ALL_ID, 
      STRING_TOKEN(STR_HISTORY_CLEAN_ALL),
      HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
    
    HiiCreateActionOpCode(StartOpCodeHandle, 
      (EFI_QUESTION_ID)HISTORY_VIEW_CLEAN_ID, 
      STRING_TOKEN(STR_HISTORY_VIEW_CLEAN),
      HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
    
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    
    HiiCreateActionOpCode(StartOpCodeHandle, 
      (EFI_QUESTION_ID)HISTORY_OUTSWAP_TO_USB_ID, 
      STRING_TOKEN(STR_HISTORY_OUTSWAP_TO_USB),
      HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
    
    if (EFI_SUCCESS != SeverityLevelOneOfString(HiiHandle, StartOpCodeHandle,
        STRING_TOKEN(STR_HISTORY_SEVERITY),
        (EFI_QUESTION_ID)HISTORY_SEVERITY_LEVEL_ID)) {
      LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
      goto _exit;
    }
    
    if (EFI_SUCCESS != CreateOneOfAutoClean(HiiHandle, StartOpCodeHandle,
      STRING_TOKEN(STR_HISTORY_AUTO_CLEAN), 
      (EFI_QUESTION_ID) HISTORY_ENABLE_AUTO_CLEAN_ID)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      goto _exit;
    }
    
    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
    
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    
    Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
      (VOID **) &gFormBrowser2);
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    if (EFI_ERROR (Status)) {
      goto _exit;
    }

    ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
    Status = EFI_SUCCESS;

    do {
      Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1,
        &FormSetGuid, FormId, NULL, &ActionRequest);
      
      if (CurrentEvent == HISTORY_VIEW_CLEAN_ID) {
        bFormExitFlag = FALSE;
        CurrentEvent = 0;

#if 0        
        Status = HistoryListPageStrings(HiiHandle, STRING_TOKEN(STR_HISTORY_VIEW_CLEAN), 
          (EFI_QUESTION_ID)HISTORY_VIEW_DEL_REC_START);
#else
        Status = HistoryListPageStringsRev (
                    HiiHandle, 
                    STRING_TOKEN(STR_HISTORY_VIEW_CLEAN), 
                    (EFI_QUESTION_ID)HISTORY_VIEW_DEL_REC_START
                    );
#endif
        if (EFI_ERROR(Status)) {
          LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
          if (Status != EFI_NOT_FOUND) {
            bFormExitFlag = TRUE;
          }
        }
      } 
      if (bRefreshForm) {
        break;
      }
      
      if (bFormExitFlag) {
        Status = EFI_SUCCESS;
        break;
      }
    } while (1);

  _exit:  
    DestroyHiiResources();
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      break;
    }
  } while (bRefreshForm);
    
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  LOG((EFI_D_ERROR, "CurSeverity=0x%X Flags=0x%X\n", 
  gHistoryStorage.CurSeverity, gHistoryStorage.Flags));
    
  Status = HistoryStorageSetRawData(gHistoryStorage.Data, 
    gHistoryStorage.DataLen);
  
  return Status;
}

STATIC
EFI_STATUS
HistoryAddRecordInternal (
  IN UINT16 EventCode,
  IN UINT8 UserId,
  IN UINT8 Severity,
  IN UINT8 Flags
  )
{
  HISTORY_RECORD NewRecord;
  UINT8 *Data, TryCnt = 0;
  EFI_STATUS Status;
  UINTN StorageOffset;
  
  LOG((EFI_D_ERROR, "%a.%d Start\n", __FUNCTION__, __LINE__));
  LOG((EFI_D_ERROR, "%04X.%02X.%02X.%02X\n", 
    EventCode, UserId, Severity, Flags));  
#if 0
  if (UserId == USER_SU_ID) {
    return EFI_SUCCESS;
  }
#endif  
  if (UserId == 0 && !GetMiiMode()) {
    return EFI_SUCCESS; /* There are no logged users  */
  }
  
  do {
    if (Flags & HISTORY_RECORD_FLAG_NO_REREAD) {
      // don't re-reading data
      Flags &= ~HISTORY_RECORD_FLAG_NO_REREAD;
    } else {
      Status = HistoryStorageGetData(&gHistoryStorage);
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
        return Status;
      }
    }
      
    LOG((EFI_D_ERROR, "%a.%d gHistoryStorage.CurSeverity=0x%X\n", 
      __FUNCTION__, __LINE__, gHistoryStorage.CurSeverity));
    if ((gHistoryStorage.CurSeverity & Severity) == 0) {
      return EFI_SUCCESS; /* not allowed level, just skip */
    }

    LOG((EFI_D_ERROR, "%a.%d gHistoryStorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, gHistoryStorage.DataLen));    

    if (HistoryStorageOverflow()) {
      if (!bAddRecordQuite) {
        ShowErrorPopup(CurrentHiiHandle,
          HiiGetString(CurrentHiiHandle, 
            STRING_TOKEN(STR_BIOS_LOG_FULL), NULL));
      }
      LockAdminMenu(ADMIN_LOCK_ALL_BUT_HISTORY);
      return EFI_INVALID_PARAMETER;
    }
    
    if (gHistoryStorage.DataLen) {
      Status = HistoryStorageCheckIntegrity();
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
          __FUNCTION__, __LINE__, Status));
        return Status;
      }
    }
    
    Status = ObtainNewHistoryRecordId(&NewRecord.RecId);
    if (EFI_ERROR(Status)) {
      /* TODO: Internal Error */
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return Status;
    }
    Status = GetU32TimeSec(&NewRecord.TimeStamp);
    /* Status = GetU64TimeSec(&NewRecord.TimeStamp); */
    if (EFI_ERROR(Status)) {
      /* TODO: Internal Error */
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return Status;
    }
    NewRecord.EventCode = EventCode;
    NewRecord.UserId = UserId;
    NewRecord.Severity = Severity;
    NewRecord.Flags = Flags & ~HISTORY_RECORD_FLAG_CLEAN_EN;
    
    Data = AllocateZeroPool(sizeof(HISTORY_RECORD) + gHistoryStorage.DataLen);
    if (NULL == Data) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_OUT_OF_RESOURCES;
    }

    if (gHistoryStorage.DataLen / HISTORY_RECORD_SIZE >= 
        HISTORY_RECORDS_AMOUNT) {
      StorageOffset = sizeof(HISTORY_RECORD);
      gHistoryStorage.DataLen -= (UINT32)StorageOffset;
    } else {
      StorageOffset = 0;
    }
    
    CopyMem(Data, gHistoryStorage.Data + StorageOffset, 
      gHistoryStorage.DataLen);
    CopyMem(Data + gHistoryStorage.DataLen, &NewRecord, 
      sizeof(HISTORY_RECORD));
    
    Status = HistoryStorageSetRawData((UINT8*)Data, 
      gHistoryStorage.DataLen + sizeof(HISTORY_RECORD));

    FreePool(Data);

    TryCnt++;
    if (EFI_ERROR(Status) && TryCnt == 1) {
      LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
      if (gHistoryStorage.Flags & HISTORY_FLAGS_AUTO_CLEAN_EN) {
        HistoryCleanOne(TRUE);
        continue;
      }
    }
    break;
  } while (TryCnt < 2);
  return Status;
}

EFI_STATUS
HistoryAddRecord (
  IN UINT16 EventCode,
  IN UINT8 UserId,
  IN UINT8 Severity,
  IN UINT8 Flags
  )
{
  EFI_STATUS Status;

  if (gHistoryHandlerProtocol == NULL) {
    Status = gBS->LocateProtocol (
              &gHistoryHandlerProtocolGuid, 
              NULL, 
              (VOID **) &gHistoryHandlerProtocol
              );
  }

  if (gHistoryHandlerProtocol) {
    gHistoryHandlerProtocol->LockOp (gHistoryHandlerProtocol);
  }

  Status = HistoryAddRecordInternal (
    EventCode,
    UserId,
    Severity,
    Flags
    );

  if (gHistoryHandlerProtocol) {
    gHistoryHandlerProtocol->UnLockOp (gHistoryHandlerProtocol);
  }
  return Status;
}

HISTORY_RECORD *
HistoryGetNextRecord (
  IN BOOLEAN bRestart 
  )
{
  EFI_STATUS Status;
  STATIC UINTN i;

  if (bRestart) {
    i = 0;
  }
  Status = HistoryFindRecordByRecNum(i);
  if (EFI_ERROR(Status)) {
    i = 0;
    return NULL;
  } else {
    i++;
  }
  return HistoryGetLastFoundedRecord();
}

/* 
 *  bUpdate:
 *    TRUE - save to storage now 
 *    FALSE - do not save to storage
 */
EFI_STATUS
HistoryDeleteLastFoundedRecord (
  IN BOOLEAN bUpdate
  )
{
  HISTORY_RECORD *pRec;
  UINT8 *RestDataPtr;
  UINTN RestDataLen;
  EFI_STATUS Status;
  
  pRec = HistoryGetLastFoundedRecord();
  if (NULL == pRec) {
    return EFI_NOT_FOUND;
  }
  
  if (!(pRec->Flags & HISTORY_RECORD_FLAG_CLEAN_EN)) {
    return EFI_WARN_DELETE_FAILURE;
  }
  
  if (gHistoryStorage.DataLen < sizeof(HISTORY_RECORD)) {
    return EFI_INVALID_PARAMETER;
  }
  
  RestDataPtr = (UINT8*)pRec + sizeof(HISTORY_RECORD);
  RestDataLen = gHistoryStorage.DataLen - 
    ((UINT8*)pRec - gHistoryStorage.Data) - sizeof(HISTORY_RECORD);
  if (RestDataLen) {
    CopyMem(pRec, RestDataPtr, RestDataLen);
  }
  
  gHistoryStorage.DataLen -= sizeof(HISTORY_RECORD);
  if (!bUpdate) {
    return EFI_SUCCESS;
  }
  
  Status = HistoryStorageSetRawData(gHistoryStorage.Data, 
    gHistoryStorage.DataLen);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__,
    Status));
  HistoryStorageOverflow();
  return Status;
}

STATIC
EFI_STATUS
InternalHistoryCleanByNum (
  IN UINTN RecNum,
  IN BOOLEAN bUpdate,
  IN BOOLEAN bRevertNum
  )
{
  EFI_STATUS Status;

  if (bRevertNum) {
    Status = HistoryFindRecordByRecNumRev (RecNum);
  } else {
    Status = HistoryFindRecordByRecNum (RecNum);
  }
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  Status = HistoryDeleteLastFoundedRecord(bUpdate); 
  return Status;
}



/* 
 *  bUpdate:
 *    TRUE - save to storage now 
 *    FALSE - do not save to storage
 */

EFI_STATUS
HistoryCleanByNum (
  IN UINTN RecNum,
  IN BOOLEAN bUpdate
  )
{
  EFI_STATUS Status;

  Status = InternalHistoryCleanByNum (RecNum, bUpdate, FALSE);
  return Status;
}

EFI_STATUS
HistoryCleanByNumRev (
  IN UINTN RecNum,
  IN BOOLEAN bUpdate
  )
{
  EFI_STATUS Status;

  Status = InternalHistoryCleanByNum (RecNum, bUpdate, TRUE);
  return Status;
}



/* 
 *  bUpdate:
 *    TRUE - save to storage now 
 *    FALSE - do not save to storage
 */

EFI_STATUS
HistoryCleanOne (
  IN BOOLEAN bUpdate
  )
{
  UINTN i;
  EFI_STATUS Status = EFI_NOT_FOUND;
  
  for (i = 0; i < 0xFFFFFFFF; i++) {
    Status = HistoryCleanByNum(i, bUpdate);
    if (EFI_WARN_DELETE_FAILURE == Status) {
      continue; /* it is non loaded record */
    }
    break;
  }
  return Status;
}


STATIC
EFI_STATUS
UpdateFnameTimeStamp (
  IN OUT CHAR8 *Fname
  )
{
  EFI_STATUS Status;
  CHAR8 *EndName, TmpStr8[14];
  INTN Res;
  EFI_TIME EfiTime;
  enum {FIND_HHMMSS, FIND_DDMMYYYY} State = FIND_HHMMSS;

  EndName = Fname + AsciiStrLen(Fname);

  if (Fname == EndName) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gRT->GetTime(&EfiTime, NULL);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  while (Fname < EndName) {
    if (*Fname != PATTERN_SYMBOL) {
      Fname++;
      continue;
    }

    switch (State) {
    case FIND_HHMMSS:
      if (Fname + 6 >= EndName) {
        return EFI_INVALID_PARAMETER;
      }
      TmpStr8[0] = Fname[6];
      Fname[6] = '\0';
      Res = AsciiStrCmp(Fname, "??????");
      Fname[6] = TmpStr8[0];
      if (Res) {
        return EFI_INVALID_PARAMETER;
      }
      AsciiSPrint(TmpStr8, sizeof(TmpStr8), "%02d%02d%02d", EfiTime.Hour,
        EfiTime.Minute, EfiTime.Second);
      CopyMem(Fname, TmpStr8, 6);
      Fname += 6;
      State = FIND_DDMMYYYY;
      break;

    case FIND_DDMMYYYY:
      if (Fname + 8 >= EndName) {
        return EFI_INVALID_PARAMETER;
      }
      TmpStr8[0] = Fname[8];
      Fname[8] = '\0';
      Res = AsciiStrCmp(Fname, "????????");
      Fname[8] = TmpStr8[0];
      if (Res) {
        return EFI_INVALID_PARAMETER;
      }
      AsciiSPrint(TmpStr8, sizeof(TmpStr8), "%02d%02d%04d", 
        EfiTime.Day, EfiTime.Month, EfiTime.Year);
      CopyMem(Fname, TmpStr8, 8);
      return EFI_SUCCESS;

    default:
      return EFI_INVALID_PARAMETER;
    }
  }

  return EFI_INVALID_PARAMETER;
}


STATIC
EFI_STATUS
SaveHistoryRecordCsv (
  IN EFI_FILE_HANDLE File,
  IN HISTORY_RECORD *pRec
  )
{
  EFI_STATUS Status;
  UINTN Size;
  CHAR8 Str8[HISTORY_STRING_LEN];
  CHAR16 *StrPtr16;
  EFI_TIME EfiTime;
  USER_INFO *pUser;
  
  LOG((EFI_D_ERROR, "%a.%d Start\n", __FUNCTION__, __LINE__));
  
  if (pRec == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (pRec->Flags & HISTORY_RECORD_FLAG_CLEAN_EN) {
    LOG((EFI_D_ERROR, "%a.%d Error pRec->Flags=0x%02X\n", 
     __FUNCTION__, __LINE__, pRec->Flags));
/* This record allready stored */
    return EFI_SUCCESS;
  }
  Status = FindUserRecordByIdWrapper(pRec->UserId);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  pUser = UserGetLastFoundedInfo();
  if (pUser == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  ConvU32ToEfiTime(pRec->TimeStamp, &EfiTime);
  
  AsciiSPrint(Str8, sizeof(Str8), "%02d.%02d.%04d %02d:%02d:%02d;", 
    EfiTime.Day, EfiTime.Month, EfiTime.Year, EfiTime.Hour, EfiTime.Minute,
    EfiTime.Second);
  Size = AsciiStrLen(Str8);
  Status = LibFsWriteFile(File, &Size, Str8);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  AsciiSPrint(Str8, sizeof(Str8), "%s %s;", 
    pUser->UserName, pUser->UserFIO);
  Size = AsciiStrLen(Str8);
  LOG((EFI_D_ERROR, "--> %a\n", Str8));
  Status = LibFsWriteFile(File, &Size, Str8);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  
  StrPtr16 = HiiGetString(CurrentHiiHandle, 
    HistoryGetSeverityString(pRec->Severity),
    NULL);
  AsciiSPrint(Str8, sizeof(Str8), "%s;%a;", 
    StrPtr16,
    pRec->Flags & HISTORY_RECORD_FLAG_RESULT_OK ? 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_SUCCESS), NULL) : 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_ERROR), NULL));
  
  Size = AsciiStrLen(Str8);
  LOG((EFI_D_ERROR, "--> %a\n", Str8));
  Status = LibFsWriteFile(File, &Size, Str8);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  AsciiSPrint(Str8, sizeof(Str8), "%a;\n", 
    HistoryGetEventString(pRec->EventCode));
  Size = AsciiStrLen(Str8);
  LOG((EFI_D_ERROR, "--> %a\n", Str8));
  Status = LibFsWriteFile(File, &Size, Str8);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


STATIC 
USER_INFO *
GetUnknownUsrInfo (
  VOID
  )
{
  STATIC USER_INFO UnknownUsr;
  CHAR16 *StrPtr16;

  UnknownUsr.UserId = USER_UNKNOWN_ID;
  StrPtr16 = HiiGetString(CurrentHiiHandle, 
    STRING_TOKEN(STR_USR_NAME_UNKNOWN), NULL);
  StrCpy(UnknownUsr.UserName, StrPtr16);
  StrCpy(UnknownUsr.UserFIO, StrPtr16);
  
  UnknownUsr.AuthType = AUTH_TYPE_LOG_PASS;
  
  return &UnknownUsr;
}

STATIC 
USER_INFO *
GetSuUsrInfo (
  VOID
  )
{
  STATIC USER_INFO SuUsr;
  CHAR16 *StrPtr16;

  SuUsr.UserId = USER_SU_ID;
  StrPtr16 = HiiGetString(CurrentHiiHandle, 
    STRING_TOKEN(STR_USR_NAME_SUPER), NULL);
  StrCpy(SuUsr.UserName, StrPtr16);
  StrCpy(SuUsr.UserFIO, StrPtr16);
  
  SuUsr.AuthType = AUTH_TYPE_LOG_PASS;
  
  return &SuUsr;
}


EFI_STATUS
GetHistoryRecordCsv16 (
  IN HISTORY_RECORD *pRec,
  IN OUT CHAR16 **ResStr,
  IN OUT UINTN *ResSize
  )
{
  EFI_STATUS Status;
  UINTN Size, RestLen;
  STATIC CHAR16 Str16[HISTORY_STRING_LEN];
  CHAR16 *CurStrPtr16;
  CHAR16 *StrPtr16;
  EFI_TIME EfiTime;
  USER_INFO *pUser;  
  
  LOG((EFI_D_ERROR, "%a.%d Start\n", __FUNCTION__, __LINE__));

  if (pRec == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  if (pRec->UserId == USER_UNKNOWN_ID) {
    pUser = GetUnknownUsrInfo();
  } else if (pRec->UserId == USER_AMT_ID) {
    pUser = GetAmtUsrInfo ();
  } else if (pRec->UserId == USER_SU_ID) {
    pUser = GetSuUsrInfo ();
  } else {
    Status = FindUserRecordByIdWrapper(pRec->UserId);
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
      //return Status;
      pUser = GetUnknownUsrInfo();
    } else {
      pUser = UserGetLastFoundedInfo();
    }
  }
  if (pUser == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  ConvU32ToEfiTime(pRec->TimeStamp, &EfiTime);

  CurStrPtr16 = Str16;
  RestLen = sizeof (Str16);
  UnicodeSPrint(CurStrPtr16, RestLen, L"%02d.%02d.%04d %02d:%02d:%02d;", 
    EfiTime.Day, EfiTime.Month, EfiTime.Year, EfiTime.Hour, EfiTime.Minute,
    EfiTime.Second);
  Size = StrLen(CurStrPtr16);
  CurStrPtr16 += Size;
  RestLen -= (Size * 2);
  
  UnicodeSPrint(CurStrPtr16, RestLen, L"%s %s;", 
    pUser->UserName, pUser->UserFIO);
  Size = StrLen(CurStrPtr16);
  CurStrPtr16 += Size;
  RestLen -= (Size * 2);
  
  //----------------------------------------------------------------------
  // Add Auth type of the user
  //----------------------------------------------------------------------
  StrPtr16 = UsersGetTypeString16(pUser->AuthType, CurrentHiiHandle);
  UnicodeSPrint(CurStrPtr16, RestLen, L"%s;", 
    StrPtr16);
  Size = StrLen(CurStrPtr16);
  CurStrPtr16 += Size;
  RestLen -= (Size * 2);
  LOG((EFI_D_ERROR, "Auth type: %s\n", StrPtr16));
  
  StrPtr16 = HiiGetString(CurrentHiiHandle, 
    HistoryGetSeverityString(pRec->Severity),
    NULL);

  UnicodeSPrint(CurStrPtr16, RestLen, L"%s;%s;", 
    StrPtr16,
    pRec->Flags & HISTORY_RECORD_FLAG_RESULT_OK ? 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_SUCCESS), NULL) : 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_ERROR), NULL));
  
  Size = StrLen(CurStrPtr16);
  CurStrPtr16 += Size;
  RestLen -= (Size * 2);

  UnicodeSPrint(CurStrPtr16, RestLen, L"%s;", 
    HistoryGetEventString16(pRec->EventCode));
  Size = StrLen(CurStrPtr16);
  CurStrPtr16 += Size;
  RestLen -= (Size * 2);
    
  UnicodeSPrint(CurStrPtr16, RestLen, L";\n", 
      StrPtr16);

  Size = StrLen(CurStrPtr16);
  CurStrPtr16 += Size;
  RestLen -= (Size * 2);

  LOG((EFI_D_ERROR, "%a.%d Size=%d\n", 
    __FUNCTION__, __LINE__, Size));
  LOG((EFI_D_ERROR, "%a.%d CurStrPtr16=%s\n", 
    __FUNCTION__, __LINE__, CurStrPtr16));
  *ResSize = StrLen (Str16) * 2;
  *ResStr = Str16;
  return EFI_SUCCESS;
}

EFI_STATUS
HistoryGetCsv16MemFile (
  IN CHAR16 **Csv16Str
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  HISTORY_RECORD *pRec;
  CHAR16 *ResStr = NULL;
  CHAR16 *TmpStr16 = NULL;
  CHAR16 *Str16 = NULL;
  
  LOG((EFI_D_ERROR, "%a.%d Start\n", __FUNCTION__, __LINE__));
  
  pRec = HistoryGetNextRecord(TRUE);
  if (!pRec) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  
  do {    
    UINTN TmpStr16Size, ResSize;
    if ((pRec->Flags & HISTORY_RECORD_FLAG_CLEAN_EN) == 0) {
      LOG((EFI_D_ERROR, "%a.%d Error pRec->Flags=0x%02X\n", 
        __FUNCTION__, __LINE__, pRec->Flags));

      Status = GetHistoryRecordCsv16(pRec, &TmpStr16, &TmpStr16Size);
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        break;
      }
      if (ResStr != NULL) {
        ResSize = StrSize (ResStr);
      } else {
        ResSize = 0;
      }
      Str16 = AllocateZeroPool (StrSize (TmpStr16) + ResSize);
      if (Str16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        break;
      }

      if (ResStr != NULL) {
        StrCpy (Str16, ResStr);
        ResSize = StrLen (ResStr);
        FreePool (ResStr);
      }

      StrCpy (&Str16[ResSize], TmpStr16);      

      ResStr = Str16;
      Str16 = NULL;
      
      LOG((EFI_D_ERROR, "%a.%d Saved record=0x%08X\n", 
        __FUNCTION__, __LINE__, pRec->RecId));
    }
    pRec = HistoryGetNextRecord(FALSE);
  } while (pRec != NULL);
  
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

/* Mark all records as clean enabled */
  pRec = HistoryGetNextRecord(TRUE);
  if (pRec == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  do {
    pRec->Flags |= HISTORY_RECORD_FLAG_CLEAN_EN;
    pRec = HistoryGetNextRecord(FALSE);
  } while (pRec != NULL);
  
_exit:
  if (EFI_ERROR(Status)) {
    if (ResStr) {
      FreePool (ResStr);
    }
    *Csv16Str = NULL;
  } else {
    *Csv16Str = ResStr;
    if (ResStr) {
      Status = HistoryStorageSetRawData (
                  gHistoryStorage.Data, 
                  gHistoryStorage.DataLen
                  );
    }
  }

  if (Str16) {
    FreePool (Str16);
  }
  
  return Status;
}



STATIC
EFI_STATUS
SaveHistoryRecordCsv16 (
  IN EFI_FILE_HANDLE File,
  IN HISTORY_RECORD *pRec
  )
{
  EFI_STATUS Status;
  CHAR16 *Str16;
  UINTN Size;

  if (pRec == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (pRec->Flags & HISTORY_RECORD_FLAG_CLEAN_EN) {
    LOG((EFI_D_ERROR, "%a.%d Error pRec->Flags=0x%02X\n", 
     __FUNCTION__, __LINE__, pRec->Flags));
/* This record allready stored */
    return EFI_SUCCESS;
  }

  Str16 = NULL;
  Size = 0;
  Status = GetHistoryRecordCsv16(pRec, &Str16, &Size);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d ERROR! Status=0x%X\n", 
    __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  Status = LibFsWriteFile(File, &Size, Str16);  
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
    __FUNCTION__, __LINE__, Status));
  return Status;
}

STATIC
EFI_STATUS
HistoryStoreAllToCsvFile (
  IN CHAR8 *FileName
  )
{
  EFI_STATUS Status;
  EFI_FILE_HANDLE File = NULL;
  HISTORY_RECORD *pRec;
  
  LOG((EFI_D_ERROR, "%a.%d Start\n", __FUNCTION__, __LINE__));
  
  pRec = HistoryGetNextRecord(TRUE);
  if (!pRec) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  
  File = LibFsCreateFile(FileName);
  if (File == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error while LibFsOpenFile!!!!\n", 
      __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  do {
    Status = SaveHistoryRecordCsv16(File, pRec);
#if 0   /* DEBUG */
    HistoryShowRecord(pRec);
#endif  /* DEBUG */
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      break;
    }
    LOG((EFI_D_ERROR, "%a.%d Saved record=0x%08X\n", 
      __FUNCTION__, __LINE__, pRec->RecId));
    pRec = HistoryGetNextRecord(FALSE);
  } while (pRec != NULL);
  
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

/* Mark all records as clean enabled */
  pRec = HistoryGetNextRecord(TRUE);
  if (pRec == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  do {
    pRec->Flags |= HISTORY_RECORD_FLAG_CLEAN_EN;
#if 0   /* DEBUG */
    LOG((EFI_D_ERROR, "/////////////////////////////////////\n"));
    HistoryShowRecord(pRec);
#endif  /* DEBUG */
    pRec = HistoryGetNextRecord(FALSE);
  } while (pRec != NULL);
  
_exit:
  LibFsCloseFile(File);
  return Status;
}



EFI_STATUS
HistoryOutswapToUSB (
  VOID
  )
{
  EFI_STATUS Status = EFI_NOT_FOUND;
  CHAR8 FileName[255];
  LIST_ENTRY *ListEntryModules;
  MULTIBOOT_ENTRY *Entry;
  MULTIBOOT_MODULE *pModule;
  CHAR16 *StrPtr16, TmpStr16[255];

  LOG((EFI_D_ERROR, "%a.%d: Start\n", __FUNCTION__, __LINE__));
  
  Entry = FindEntryByIndex(CurrentConfig, ADM_MAIN_PAGE_BIOS_LOG_CTRL_ID);
  if (NULL == Entry) {
    LOG((EFI_D_ERROR, "%a.%d: Error\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
 
  ListEntryModules = Entry->ModuleHead.ForwardLink;
  if(IsListEmpty(&Entry->ModuleHead)) {
    LOG((EFI_D_ERROR, "%a.%d: Error\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  
  pModule = _CR( ListEntryModules, MULTIBOOT_MODULE, ListEntry );
  if (pModule->DevPath == NULL) {
    LOG((EFI_D_ERROR, "%a.%d: Error\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  LOG((EFI_D_ERROR, "%a.%d pModule->DevPath=%s\n", __FUNCTION__, __LINE__, pModule->DevPath));

  *TmpStr16 = 0;
  StrPtr16 = StrStr (pModule->DevPath, L"\\");
  if (StrPtr16) {
    CHAR16 Reserv;
    Reserv = *(StrPtr16 + 1);
    *(StrPtr16 + 1) = 0;
    StrCpy(TmpStr16, pModule->DevPath);
    *(StrPtr16 + 1) = Reserv;
  }
  StrPtr16 = TmpStr16;
  LOG((EFI_D_ERROR, "%a.%d StrPtr16=%s\n", __FUNCTION__, __LINE__, StrPtr16));  
  if (!CheckFsPathPresent(StrPtr16, NULL)) {
    Status = FindSpecialDevPath(L"Pci(0x16,0x2)/Ata");
    if (!EFI_ERROR(Status)) {
      StrPtr16 = StrStr (pModule->DevPath, L":");
      UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"%s%s", 
        SPEC_PATH_SHORT_NAME, StrPtr16);
      StrPtr16 = TmpStr16;
    } else {
      LOG((EFI_D_ERROR, "%a.%d: Error\n", __FUNCTION__, __LINE__));
      goto _exit;
    }
  } else {
    StrPtr16 = pModule->DevPath;
  }
  LOG((EFI_D_ERROR, "%a.%d StrPtr16=%s\n", __FUNCTION__, __LINE__, StrPtr16));
  
  AsciiSPrint(FileName, sizeof(FileName), "%s", StrPtr16);
  LOG((EFI_D_ERROR, "%a.%d: FileName=%a\n", 
    __FUNCTION__, __LINE__, FileName));
  Status = UpdateFnameTimeStamp(FileName);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  LOG((EFI_D_ERROR, "%a.%d: FileName=%a\n", 
    __FUNCTION__, __LINE__, FileName));

  Status = HistoryStoreAllToCsvFile(FileName);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
#if 0
  DumpBytes(gHistoryStorage.Data, gHistoryStorage.DataLen);
#endif
  Status = HistoryStorageSetRawData(gHistoryStorage.Data, 
    gHistoryStorage.DataLen);
#if 0
  DumpBytes(gHistoryStorage.Data, gHistoryStorage.DataLen);
#endif
_exit:
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
#if 0  
  if (Status == EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d Unlock admin menu!\n", __FUNCTION__, __LINE__));  
    LockAdminMenu(0);
  }
#endif  
  return Status;
}


EFI_STATUS
HistoryCleanAll (
  VOID
  )
{
  EFI_STATUS Status;
  
  do {
    Status = HistoryCleanOne(FALSE);
  } while (!EFI_ERROR(Status));
  
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }
  Status = HistoryStorageSetRawData(gHistoryStorage.Data, 
    gHistoryStorage.DataLen);
  return Status;
}


VOID 
HistorySetCurrentConfig (
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *Cfg
  )
{
  CurrentConfig = Cfg;
  CurrentHiiHandle = HiiHandle;
}


EFI_STATUS
HistoryCtrlMenuStart (
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  EFI_STATUS Status;
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
  
  CurrentHiiHandle = HiiHandle;
  bRefreshForm = FALSE;
  Status = HistoryStorageGetData(&gHistoryStorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    ShowErrorPopup(HiiHandle, 
      HiiGetString(HiiHandle, STRING_TOKEN(MSG_LOG_READING_ERROR), NULL));
    return Status;
  }
  if (gHistoryStorage.DataLen) {
    Status = HistoryStorageCheckIntegrity();
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
        __FUNCTION__, __LINE__, Status));
      return Status;
    }
  }
  
  LOG((EFI_D_ERROR, "%a.%d gHistoryStorage.CurSeverity=%X\n", 
    __FUNCTION__, __LINE__, gHistoryStorage.CurSeverity));
  
  Status = HistoryControlPage(HiiHandle, Language);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

BOOLEAN
HistoryAutoCleanEnabled (
  VOID
  )
{
  if ((gHistoryStorage.Flags & HISTORY_FLAGS_AUTO_CLEAN_EN) == 0) {
    return FALSE;
  }
  return TRUE;
}

EFI_STATUS
HistoryFlush (
  VOID
  )
{
  EFI_STATUS Status;
  
  if (gHistoryHandlerProtocol == NULL) {
    Status = gBS->LocateProtocol (
              &gHistoryHandlerProtocolGuid, 
              NULL, 
              (VOID **) &gHistoryHandlerProtocol
              );
  }

  if (gHistoryHandlerProtocol) {
    gHistoryHandlerProtocol->LockOp (gHistoryHandlerProtocol);
  }
  Status = HistoryStorageSetRawData(gHistoryStorage.Data, 
    gHistoryStorage.DataLen);

  if (gHistoryHandlerProtocol) {
    gHistoryHandlerProtocol->UnLockOp (gHistoryHandlerProtocol);
  }
  return Status;
}

BOOLEAN
HistoryOutswapped (
  VOID
  )
{
  EFI_STATUS Status;

  /* update to actual state */
  Status = HistoryStorageGetData(&gHistoryStorage);  
  if (EFI_ERROR(Status)) {
    return FALSE;
  }
  if (HistoryCountUnloadedButNoDebug()) {
    return FALSE;
  }
  return TRUE;
}

EFI_STATUS
HistorySettings (
  IN UINT8 CurSeverity,
  IN BOOLEAN bAutocleanEn
  )
{
  gHistoryStorage.CurSeverity = CurSeverity;
  if (bAutocleanEn) {
    gHistoryStorage.Flags |= HISTORY_FLAGS_AUTO_CLEAN_EN;
  } else {
    gHistoryStorage.Flags &= ~HISTORY_FLAGS_AUTO_CLEAN_EN;
  }
  return HistoryFlush();
}


