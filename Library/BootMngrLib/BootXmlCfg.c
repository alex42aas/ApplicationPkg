/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "BootXmlCfg.h"


STATIC UINTN DataSetIdx;
STATIC UINTN HowMuchDataSets;
STATIC UINTN ErrorsCnt;

STATIC CONFIG_STATE_TABLE gConfigStateTable[] = {
  { ST_BASE,        L"bootconf",   8, EVENT_START,  ST_BOOT_CONF,  0 },

  { ST_BOOT_CONF,   L"confguid",   8, EVENT_START,  ST_CONF_GUID,  0 },  
  { ST_CONF_GUID,   0,             0, EVENT_TEXT,   ST_CONF_GUID,  1 },
  { ST_CONF_GUID,   L"/confguid",  9, EVENT_END,    ST_BOOT_CONF,  0 },

  { ST_BOOT_CONF,   L"conftype",   8, EVENT_START,  ST_CONF_TYPE,  0 },  
  { ST_CONF_TYPE,   0,             0, EVENT_TEXT,   ST_CONF_TYPE,  1 },
  { ST_CONF_TYPE,   L"/conftype",  9, EVENT_END,    ST_BOOT_CONF,  0 },
    
  { ST_BOOT_CONF,   L"boottype",   8, EVENT_START,  ST_BOOT_TYPE,  0 },  
  { ST_BOOT_TYPE,   0,             0, EVENT_TEXT,   ST_BOOT_TYPE,  1 },
  { ST_BOOT_TYPE,   L"/boottype",  9, EVENT_END,    ST_BOOT_CONF,  0 },

  { ST_BOOT_CONF,   L"module",     6, EVENT_START,  ST_MODULE,     0 },

  { ST_MODULE,      L"devpath",    7, EVENT_START,  ST_DEVPATH,    0 },  
  { ST_DEVPATH,     0,             0, EVENT_TEXT,   ST_DEVPATH,    1 },
  { ST_DEVPATH,     L"/devpath",   8, EVENT_END,    ST_MODULE,     0 },

  { ST_MODULE,      L"params",     6, EVENT_START,  ST_PARAMS,     0 },  
  { ST_PARAMS,      0,             0, EVENT_TEXT,   ST_PARAMS,     1 },
  { ST_PARAMS,      L"/params",    7, EVENT_END,    ST_MODULE,     0 },

  { ST_MODULE,      L"hash",       6, EVENT_START,  ST_MOD_HASH,   0 },  
  { ST_MOD_HASH,    0,             0, EVENT_TEXT,   ST_MOD_HASH,   1 },
  { ST_MOD_HASH,    L"/hash",      7, EVENT_END,    ST_MODULE,     0 },
  
  { ST_MODULE,      L"/module",    7, EVENT_END,    ST_BOOT_CONF,  0 },

  { ST_BOOT_CONF,   0,             0, EVENT_TEXT,   ST_BOOT_CONF,  0 },
  { ST_BOOT_CONF,   L"/bootconf",  9, EVENT_END,    ST_BASE,       1 },

  { ST_BASE,        L"icfl",       4, EVENT_START,  ST_ICFL,       0 },

  { ST_ICFL,        L"entry",      5, EVENT_START,  ST_ENTRY,      0 },

  { ST_ENTRY,       L"file",       4, EVENT_START,  ST_FILE,       0 },  
  { ST_FILE,        0,             0, EVENT_TEXT,   ST_FILE,       1 },
  { ST_FILE,        L"/file",      5, EVENT_END,    ST_ENTRY,      0 },

  { ST_ENTRY,       L"hash",       4, EVENT_START,  ST_HASH,       0 },  
  { ST_HASH,        0,             0, EVENT_TEXT,   ST_HASH,       1 },
  { ST_HASH,        L"/hash",      5, EVENT_END,    ST_ENTRY,      0 },

  { ST_ENTRY,       L"/entry",     6, EVENT_END,    ST_ICFL,       0 },

  { ST_ICFL,        0,             0, EVENT_TEXT,   ST_ICFL,       0 },
  { ST_ICFL,        L"/icfl",      5, EVENT_END,    ST_BASE,       1 },
  
  { ST_ERROR_TAG,   0,             0, EVENT_NONE,   ST_ERROR_TAG,  0 }
};

//static CHAR16 *ParserText = NULL;
STATIC UINT32 CurState;


VOID
FixDataSetDevPath(
  IN CBCFG_DATA_SET *DataSet
  )
{
  UINTN Idx;
  CBCFG_RECORD *Rec;
  UINT8 *Ptr8;
  CHAR16 *StrPtr16, *TmpPtr;
  CHAR16 *ShortNamePtr, ShortName[10];

  for (Idx = 0; Idx < DataSet->BootOptionsNum; Idx++) {
    Ptr8 = DataSet->Data + (Idx * sizeof(CBCFG_RECORD));
    Rec = (CBCFG_RECORD*)Ptr8;
    StrPtr16 = StrStr(Rec->DevPath, L"\\");
    if (StrPtr16) {
      TmpPtr = StrPtr16 - 1;
      if (*TmpPtr == L'/') {
        *TmpPtr = 0;
      }
      *StrPtr16 = 0;
      StrCpy(Rec->DeviceFullName, Rec->DevPath);
      *StrPtr16 = L'\\';
      if (*TmpPtr == 0) {
        *TmpPtr = L'/';
      }
      ShortNamePtr = FsDescTableGetShortName(Rec->DeviceFullName);
      if (ShortNamePtr) {
        UnicodeSPrint(Rec->DevPath, sizeof(Rec->DevPath), 
          L"%s:%s", 
          ShortNamePtr, StrPtr16);
      } else {
        UnicodeSPrint(ShortName, sizeof(ShortName), L"fs%02d", Idx + 0x30);
        if (0 == AddFsDescTableItem(ShortName, Rec->DeviceFullName, FALSE)) {
          UnicodeSPrint(Rec->DevPath, sizeof(Rec->DevPath), 
            L"%s:%s", 
            ShortName, StrPtr16);
        }
      }
    }
  }
}


VOID
BootXmlConfigShowState(
  IN UINT32 State
  )
{
  switch(State) {
  case ST_MODULE:
    break;

  case ST_DEVPATH:
    break;

  case ST_PARAMS:
    break;

  case ST_ENTRY:
    break;

  case ST_FILE:
    break;

  case ST_HASH:
    break;
    
  default:
    MsgDebugPrint("State: unknown %x\n", State);
  }
}

EFI_STATUS 
ParseConfig16( 
  IN CHAR16 *Text16, 
  IN UINT32 Length,
  IN UINT32 State,
  IN UINT32 NextState, 
  IN UINT32 Emit,
  IN LIST_ENTRY *IcflList,
  IN CBCFG_DATA_SET *DataSet
  )
{
  CHAR16 *Text;
  EFI_STATUS Status;
  CBCFG_RECORD *Rec;
  CHAR8 TmpStr8[255];
  STATIC UINT8 IcflHash[MAX_HASH_LEN];
  STATIC CHAR16 *IcflFileName;
  STATIC BOOLEAN bModuleDevPathFound;
  STATIC BOOLEAN bIcflHashPresent;

  Text = Text16;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  DEBUG((EFI_D_ERROR, "Text=\"%s\"\n", Text));
  DEBUG((EFI_D_ERROR, "Length=0x%X\n", Length));
  DEBUG((EFI_D_ERROR, "State=0x%X\n", State));
  DEBUG((EFI_D_ERROR, "NextState=0x%X\n", NextState));
  DEBUG((EFI_D_ERROR, "Emit=0x%X\n\n\n", Emit));
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (IcflList == NULL || DataSet == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  if (DataSetIdx < MAXIMUM_BOOT_OPTIONS) {
    Rec = (CBCFG_RECORD*)(DataSet->Data + DataSetIdx * sizeof(CBCFG_RECORD));
  } else {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  switch(State) {
  case ST_BASE:
    DEBUG((EFI_D_ERROR, "State=ST_BASE\n"));
    break;

  case ST_BOOT_CONF:
    DEBUG((EFI_D_ERROR, "State=ST_BOOT_CONF\n"));
    DEBUG((EFI_D_ERROR, "Emit=%X DataSetIdx=%X\n", Emit, DataSetIdx));
    
    if (Emit) {
      if (DataSetIdx) {
        DataSet->BootOptionsNum = (UINT32)DataSetIdx;
        FixDataSetDevPath(DataSet);
        Status = CbcfgSave(DataSet);
        DataSetIdx = 0;
        ZeroMem(DataSet, sizeof(CBCFG_DATA_SET) - 1 +  
          MAXIMUM_BOOT_OPTIONS * sizeof(CBCFG_RECORD));
        if (EFI_ERROR(Status)) {
          DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
            __FUNCTION__, __LINE__, Status));
          return Status;
        } else {
          HowMuchDataSets++;
        }    
      }  
    }
    break;

 case ST_CONF_GUID:
    DEBUG((EFI_D_ERROR, "State=ST_CONF_GUID\n"));
    if (Emit) {
      EFI_GUID Guid;
      
      DEBUG((EFI_D_ERROR, "%a.%d Guid=%s\n",
        __FUNCTION__, __LINE__, Text));  
      Status = Str16ToGuid(Text, &Guid);
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n",
        __FUNCTION__, __LINE__)); 
        return Status;
      }
      Status = BootMngrSetVarsGuidIdxByGuid(&Guid);
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n",
        __FUNCTION__, __LINE__)); 
        return Status;
      }
    }
    break;

  case ST_CONF_TYPE:
    DEBUG((EFI_D_ERROR, "State=ST_CONF_TYPE\n"));
    if (Emit) {
      Status = GetBootTypeFromString(Text, &DataSet->BootType);
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
          __FUNCTION__, __LINE__, Status));
        return Status;
      }
    }
    break;
    
  case ST_BOOT_TYPE:
    DEBUG((EFI_D_ERROR, "State=ST_BOOT_TYPE\n"));
    if (Emit) {
      Status = GetModuleTypeFromString(Text, &DataSet->ModulesType);
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
          __FUNCTION__, __LINE__, Status));
        return Status;
      }
    }
    break;
    
  case ST_MODULE:
    DEBUG((EFI_D_ERROR, "State=ST_MODULE\n"));
    if (State == ST_BOOT_CONF && NextState == ST_MODULE) {
      
    } else if (State == ST_MODULE && NextState == ST_BOOT_CONF) {
      if (bModuleDevPathFound) {
        DataSetIdx++;
      }
      bModuleDevPathFound = FALSE;
    }
    break;

  case ST_DEVPATH:
    DEBUG((EFI_D_ERROR, "State=ST_DEVPATH\n"));
    if (Emit) {
      if (Length >= sizeof(Rec->DevPath) / sizeof(CHAR16) - 1) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
          __FUNCTION__, __LINE__));
        return EFI_ABORTED;
      }
      StrCpy(Rec->DevPath, Text);
      bModuleDevPathFound = TRUE;
    }
    break;

  case ST_PARAMS:
    DEBUG((EFI_D_ERROR, "State=ST_PARAMS\n"));
    if (Emit) {
      if (Length >= sizeof(Rec->Args) / sizeof(CHAR16) - 1) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
          __FUNCTION__, __LINE__));
        return EFI_ABORTED;
      }
      StrCpy(Rec->Args, Text);
    }
    break;

  case ST_MOD_HASH:
    DEBUG((EFI_D_ERROR, "State=ST_MOD_HASH\n"));
    if (Emit) {
      if (Length > MAX_HASH_LEN * sizeof(CHAR16)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
          __FUNCTION__, __LINE__));
        return EFI_ABORTED;
      }
      AsciiSPrint(TmpStr8, sizeof(TmpStr8), "%s", Text);
      DEBUG((EFI_D_ERROR, "HashStr: %a\n", TmpStr8));
      Status = HexStringToByteBufRev(TmpStr8, Rec->Hash, sizeof(Rec->Hash));
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
          __FUNCTION__, __LINE__));
        return Status;
      }
      DumpBytes(Rec->Hash, sizeof(Rec->Hash));
    }
    break;

  case ST_ICFL:
    DEBUG((EFI_D_ERROR, "State=ST_ICFL\n"));
    if (Emit) {
      Status = StoreIcfl(IcflList);
      DestroyIcflList(IcflList);
      InitializeListHead(IcflList);
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
          __FUNCTION__, __LINE__, Status));
        return Status;
      }
    }
    break;

  case ST_ENTRY:
    DEBUG((EFI_D_ERROR, "State=ST_ENTRY\n"));
    if (State == ST_ICFL && NextState == ST_ENTRY) {
      bIcflHashPresent = FALSE;      
    } else if (State == ST_ENTRY && NextState == ST_ICFL) {
      Status = EFI_SUCCESS;
      if (bIcflHashPresent && IcflFileName != NULL) {
        if (IcflItemPresent(IcflFileName, IcflList)) {
          Status = EFI_ABORTED;
          DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
            __FUNCTION__, __LINE__));
        } else {
          ICFL_LIST *List;
          List = AllocateZeroPool(sizeof(ICFL_LIST) - sizeof(CHAR16) + 
            StrSize(IcflFileName));
          if (List == NULL) {
            Status = EFI_ABORTED;
            DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
              __FUNCTION__, __LINE__));
          } else {
            StrCpy(List->FileName, IcflFileName);
            CopyMem(List->Hash, IcflHash, sizeof(IcflHash));
            InsertTailList(IcflList, &List->Entry);
          }
        }
      }
      if (IcflFileName) {
        FreePool(IcflFileName);
        IcflFileName = NULL;
      }
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
          __FUNCTION__, __LINE__));
        return Status;
      }
    }
    break;

  case ST_FILE:
    DEBUG((EFI_D_ERROR, "State=ST_FILE\n"));
    if (Emit) {
      if (IcflFileName) {
        FreePool(IcflFileName);
        IcflFileName = NULL;
      }
      IcflFileName = AllocateCopyPool((Length + 1) * sizeof(CHAR16), Text);
      if (IcflFileName == NULL) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
          __FUNCTION__, __LINE__));
        return EFI_OUT_OF_RESOURCES;
      }
    }
    break;

  case ST_HASH:
    DEBUG((EFI_D_ERROR, "State=ST_HASH\n"));
    if (Emit) {
      if (Length > MAX_HASH_LEN * sizeof(CHAR16)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
          __FUNCTION__, __LINE__));
        return EFI_ABORTED;
      }
      AsciiSPrint(TmpStr8, sizeof(TmpStr8), "%s", Text);
      DEBUG((EFI_D_ERROR, "HashStr: %a\n", TmpStr8));
      Status = HexStringToByteBufRev(TmpStr8, IcflHash, sizeof(IcflHash));
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
          __FUNCTION__, __LINE__));
        return Status;
      }
      DumpBytes(IcflHash, sizeof(IcflHash));
      bIcflHashPresent = TRUE;
    }
    break;

  default:
    DEBUG((EFI_D_ERROR, "Unknown state: %X\n", State));
    return EFI_INVALID_PARAMETER;
  }
    
  return EFI_SUCCESS;
}

/* 
   simpler than dealing with strcasecmp and more efficient as we only
   need to fold the incoming text 
 */
#define FOLD(c) ((c < 'A' || c > 'Z') ? c : (c + 'a' - 'A'))

STATIC
INT32
ConfigCallback(
  IN INT32 Event,
  IN CONST CHAR16 *Txt,
  IN INT32 Len,
  IN OUT VOID *User1,
  IN OUT VOID *User2
  )
{
  EFI_STATUS Status;
  CONST CHAR16 *Name;
  UINT32 i, j, match = 0, Next, Length = (UINT32)Len;


  Next = CurState; /* stay in same state */

  for (i = 0; gConfigStateTable[i].State != ST_ERROR_TAG; i++) {
    if(gConfigStateTable[i].State == CurState &&
        gConfigStateTable[i].Event == (UINT32)Event) {
      if(gConfigStateTable[i].Name) {          /* if we have a name */

        if(gConfigStateTable[i].Length == (UINT32)Len) {  /* same length? */
          match = 1; /* assume match */
          Name = gConfigStateTable[i].Name;
          for(j=0; j < Length; j++) {
            /* only case fold the incoming txt tags */
            //            DEBUG((EFI_D_ERROR, "%x:%x", name[j], txt[j]));
            if(Name[j] != FOLD(Txt[j])) {
              match = 0; /* doesn't match */
              break;
            }
          }
        }
      } else {
        match = 1; /* no name, match implicitly */
      }

      if(match) {
        Status = ParseConfig16( 
            (CHAR16*)Txt,
            Length,
            CurState, 
            gConfigStateTable[i].Next,
            gConfigStateTable[i].Emit, 
            User1,
            User2
            );
        
        DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
            __FUNCTION__, __LINE__, Status));
        if (EFI_ERROR(Status)) {
          DEBUG((EFI_D_ERROR, "%a.%d error! Status=0x%X\n", 
            __FUNCTION__, __LINE__, Status));
          ErrorsCnt++;
          return 0;
        }

        Next = gConfigStateTable[i].Next;
        break;
      } 
    }
  }

  CurState = Next;

  DEBUG((EFI_D_ERROR, "%a.%d match=%d\n", 
            __FUNCTION__, __LINE__, match));
  return match;
}


EFI_STATUS
Xml16ConfigRead(
  IN CHAR16 *ConfigText,
  IN UINTN Size
  )
{
  Tinyxml16_t *Tinyxml16;
  LIST_ENTRY IcflList;
  CBCFG_DATA_SET *DataSet;
  UINTN DataLen;
  EFI_STATUS Status = EFI_SUCCESS;

  DataSetIdx = 0;
  DataSet = NULL;
  InitializeListHead(&IcflList);
  CurState = 0;
  HowMuchDataSets = 0;
  ErrorsCnt = 0;

  DataLen = sizeof(CBCFG_DATA_SET) - 1 + 
    MAXIMUM_BOOT_OPTIONS * sizeof(CBCFG_RECORD);

  DataSet = AllocateZeroPool(DataLen);
  if (NULL == DataSet) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  Tinyxml16 = Tinyxml16_new((INT32)Size, ConfigCallback, 
    &IcflList, DataSet);

  Tinyxml16_feed(Tinyxml16, ConfigText, (INT32) Size);
  DEBUG((EFI_D_ERROR, "Tinyxml16->State=%X\n", Tinyxml16->State));
  DEBUG((EFI_D_ERROR, "Tinyxml16->Event=%X\n", Tinyxml16->Event));

  if(Tinyxml16->Halt) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  } else if (HowMuchDataSets == 0 || ErrorsCnt != 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_INVALID_PARAMETER;
  }
  
Done:
  if (DataSet) {
    FreePool(DataSet);
  }
  
  //DestroyIcflList(&IcflList);
  
  Tinyxml16_free(Tinyxml16);
  return Status;
}


