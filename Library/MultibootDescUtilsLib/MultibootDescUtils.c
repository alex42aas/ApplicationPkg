/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/MultibootDescUtils.h>


static OBJDESC *ObjectsDescTable;
static UINTN ObjectsDescTableCount;
static PCI_DA_DESC *PciDaDescTable;
static UINTN PciDaDescTableCount;


VOID
ShowPciDaItem(
  IN PCI_DA_DESC *PciDaDesc
  )
{
  DEBUG((EFI_D_INFO, "PciDaDesc->Bus = %d\n", PciDaDesc->Bus));
  DEBUG((EFI_D_INFO, "PciDaDesc->BusMask = %d\n", PciDaDesc->BusMask));
  DEBUG((EFI_D_INFO, "PciDaDesc->Dev = %d\n", PciDaDesc->Dev));
  DEBUG((EFI_D_INFO, "PciDaDesc->DevMask = %d\n", PciDaDesc->DevMask));
  DEBUG((EFI_D_INFO, "PciDaDesc->Func = %d\n", PciDaDesc->Func));
  DEBUG((EFI_D_INFO, "PciDaDesc->FuncMask = %d\n", PciDaDesc->FuncMask));
}


VOID
DestroyPciDaTable(
  VOID
  )
{
  if (PciDaDescTable) {
    FreePool(PciDaDescTable);
    PciDaDescTable = NULL;
    PciDaDescTableCount = 0;
  }
}

UINTN
CountPciDaItems(
  IN CHAR16 *PciDaStr
  )
{
  UINTN Cnt = 0;

  if (PciDaStr == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  while (*PciDaStr) {
    if (*PciDaStr == 0x0A) {
      Cnt++;
    }
    PciDaStr++;
  }
  return Cnt;
}

BOOLEAN
PciDaAlloweed(
  IN UINT8 Bus,
  IN UINT8 Dev,
  IN UINT8 Func
  )
{
  UINTN i;

  if (PciDaDescTableCount == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));  
    return FALSE;
  }
  
  for (i = 0; i < PciDaDescTableCount; i++) {
#if 0    
    ShowPciDaItem(&PciDaDescTable[i]);
#endif
    if ((PciDaDescTable[i].BusMask | PciDaDescTable[i].DevMask | 
        PciDaDescTable[i].FuncMask) == 0) {
      /* mask not present */
      if (PciDaDescTable[i].Bus != Bus) {
        continue;
      }
      if (PciDaDescTable[i].Dev != Dev) {
        continue;
      }
      if (PciDaDescTable[i].Func != Func) {
        continue;
      }
      return TRUE;
    }
    /* range with mask */
    if (PciDaDescTable[i].Bus != (Bus & PciDaDescTable[i].BusMask)) {
      continue;
    }
    if (PciDaDescTable[i].Dev != (Dev & PciDaDescTable[i].DevMask)) {
      continue;
    }
    if (PciDaDescTable[i].Func != (Func & PciDaDescTable[i].FuncMask)) {
      continue;
    }
    return TRUE;
  }
  return FALSE;
}

EFI_STATUS
ObtainPciDaItem(
  IN OUT PCI_DA_DESC *PciDaDesc, 
  IN CHAR16 *PciDaStr, 
  IN OUT UINTN *Offset
  )
{
  CHAR16 *BaseStr = &PciDaStr[*Offset];
  CHAR16 *TmpStr, *TmpStr2;
  UINTN Val;
  BOOLEAN bMaskPresent = FALSE;
  

  ZeroMem(PciDaDesc, sizeof(PCI_DA_DESC));

  TmpStr = FindSymbol(BaseStr, L'"');
  if (TmpStr == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  BaseStr = TmpStr + 1;
  
  /* obtain bus */
  TmpStr = FindSymbol(BaseStr, L'.');
  if (TmpStr == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  *TmpStr = 0;
  Val = StrDecimalToUintn (BaseStr);
  if (Val > 0xFF) {
    return EFI_INVALID_PARAMETER;
  }
  PciDaDesc->Bus = (UINT8)(Val & 0xFF);

  BaseStr = TmpStr + 1;
  *TmpStr = L'.';

  /* obtain dev */
  TmpStr = FindSymbol(BaseStr, L'.');
  if (TmpStr == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  *TmpStr = 0;

  Val = StrDecimalToUintn (BaseStr);
  if (Val > 0xFF) {
    return EFI_INVALID_PARAMETER;
  }
  PciDaDesc->Dev = (UINT8)(Val & 0xFF);

  BaseStr = TmpStr + 1;
  *TmpStr = L'.';

  /* obtain function */
  TmpStr2 = FindSymbol(BaseStr, L'"');
  TmpStr = FindSymbol(BaseStr, L':');
  if (TmpStr == NULL || TmpStr2 < TmpStr) {
    TmpStr = TmpStr2;
    if (TmpStr == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_NOT_FOUND;
    }
  } else {
    bMaskPresent = TRUE;
  }
  *TmpStr = 0;

  Val = StrDecimalToUintn (BaseStr);
  if (Val > 0xFF) {
    return EFI_INVALID_PARAMETER;
  }
  PciDaDesc->Func = (UINT8)(Val & 0xFF);

  BaseStr = TmpStr + 1;
  if (bMaskPresent) {
    *TmpStr = L':';
  } else {
    *TmpStr = L'"';
    *Offset = (TmpStr - PciDaStr) + 1;
    return EFI_SUCCESS;
  }

  BaseStr = TmpStr + 1;
  /* obtain bus mask */
  TmpStr = FindSymbol(BaseStr, L'.');
  if (TmpStr == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  *TmpStr = 0;

  Val = StrDecimalToUintn (BaseStr);
  if (Val > 0xFF) {
    return EFI_INVALID_PARAMETER;
  }
  PciDaDesc->BusMask= (UINT8)(Val & 0xFF);

  BaseStr = TmpStr + 1;
  *TmpStr = L'.';

  /* obtain dev mask */
  TmpStr = FindSymbol(BaseStr, L'.');
  if (TmpStr == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  *TmpStr = 0;

  Val = StrDecimalToUintn (BaseStr);
  if (Val > 0xFF) {
    return EFI_INVALID_PARAMETER;
  }
  PciDaDesc->DevMask= (UINT8)(Val & 0xFF);

  BaseStr = TmpStr + 1;
  *TmpStr = L'.';

  /* obtain function mask */
  TmpStr = FindSymbol(BaseStr, L'"');
  if (TmpStr == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  *TmpStr = 0;

  Val = StrDecimalToUintn (BaseStr);
  if (Val > 0xFF) {
    return EFI_INVALID_PARAMETER;
  }
  PciDaDesc->FuncMask= (UINT8)(Val & 0xFF);

  BaseStr = TmpStr + 1;
  *TmpStr = L'"';
  *Offset = (TmpStr - PciDaStr) + 1;
  return EFI_SUCCESS;
}


EFI_STATUS
CreatePciDaTable(
  IN UINT16 *PciDaStr
  )
{
  UINTN i, Cnt, Offset;
  EFI_STATUS Status;

  if (PciDaStr == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

#if 0
  DEBUG((EFI_D_INFO, "{%s}\n", PciDaStr));
#endif

  DestroyPciDaTable();
  Cnt = CountPciDaItems(PciDaStr);

  if (Cnt == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  PciDaDescTable = (PCI_DA_DESC*)AllocateZeroPool(sizeof(PCI_DA_DESC) * Cnt);
  if (NULL == PciDaDescTable) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  PciDaDescTableCount = Cnt;

  for (i = 0, Offset = 0; i < Cnt; i++) {
    Status = ObtainPciDaItem(&PciDaDescTable[i], PciDaStr, &Offset);
    if (EFI_ERROR(Status)) {
      DestroyPciDaTable();     
      return EFI_ABORTED;
    } else {
#if 0    
      ShowPciDaItem(&PciDaDescTable[i]);
#endif
    }
  }
  
  return EFI_SUCCESS;
}


static UINTN
CountDescObjects(
  IN UINT16 *ObjDescStr)
{
  UINTN DescObjCnt = 0;

  while (*ObjDescStr) {
    if (*ObjDescStr == L'=') {
      DescObjCnt++;
    }
    ObjDescStr++;
  }
  return DescObjCnt;
}


static EFI_STATUS
FillObjectsDescTable(
  IN CHAR16 *ObjDescStr,
  IN UINTN Count)
{
  return EFI_SUCCESS;
}


VOID
PrintObjectsDescTable(
  VOID
  )
{
  UINTN i;
  
  if (NULL == ObjectsDescTable) {
    return;
  }
  for (i = 0; i < ObjectsDescTableCount; i++) {
    DEBUG((EFI_D_INFO, "(%d) Guid: %g Desc: %s\n",
      i, &ObjectsDescTable[i].GuidVal, 
      ObjectsDescTable[i].ObjDesc));
  }
}


VOID
DestroyObjectsDescTable(
  VOID
  )
{
  if (NULL == ObjectsDescTable) {
    return;
  }
  FreePool(ObjectsDescTable);
  ObjectsDescTable = NULL;
}


EFI_STATUS
CreateObjectsDescTable(
  IN CHAR16 *ObjDescStr
  )
{
  UINTN Count, i;
  CHAR16 *TmpStr, *LeftEdge;
  UINT8 AsciiStr[255];
  EFI_STATUS Status;

  if (ObjDescStr == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (ObjectsDescTable != NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Count = CountDescObjects(ObjDescStr);
  if (Count == 0) {
    return EFI_INVALID_PARAMETER;
  }

  ObjectsDescTable = AllocateZeroPool(Count * sizeof(OBJDESC));
  if (NULL == ObjectsDescTable) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  for (i = 0; i < Count; i++) {
#if 0    
    ObjDescStr = FindSymbol(ObjDescStr, L'"');
    if (ObjDescStr == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d not found \" !\n", __FUNCTION__, __LINE__));
      break;
    }
    ObjDescStr++;
#endif
    TmpStr = FindSymbol(ObjDescStr, L'=');
    if (NULL == TmpStr) {
      goto _error_exit;
    }    
    *TmpStr++ = L'\0';

    TmpStr = FindSymbol(TmpStr, L'"');
    if (NULL == TmpStr) {
      goto _error_exit;
    }    
    *TmpStr++ = L'\0';

    UnicodeStrToAsciiStr(ObjDescStr, AsciiStr);

    Status = StringToGuid_L(AsciiStr, &ObjectsDescTable[i].GuidVal);
    if (EFI_ERROR(Status)) {
      goto _error_exit;
    }

    ObjectsDescTable[i].ObjDesc = TmpStr;

    LeftEdge = FindSymbol(TmpStr, L'"');
    if (LeftEdge) {
      *LeftEdge++ = L'\0';
    }

    ObjDescStr = KillCrlfAndWhiteSpaces(LeftEdge ? LeftEdge : TmpStr);
  }
  ObjectsDescTableCount = Count;

#if 0
  PrintObjectsDescTable();
#endif
  
  return EFI_SUCCESS;
  
_error_exit:
  DestroyObjectsDescTable();
  return EFI_INVALID_PARAMETER;
}


CHAR16 *
FindObjDescByGuid(
  IN EFI_GUID *Guid
  )
{
  UINTN i;

  if (ObjectsDescTable == NULL) {
    return NULL;
  }
  
  for (i = 0; i < ObjectsDescTableCount; i++) {
    if (CompareGuid_L(&ObjectsDescTable[i].GuidVal, Guid) == 0) {
      return ObjectsDescTable[i].ObjDesc;
    }
  }
  
  return NULL;
}

EFI_GUID *
GetNextObjDescGuid(
  IN BOOLEAN bRestart
  )
{
  STATIC UINTN i;

  if (ObjectsDescTable == NULL || ObjectsDescTableCount == 0) {
    return NULL;
  }
  if (bRestart) {
    i = 0;
  }
  if (i == ObjectsDescTableCount) {
    return NULL;
  }
  
  return &ObjectsDescTable[i++].GuidVal;
}

UINTN
GetObjDescCount(
  VOID
  )
{
  return ObjectsDescTableCount;
}


static int
CompareIndex(
  IN VOID *p1,
  IN VOID *p2
  )
{
  UINTN *pIndex1, *pIndex2;
  
  pIndex1 = (UINTN*)p1;
  pIndex2 = (UINTN*)p2;
  
  if (*pIndex1 == *pIndex2) {
    return 0;
  }
  return -1;
}


static INTN
CompareName(
  IN VOID *p1,
  IN VOID *p2
  )
{
  CHAR16 *pName1, *pName2;

  pName1 = (CHAR16*)p1;
  pName2 = (CHAR16*)p2;

  return StrCmp(pName1, pName2);
}


static MULTIBOOT_ENTRY *
FindEntryBy(
  MULTIBOOT_CONFIG *Config,
  UINTN FieldOffset,
  int (*Compare)(VOID*, VOID*))
{
  return 0;
}

MULTIBOOT_ENTRY *
FindEntryOnCurrentFormByIndex(
  MULTIBOOT_CONFIG *Config,
  UINTN Index
  )
{
  LIST_ENTRY *ListEntry;
  MULTIBOOT_ENTRY *Entry;
  MULTIBOOT_FORM *Form;

  Form = Config->CurrentForm;

  ListEntry = Form->EntryHead.ForwardLink;
  while( ListEntry != &Form->EntryHead ) {

    Entry = _CR(ListEntry, MULTIBOOT_ENTRY, ListEntry );
    if( Index == Entry->Index ) {
      return Entry;
    }

    ListEntry = ListEntry->ForwardLink;
  }

  return NULL;
}

MULTIBOOT_ENTRY *
FindEntryOnFormByIndex(
  MULTIBOOT_CONFIG *Config,
  MULTIBOOT_FORM *Form,
  UINTN Index
  )
{
  LIST_ENTRY *ListEntry;
  MULTIBOOT_ENTRY *Entry;
  
  ListEntry = Form->EntryHead.ForwardLink;
  while( ListEntry != &Form->EntryHead ) {

    Entry = _CR(ListEntry, MULTIBOOT_ENTRY, ListEntry );
    if( Index == Entry->Index ) {
      return Entry;
    }

    ListEntry = ListEntry->ForwardLink;
  }

  return NULL;
}

MULTIBOOT_ENTRY *
FindEntryByIndex(
  MULTIBOOT_CONFIG *Config,
  UINTN Index
  )
{
  LIST_ENTRY *ListForm, *ListEntry;
  MULTIBOOT_ENTRY *Entry;
  MULTIBOOT_FORM *Form;

  ListForm = Config->FormHead.ForwardLink;
  while( ListForm != &Config->FormHead ) {

    Form = _CR(ListForm, MULTIBOOT_FORM, ListForm);

    ListEntry = Form->EntryHead.ForwardLink;
    while( ListEntry != &Form->EntryHead ) {

      Entry = _CR(ListEntry, MULTIBOOT_ENTRY, ListEntry );
      if( Index == Entry->Index ) {
        return Entry;
      }

      ListEntry = ListEntry->ForwardLink;
    }
    ListForm = ListForm->ForwardLink;
  }
  return NULL;
}

MULTIBOOT_MODULE *
FindModuleByGuid(
  IN MULTIBOOT_CONFIG *Config,
  IN EFI_GUID *pGuid
  )
{
  LIST_ENTRY *ListForm, *ListEntry, *ListModules;
  MULTIBOOT_MODULE *Module;
  MULTIBOOT_ENTRY *Entry;
  MULTIBOOT_FORM *Form;
  EFI_GUID TmpGuid;
  EFI_STATUS Status;

  ListForm = Config->FormHead.ForwardLink;
  while( ListForm != &Config->FormHead ) {

    Form = _CR(ListForm, MULTIBOOT_FORM, ListForm);

    ListEntry = Form->EntryHead.ForwardLink;
    while( ListEntry != &Form->EntryHead ) {

      Entry = _CR(ListEntry, MULTIBOOT_ENTRY, ListEntry );

      ListModules = Entry->ModuleHead.ForwardLink;

      while( ListModules != &Entry->ModuleHead ) {
        Module = _CR(ListModules, MULTIBOOT_MODULE, ListEntry);
        Status = StringToGuid_L(Module->GuidStr, &TmpGuid);
        if (!EFI_ERROR(Status) && CompareGuid_L(&TmpGuid, pGuid) == 0) {
          return Module;
        }
        ListModules = ListModules->ForwardLink;
      }

      ListEntry = ListEntry->ForwardLink;
    }
    ListForm = ListForm->ForwardLink;
  }
  return NULL;
}


MULTIBOOT_ENTRY*
FindEntryByName(
  MULTIBOOT_CONFIG* Config,
  CHAR16 *Name
  )
{
#if 0
  LIST_ENTRY *ListEntry;
  MULTIBOOT_ENTRY *Entry;

  ListEntry = Config->EntryHead.ForwardLink;
  while( ListEntry != &Config->EntryHead ) {

    Entry = _CR(ListEntry, MULTIBOOT_ENTRY, ListEntry );
    if( StrCmp(Name, Entry->Name) == 0 ) {
      return Entry;
    }

    ListEntry = ListEntry->ForwardLink;
  }
#endif
  return NULL;
}


MULTIBOOT_ENTRY*
FindEntryByGuid(
  MULTIBOOT_CONFIG* Config,
  EFI_GUID *pGuid
  )
{
  LIST_ENTRY *ListForm, *ListEntry;
  MULTIBOOT_ENTRY *Entry;
  MULTIBOOT_FORM *Form;
  EFI_GUID TmpGuid;
  EFI_STATUS Status;

  ListForm = Config->FormHead.ForwardLink;
  while( ListForm != &Config->FormHead ) {

    Form = _CR(ListForm, MULTIBOOT_FORM, ListForm);

    ListEntry = Form->EntryHead.ForwardLink;
    while( ListEntry != &Form->EntryHead ) {

      Entry = _CR(ListEntry, MULTIBOOT_ENTRY, ListEntry );

      Status = StringToGuid_L(Entry->GuidStr, &TmpGuid);
      if (CompareGuid(pGuid, &TmpGuid)) {
        return Entry;
      }

      ListEntry = ListEntry->ForwardLink;
    }
    ListForm = ListForm->ForwardLink;
  }
  return NULL;

}



MULTIBOOT_FORM *
GetFormById(
  IN MULTIBOOT_CONFIG *Config,
  IN UINTN FormId
  )
{
  LIST_ENTRY *ListForm;
  MULTIBOOT_FORM *Form;

  ListForm = Config->FormHead.ForwardLink;
  while( ListForm != &Config->FormHead ) {
    Form = _CR(ListForm, MULTIBOOT_FORM, ListForm);
    if (Form == NULL) {
      return NULL;
    }

    if (FormId == Form->Id) {
      return Form;
    }
    ListForm = ListForm->ForwardLink;
  }
  return NULL;
}

MULTIBOOT_FORM *
GetFormByGuid(
  IN MULTIBOOT_CONFIG *Config,
  IN EFI_GUID *pFormGuid
  )
{
  LIST_ENTRY *ListForm;
  MULTIBOOT_FORM *Form;
  CHAR8 TmpStr[255];

  if (NULL == Config || NULL == pFormGuid) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }

  AsciiSPrint(TmpStr, sizeof(TmpStr), "%g", pFormGuid);

  ListForm = Config->FormHead.ForwardLink;
  while( ListForm != &Config->FormHead ) {
    Form = _CR(ListForm, MULTIBOOT_FORM, ListForm);
    if (Form == NULL) {
      return NULL;
    }
    
    DEBUG((EFI_D_INFO, "\"%a\" <--> \"%a\"\n", TmpStr, Form->GuidStr));
    if (AsciiStrniCmp(Form->GuidStr, TmpStr, AsciiStrLen(TmpStr)) == 0) {
      return Form;
    }
    ListForm = ListForm->ForwardLink;
  }
  return NULL;
}


VOID
ClearForm(
  IN MULTIBOOT_FORM *Form
)
{
  MULTIBOOT_ENTRY   *Entry;
  LIST_ENTRY *Link, *PrevLink;

  if (IsListEmpty(&Form->EntryHead) == FALSE) {
    for (Link = GetFirstNode(&Form->EntryHead);
         !IsNull(&Form->EntryHead, Link);
         ) {
      PrevLink = Link;
      Entry = (MULTIBOOT_ENTRY *)PrevLink;
      Link = GetNextNode (&Form->EntryHead, Link);
      RemoveEntryList (PrevLink);
      if (Entry->Help != NULL)
        FreePool(Entry->Help);
      FreePool(Entry);
    }
  }

  return;
}


VOID
DeleteEntry(
  IN MULTIBOOT_ENTRY   *Entry
)
{
  RemoveEntryList (&Entry->ListEntry);
  if (Entry->Help != NULL)
    FreePool(Entry->Help);
  FreePool(Entry);
}


VOID
DeleteFormByGuid(
  IN MULTIBOOT_CONFIG *Config,
  IN EFI_GUID *pFormGuid
  )
{
  MULTIBOOT_FORM *Form;

  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  Form = GetFormByGuid (Config, pFormGuid);
  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (Form != NULL) {
    DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    ClearForm (Form);
    DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    RemoveEntryList (&Form->ListForm);
    DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    FreePool (Form);
    DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    if (Config->CurrentForm == Form) {
      DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      Config->CurrentForm = NULL;
      DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    }
    DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  }
  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
}


CHAR16*
GetDevicePathFromCfg(
  IN MULTIBOOT_CONFIG *Config,
  IN UINTN EntryIndex
  )
{
  MULTIBOOT_ENTRY *Entry;
  MULTIBOOT_MODULE *pModule;
  LIST_ENTRY *ListEntryModules;
    
  Entry = FindEntryByIndex(Config, EntryIndex);
  if (NULL == Entry) {
    return NULL;
  }

  ListEntryModules = Entry->ModuleHead.ForwardLink;
  if(IsListEmpty(&Entry->ModuleHead)) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  pModule = _CR( ListEntryModules, MULTIBOOT_MODULE, ListEntry );
  if (pModule->DevPath == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }

  return (CHAR16*)pModule->DevPath;
}


DEV_PATH_ADV *
GetNextDevPathAdv(
  IN MULTIBOOT_MODULE *ModuleEntry,
  IN BOOLEAN bReset
  )
{
  static LIST_ENTRY *DevPathAdvList;

  if (bReset) {
    DevPathAdvList = ModuleEntry->DevPathAdvHead.ForwardLink;
  } else {
    DevPathAdvList = DevPathAdvList->ForwardLink;
  }
  if (DevPathAdvList == &ModuleEntry->DevPathAdvHead ) {
    return NULL;
  }
  return (DEV_PATH_ADV*)_CR(DevPathAdvList, DEV_PATH_ADV, ListEntry);
}

VOID
ShowDevPathAdv(
  IN MULTIBOOT_ENTRY *MbootDefaultEntry
  )
{
  LIST_ENTRY *ModulesList;
  MULTIBOOT_MODULE *ModuleEntry;
  DEV_PATH_ADV *DevPathAdv;
  BOOLEAN bReset;

  ModulesList = MbootDefaultEntry->ModuleHead.ForwardLink;
  
  while (ModulesList != &MbootDefaultEntry->ModuleHead) {
    ModuleEntry = (MULTIBOOT_MODULE *)ModulesList;

    bReset = TRUE;
    while ((DevPathAdv = GetNextDevPathAdv(ModuleEntry, bReset)) != NULL) {
      DEBUG((EFI_D_INFO, "DevPathAdv=\"%s\"\n", DevPathAdv->DevPath));
      bReset = FALSE;
    }
    
    ModulesList = ModulesList->ForwardLink;
  }
}


VOID
ShowAllDevPathAdv(
  IN MULTIBOOT_CONFIG *Config
  )
{
  LIST_ENTRY *ListForm, *ListEntry;
  MULTIBOOT_ENTRY *Entry;
  MULTIBOOT_FORM *Form;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  ListForm = Config->FormHead.ForwardLink;
  while( ListForm != &Config->FormHead ) {

    Form = _CR(ListForm, MULTIBOOT_FORM, ListForm);

    ListEntry = Form->EntryHead.ForwardLink;
    while( ListEntry != &Form->EntryHead ) {

      Entry = _CR(ListEntry, MULTIBOOT_ENTRY, ListEntry );

      ShowDevPathAdv(Entry);

      ListEntry = ListEntry->ForwardLink;
    }
    ListForm = ListForm->ForwardLink;
  }  
}

CHAR16*
GetDevicePathAdvFromCfg(
  IN MULTIBOOT_CONFIG *Config,
  IN UINTN EntryIndex,
  IN BOOLEAN bReset
  )
{
  MULTIBOOT_ENTRY *Entry;
  MULTIBOOT_MODULE *pModule;
  LIST_ENTRY *ListEntryModules;
  DEV_PATH_ADV *DevPathAdv;
    
  Entry = FindEntryByIndex(Config, EntryIndex);
  if (NULL == Entry) {
    return NULL;
  }

  ListEntryModules = Entry->ModuleHead.ForwardLink;
  if(IsListEmpty(&Entry->ModuleHead)) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  pModule = _CR( ListEntryModules, MULTIBOOT_MODULE, ListEntry );
  DevPathAdv = GetNextDevPathAdv(pModule, bReset);
  return DevPathAdv ? DevPathAdv->DevPath : NULL;
}


