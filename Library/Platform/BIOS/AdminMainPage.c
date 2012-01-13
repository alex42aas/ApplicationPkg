/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/DeviceManager/DeviceManagerInterface.h>
#include <Library/Lib/AdminMainPage.h>
#include <Protocol/LegacyBios.h>
#include <Library/PciDevsMonitorLib.h>
#include <Library/ChipsetCfgLib.h>

extern UINT8 MainPagevfrBin[];

STATIC MULTIBOOT_CONFIG *CurrentConfig;
STATIC EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
STATIC EFI_HII_HANDLE CurrentHiiHandle;
STATIC VOID *StartOpCodeHandle, *EndOpCodeHandle;
STATIC BOOLEAN bFormExitFlag;
STATIC UINT32 CurrentEvent;
extern struct tMainFvInfo MainFvInfo;
STATIC ADV_MENU_HANDLER_PROTOCOL *pAdvMenuHandlerProto;

EFI_STRING_ID AdvMenuStrings[] = {
                                  STRING_TOKEN(STR_CONFIG_SAVES_SUCCESS), 
                                  STRING_TOKEN(STR_CONFIG_SAVES_ERROR),
                                  STRING_TOKEN(STR_INCORRECT_IP_ADDRESS),
                                  STRING_TOKEN(STR_CORRRESPONDENCE_DATA_TYPE_ERROR),
                                  STRING_TOKEN(STR_GUEST_UNSUPPORTED_SETTING),
                                  STRING_TOKEN(STR_ADVANCED_MODE_PAGE_TITLE),
                                  STRING_TOKEN(MSG_URL_EMPTY),
                                  STRING_TOKEN(STR_PASSWORD_SET),
                                  STRING_TOKEN(STR_PASSWORD_NOT_SET),
                                  STRING_TOKEN(STR_INCORRECT_TCP_PORT),
                                  STRING_TOKEN(STR_CONFIG_APPLY_SUCCESS),
                                  STRING_TOKEN(STR_CONFIG_SETTINGS_UNSUPPORTED),
                                  STRING_TOKEN(STR_CONFIG_INCORRECT_VALUE),
                                  STRING_TOKEN(MSG_SUBJECT),
                                  STRING_TOKEN(MSG_ISSUER),
                                  STRING_TOKEN(MSG_NOT_BEFORE),
                                  STRING_TOKEN(MSG_NOT_AFTER),
                                  STRING_TOKEN(MSG_SERIAL),
                                  STRING_TOKEN(MSG_PORT_TO_BIG),
                                  STRING_TOKEN(MSG_DIAGNOSTIC_LOG_NOT_SET)
                                  };

/**/
#define AMT_READY_TO_BOOT_PROTOCOL_GUID \
  { \
    0x40b09b5a, 0xf0ef, 0x4627, 0x93, 0xd5, 0x27, 0xf0, 0x4b, 0x75, 0x4d, 0x5 \
  }

typedef struct _AMT_READY_TO_BOOT_PROTOCOL AMT_READY_TO_BOOT_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *AMT_READY_TO_BOOT_PROTOCOL_SIGNAL) (
  VOID
  );

struct _AMT_READY_TO_BOOT_PROTOCOL {
  AMT_READY_TO_BOOT_PROTOCOL_SIGNAL Signal;
};

EFI_GUID gAmtReadyToBootProtocolGuid = AMT_READY_TO_BOOT_PROTOCOL_GUID;

#define DXE_PLATFORM_AMT_POLICY_GUID \
  { \
    0xb2ab115e, 0xc8b6, 0x4036, 0xbf, 0x31, 0xe7, 0x4b, 0xd8, 0x92, 0x6c, 0xce \
  }

//
// Protocol revision number
// Any backwards compatible changes to this protocol will result in an update in the revision number
// Major changes will require publication of a new protocol
//
#define DXE_PLATFORM_AMT_POLICY_PROTOCOL_REVISION_2 2
#define DXE_PLATFORM_AMT_POLICY_PROTOCOL_REVISION_3 3
#define DXE_PLATFORM_AMT_POLICY_PROTOCOL_REVISION_4 4
#define DXE_PLATFORM_AMT_POLICY_PROTOCOL_REVISION_5 5 // Added BiosParamsPtr to the Policy structure
#define DXE_PLATFORM_AMT_POLICY_PROTOCOL_REVISION_6 6 // Added FWVerbose, USBProvision and FWProgress to AMT_CONFIG structure
#define DXE_PLATFORM_AMT_POLICY_PROTOCOL_REVISION_7 7 // Added LocalFwQualifier to AMT_CONFIG structure
#define DXE_PLATFORM_AMT_POLICY_PROTOCOL_REVISION_8 8 // Added Enable/Redirection functions
#define DXE_PLATFORM_AMT_POLICY_PROTOCOL_REVISION_9 9 // Cleanup unused fields
EFI_GUID gDxePlatformAmtPolicyGuid = DXE_PLATFORM_AMT_POLICY_GUID;
#pragma pack(1)
typedef struct {
  //
  // Byte 0, bit definition for functionality enable/disable
  //
  UINT8   AsfEnabled : 1;           // 0: Disabled; 1: Enabled
  UINT8   iAmtEnabled : 1;          // 0: Disabled; 1: Enabled
  UINT8   iAmtbxPrompt : 1;         // 0: Disabled; 1: Enabled
  UINT8   iAmtSpiLock : 1;          // 0: Disabled; 1: Enabled
  UINT8   iAmtbxPasswordWrite : 1;  // 0: Disabled; 1: Enabled
  UINT8   Reserved3 : 1;
  UINT8   WatchDog : 1;             // 0: Disabled; 1: Enabled
  UINT8   Reserved1 : 1;
  //
  // Byte 1, bit definition for functionality enable/disable
  //
  UINT8   CiraRequest : 1;        // 0: No CIRA request; 1: Trigger CIRA request
  UINT8   Reserved : 1;
  UINT8   ManageabilityMode : 2;  // 0: Off, 1:On
  UINT8   Reserved4 : 2;
  UINT8   SolEnabled : 1;         // 0: Disabled, 1: Enabled
  UINT8   IderEnabled : 1;        // 0: Disabled, 1: Enabled
  //
  // Byte 2, bit definition for functionality enable/disable
  //
  UINT8   UnConfigureMe : 1;            // 0: nope, 1: Un-configure ME without password
  UINT8   MebxDebugMsg : 1;             // 0: nope, 1: Mebx Debug Messages Enabled
  UINT8   Reserved2 : 1;
  UINT8   UsbrEnabled : 1;              // 0: Disabled,  1: Enabled
  UINT8   UsbLockingEnabled : 1;        // 0: Disabled,  1: Enabled
  UINT8   HideUnConfigureMeConfirm : 1; // 0: Don't hide 1: Hide Un-configure ME Confirmation Prompt
  UINT8   Reserved5 : 1;
  UINT8   TdtEnabled : 1;               // 0: Disabled, 1: Enabled
  //
  // Byte 3 bit definition for functionality enable/disable
  //
  UINT8   MeFwDownGrade : 1;
  UINT8   FWVerbose : 1;              // 0: Verbosity Disabled; 1: Enabled in Bios setup
  UINT8   USBProvision : 1;           // 0: USB provision Disabled; 1: Enabled in Bios setup
  UINT8   FWProgress : 1;             // 0: FW progress Disabled; 1: Enabled in Bios setup
  UINT8   MeLocalFwUpdEnabled : 1;    // 0: Disabled, 1: Enabled
  UINT8   Reserved6 : 1;
  UINT8   iAmtbxHotkeyPressed : 1;    // 0: Disabled, 1: Enabled
  UINT8   iAmtbxSelectionScreen : 1;  // 0: Disabled, 1: Enabled
  //
  // Byte 4-5 OS WatchDog Timer
  //
  UINT16  WatchDogTimerOs;

  //
  // Byte 6-7 BIOS WatchDog Timer
  //
  UINT16  WatchDogTimerBios;

  //
  // Byte 8-9 ASF Get Boot Options waiting Timer in second
  //
  UINT16  AmtWaitTimer;

  //
  // Byte 10  Flash Write Protect Software SMI number for POST complete flag set in SMM
  //
  UINT8   AmtFlashWriteProtectPostCompleteSwSmiNumber;

  //
  // Byte 11 CIRA Timeout, Client Initiated Remote Access Timeout
  //             OEM defined timeout for MPS connection to be established.
  //
  UINT8   CiraTimeout;

  //
  // Byte 12-15 Pointer to a list which contain on-board devices bus/device/fun number
  //
  UINT32  PciDeviceFilterOutTable;

  //
  // Byte 16-23 Reserved and make AMT_CONFIG as 32 bit alignment
  //
  UINT8   ByteReserved[8];
} AMT_CONFIG;

#pragma pack()
//
// AMT DXE Platform Policiy ====================================================
//
typedef struct _DXE_AMT_POLICY_PROTOCOL {
  UINT8                 Revision;
  AMT_CONFIG            AmtConfig;
  EFI_PHYSICAL_ADDRESS  *BiosParamsPtr;
} DXE_AMT_POLICY_PROTOCOL;

STATIC BOOLEAN bNeedAmt = FALSE;

BOOLEAN
ExtractHiiFormFromHiiHandle (
  IN      EFI_HII_HANDLE      Handle,
  IN      EFI_GUID            *SetupClassGuid,
  IN      UINT16              FormId
  )
{
  EFI_STATUS                   Status;
  UINTN                        BufferSize;
  EFI_HII_PACKAGE_LIST_HEADER  *HiiPackageList;
  UINT8                        *Package;
  UINT8                        *OpCodeData;
  UINT32                       Offset;
  UINT32                       Offset2;
  UINT32                       PackageListLength;
  EFI_HII_PACKAGE_HEADER       PackageHeader;
  EFI_GUID                     *ClassGuid;
  UINT8                        ClassGuidNum;
  EFI_HII_DATABASE_PROTOCOL    *gHiiDatabase;
  UINT8                        OpCode;
  BOOLEAN                      bFoundFormSet = FALSE;
  EFI_IFR_FORM                 *Form;
  
  ASSERT (Handle != NULL);
  ASSERT (SetupClassGuid != NULL);  

  ClassGuidNum  = 0;
  ClassGuid     = NULL;

  Status = gBS->LocateProtocol (
                  &gEfiHiiDatabaseProtocolGuid,
                  NULL,
                  (VOID**)&gHiiDatabase
                  );

  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  //
  // Get HII PackageList
  //
  BufferSize = 0;
  HiiPackageList = NULL;
  Status = gHiiDatabase->ExportPackageLists (gHiiDatabase, Handle, &BufferSize, HiiPackageList);
  //
  // Handle is a invalid handle. Check if Handle is corrupted.
  //
  ASSERT (Status != EFI_NOT_FOUND);
  //
  // The return status should always be EFI_BUFFER_TOO_SMALL as input buffer's size is 0.
  //
  ASSERT (Status == EFI_BUFFER_TOO_SMALL);
  
  HiiPackageList = AllocatePool (BufferSize);
  ASSERT (HiiPackageList != NULL);

  Status = gHiiDatabase->ExportPackageLists (gHiiDatabase, Handle, &BufferSize, HiiPackageList);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  DEBUG ((EFI_D_ERROR, "-----------\n"));

  //
  // Get Form package from this HII package List
  //
  Offset = sizeof (EFI_HII_PACKAGE_LIST_HEADER);
  Offset2 = 0;
  PackageListLength = ReadUnaligned32 (&HiiPackageList->PackageLength);

  while (Offset < PackageListLength) {
    Package = ((UINT8 *) HiiPackageList) + Offset;
    CopyMem (&PackageHeader, Package, sizeof (EFI_HII_PACKAGE_HEADER));

    if (PackageHeader.Type == EFI_HII_PACKAGE_FORMS) {
      //
      // Search FormSet Opcode in this Form Package
      //
      Offset2 = sizeof (EFI_HII_PACKAGE_HEADER);
      while (Offset2 < PackageHeader.Length) {
        OpCodeData = Package + Offset2;

        OpCode = ((EFI_IFR_OP_HEADER *) OpCodeData)->OpCode;
        DEBUG ((EFI_D_ERROR, "OpCode=%02X\n", OpCode));
        if (OpCode == EFI_IFR_FORM_OP) {
          Form = (EFI_IFR_FORM*)OpCodeData;
          DEBUG ((EFI_D_ERROR, "Form->FormId = %04X\n", Form->FormId));
          if (bFoundFormSet && FormId == Form->FormId) {
            FreePool (HiiPackageList);
            return TRUE;
          }
        }
        if (OpCode == EFI_IFR_FORM_SET_OP) {
          if (((EFI_IFR_OP_HEADER *) OpCodeData)->Length > OFFSET_OF (EFI_IFR_FORM_SET, Flags)) {
            //
            // Find FormSet OpCode
            //
            ClassGuidNum = (UINT8) (((EFI_IFR_FORM_SET *) OpCodeData)->Flags & 0x3);
            ClassGuid = (EFI_GUID *) (VOID *)(OpCodeData + sizeof (EFI_IFR_FORM_SET));
            DEBUG ((EFI_D_ERROR, "ClassGuid = %g SetupClassGuid=%g\n", 
              ClassGuid, SetupClassGuid));
            while (ClassGuidNum-- > 0) {
              if (CompareGuid (SetupClassGuid, ClassGuid)) {
                  DEBUG ((EFI_D_ERROR, "Match ClassGuid = %g\n", ClassGuid));
                  bFoundFormSet = TRUE;
              }
              ClassGuid ++;
            }
          } else {
            DEBUG ((EFI_D_ERROR, "%a.%d Achtung!!!!\n", 
              __FUNCTION__, __LINE__));
          }
        }
        
        //
        // Go to next opcode
        //
        Offset2 += ((EFI_IFR_OP_HEADER *) OpCodeData)->Length;
      }
    }
    
    //
    // Go to next package
    //
    Offset += PackageHeader.Length;
  }

  FreePool (HiiPackageList);

  return FALSE;
}


EFI_HII_HANDLE
SearchHiiHandleByFormId (
  IN UINT16 FormId
  )
{
  EFI_HII_HANDLE *HiiHandles;
  UINTN Index;

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
  HiiHandles = HiiGetHiiHandles (NULL);
//  ASSERT (HiiHandles != NULL);
  
  for (Index = 0; HiiHandles[Index] != NULL; Index++) {
    BOOLEAN bFound;
    extern EFI_GUID gLoaderGuid;
    bFound = ExtractHiiFormFromHiiHandle (
                HiiHandles[Index],
                &gLoaderGuid, //IN EFI_GUID * SetupClassGuid,
                FormId
                );
    if (bFound) {
      return HiiHandles[Index];  
    }
  }

  return NULL;
}


BOOLEAN
IsNeedAmt (
  VOID
  )  
{
  return bNeedAmt;
}

VOID
AmtHelper (
  VOID
  )
{
  EFI_STATUS Status;
  EFI_HANDLE *Handles;
  UINTN Count;
  UINTN Index;
  AMT_READY_TO_BOOT_PROTOCOL *AmtReadyToBoot;
  DXE_AMT_POLICY_PROTOCOL    *AmtPolicyProtocolInst;

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = gBS->LocateProtocol (&gDxePlatformAmtPolicyGuid, 
    NULL, &AmtPolicyProtocolInst);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "No AMT Platform Policy Protocol available"));    
  } else {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    AmtPolicyProtocolInst->AmtConfig.iAmtbxHotkeyPressed = 1;
    AmtPolicyProtocolInst->AmtConfig.iAmtbxSelectionScreen = 1;
  }

  (VOID)gAmtReadyToBootProtocolGuid; 
  (VOID)Count;
  (VOID)Handles;
  (VOID)Index;
  (VOID)AmtReadyToBoot;
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
}


extern BOOLEAN
CheckEngeneerPasswdPresent(
  IN struct tMainFvInfo *pmfvi,
  IN CHAR8 *Guid
  );

VOID
SoundForError(
  VOID
  );

VOID InitApmdz(
  VOID
  );

EFI_STATUS
AreYouSureToProceedUpdate(
  EFI_STRING_ID WarningStrId
  )
{
  EFI_INPUT_KEY Key;
  EFI_STATUS Status = EFI_ABORTED;
  
  do {
    CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_RED, &Key, 
      HiiGetString(CurrentHiiHandle, WarningStrId, NULL), 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BIOS_UPDATE_SURE), NULL),
      NULL);
    if (Key.UnicodeChar == 'Y' || Key.UnicodeChar == 'y') {
      Status = EFI_SUCCESS;
      break;
    }
    if (Key.UnicodeChar == 'N' || Key.UnicodeChar == 'n') {
      Status = EFI_ABORTED;
      break;
    }
  } while (1);

  gST->ConOut->ClearScreen(gST->ConOut);
  return Status;
}


BOOLEAN
NeedUpdateEfiVars(
  VOID
  )
{
  EFI_INPUT_KEY Key;
  BOOLEAN RetVal = FALSE;
  
  do {
    CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_RED, &Key, 
      HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(STR_ASK_FOR_UPDATE_EFI_VARS), NULL),
      NULL);
    if (Key.UnicodeChar == 'Y' || Key.UnicodeChar == 'y') {
      RetVal = TRUE;
      break;
    }
    if (Key.UnicodeChar == 'N' || Key.UnicodeChar == 'n') {
      RetVal = FALSE;
      break;
    }
  } while (1);

  gST->ConOut->ClearScreen(gST->ConOut);
  return RetVal;
}


STATIC
EFI_STATUS
CheckBiosFile(
  IN CHAR16 *Fname,
  IN OUT UINT8 **Data,
  IN OUT UINTN *DataSize
  )
{
  EFI_FILE_HANDLE File;
  UINTN FileLen;
  struct tMainFvInfo MainFv;
  T_FIRMWARE_INFO FwInfo;
  BiosInfoRecord *pBiosInfo = NULL;
  EFI_STATUS Status;  
  EFI_GUID TmpGuid;

  DEBUG((EFI_D_ERROR, "%a.%d Fname={%s}\n", __FUNCTION__, __LINE__, Fname));
  
  File = LibFsOpenFile16(Fname, EFI_FILE_MODE_READ, 0);
  if (NULL == File) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  FileLen = *DataSize = LibFsSizeFile(File);
  DEBUG((EFI_D_ERROR, "%a.%d FileLen={%d}\n", __FUNCTION__, __LINE__, FileLen));
  if (*DataSize == 0) {
    LibFsCloseFile(File);
    ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_WRONG_BIOS_FILE),NULL)); 
    return EFI_ABORTED;
  }

  *Data = AllocateZeroPool(*DataSize);
  if (NULL == *Data) {
    LibFsCloseFile(File);
    return EFI_ABORTED;
  }

  LibFsReadFile(File, &FileLen, *Data);
  LibFsCloseFile(File);

  Status = FindMainFvInByteBuf(*Data, *DataSize, MAIN_FV_GUID_STR, &MainFv);
  if (EFI_ERROR(Status)) {
    if (CheckPcdDebugPropertyMask()) {
      Status = AreYouSureToProceedUpdate(STRING_TOKEN(STR_WRONG_BIOS_FILE));
      if (EFI_ERROR(Status)) {
        return Status;
      }
    } else {
      ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(STR_WRONG_BIOS_FILE),NULL));    
      return Status;
    }
  }

  if (!IsItFwUpdate(&MainFv)) {
    if (CheckPcdDebugPropertyMask()) {
      Status = AreYouSureToProceedUpdate(STRING_TOKEN(STR_WRONG_UPDATE_FILE));
      if (EFI_ERROR(Status)) {
        return Status;
      }
    } else {
      ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(STR_WRONG_UPDATE_FILE),NULL));
      return EFI_NOT_FOUND;
    }
  }

  pBiosInfo = (BiosInfoRecord*)FindBiosInfoRecord(&MainFv);
  if (NULL == pBiosInfo) {
    if (CheckPcdDebugPropertyMask()) {
      Status = AreYouSureToProceedUpdate(
        STRING_TOKEN(STR_ERR_BIOS_INFO_NOT_FOUND));
      if (EFI_ERROR(Status)) {
        return Status;
      }
    } else {
      ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(STR_ERR_BIOS_INFO_NOT_FOUND),NULL));    
      return EFI_NOT_FOUND;
    }
  }
  GetFirmwareInfo(&FwInfo);

  CopyMem(&TmpGuid, &pBiosInfo->PlatformGuid, sizeof(EFI_GUID));
  if (CompareGuid_L(&FwInfo.PlatformGuid, &TmpGuid)) {
    if (CheckPcdDebugPropertyMask()) {
      Status = AreYouSureToProceedUpdate(
        STRING_TOKEN(STR_ERR_BIOS_WRONG_HW_GUID));
      if (EFI_ERROR(Status)) {
        return Status;
      }
    } else { 
      ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(STR_ERR_BIOS_WRONG_HW_GUID),NULL));
      return EFI_NOT_FOUND;
    }
  }
  
  if (!CheckEngeneerPasswdPresent(&MainFv, BIOS_PASS_GUID)) {
    if (CheckPcdDebugPropertyMask()) {
      Status = AreYouSureToProceedUpdate(STRING_TOKEN(STR_ERR_ENGENEER_PASS));
      if (EFI_ERROR(Status)) {
        return Status;
      }
    } else {
      ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(STR_ERR_ENGENEER_PASS),NULL));
      return EFI_ABORTED;
    }
  }
  if (!CheckEngeneerPasswdPresent(&MainFv, FAIL_SAVE_PASS_GUID)) {
    if (CheckPcdDebugPropertyMask()) {
      Status = AreYouSureToProceedUpdate(STRING_TOKEN(STR_ERR_ENGENEER_PASS));
      if (EFI_ERROR(Status)) {
        return Status;
      }
    } else {
      ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(STR_ERR_ENGENEER_PASS),NULL));
      return EFI_ABORTED;
    }
  }

  if (-1 == CheckMainFvHashCs(MAIN_GUID_STR, &MainFv)) {
    if (CheckPcdDebugPropertyMask()) {
      Status = AreYouSureToProceedUpdate(STRING_TOKEN(STR_ERR_BIOS_SIGNATURE));
      if (EFI_ERROR(Status)) {
        return Status;
      }
    } else {
      ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(STR_ERR_BIOS_SIGNATURE),NULL));    
      return EFI_ABORTED;
    }
  }
  
  return EFI_SUCCESS;
}


STATIC
VOID
UpdateSuPassword(
  EFI_STRING_ID PswdId
  )
{
  CHAR16 *Password16;
  CHAR8 Password8[255];
  EFI_STATUS Status;
  EFI_INPUT_KEY Key;
  //UINT32 PassCreationTime;
  USER_INFO *pUserInfo;
  USER_INFO_LOG_PASS *pLogPassUsr;
  UINT8 HashBuf[MAX_HASH_LEN];

  if (PswdId == (EFI_STRING_ID)0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return;
  }

  Password16 = HiiGetString(CurrentHiiHandle, PswdId, NULL);
  if (Password16 == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return;
  }
  if (*Password16 == L'\0') {
    DEBUG((EFI_D_ERROR, "%a.%d: empty password!\n", __FUNCTION__, __LINE__));
    return;
  }

  Status = CheckPasswordSymbols(Password16, (UINT32) StrLen(Password16));
  if (EFI_ACCESS_DENIED == Status) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    CleanKeyBuffer();
    CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_RED, &Key, 
      HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(STR_USER_WEAK_PASSWORD_ERR), NULL), NULL);
    return;
  }

  pUserInfo = GetCurrentUser();

  UnicodeStrToAsciiStr(Password16, Password8);
  Status = SuPassUpdate(Password8, AsciiStrLen(Password8));
  if (EFI_ERROR(Status)) {
    return;
  }
  
  if ((pUserInfo->Flags & USER_SU_FLAG) == 0) {
    return;
  }
  if (pUserInfo->ExtDataLen != sizeof(USER_INFO_LOG_PASS)) {
    return;
  }
  pLogPassUsr = (USER_INFO_LOG_PASS*)pUserInfo->ExtData;
  Status = SuGetHash(HashBuf);  
  if (!EFI_ERROR(Status)) {
    if (0 == CompareMem(pLogPassUsr->PassHash, HashBuf, 
              GetHashLen(PASSWD_HASH_TYPE))) {
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_PASS_SAME_AS_OLD), NULL));
    }
  }
}


EFI_STATUS
AdminMainPageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  if (ActionRequest == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (QuestionId >= ADM_BIOS_UPDATE_FILES_START_ID && 
      QuestionId <= ADM_BIOS_UPDATE_FILES_END_ID) {
    return FeCallback(This, Action, QuestionId, Type, Value, ActionRequest);
  }

  switch (Action)  {
  case EFI_BROWSER_ACTION_FORM_OPEN:
    return EFI_SUCCESS;
  
  case EFI_BROWSER_ACTION_FORM_CLOSE:
    bFormExitFlag = TRUE;
    return EFI_SUCCESS;
  }

  if (Action != EFI_BROWSER_ACTION_RETRIEVE && 
      ADMIN_LOCK_ALL_BUT_HISTORY == GetAdminMenuLockMask () && 
      QuestionId != ADM_MAIN_PAGE_BIOS_LOG_CTRL_ID) {
    ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle,
      STRING_TOKEN(STR_FUNC_NOT_AVAIL_BIOS_LOG_FULL), NULL));
    if (QuestionId == ADM_MAIN_PAGE_SU_PASS_ID) {
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_RESET;
      return EFI_INVALID_PARAMETER;
    }
    return EFI_SUCCESS;
  }

  switch (QuestionId) {
  case ADM_MAIN_PAGE_SERT_CTRL_ID:
    CurrentEvent = ADM_MAIN_PAGE_SERT_CTRL_ID;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;
  
  case ADM_MAIN_PAGE_USRS_CTRL_ID:
    CurrentEvent = QuestionId;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;
  
  case ADM_MAIN_PAGE_BIOS_LOG_CTRL_ID:
    CurrentEvent = QuestionId;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;

  case ADM_MAIN_PAGE_INTEGRITY_CTRL_ID:
    CurrentEvent = QuestionId;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;

  
  case ADM_MAIN_AMT_FUNC:
  case ADM_MAIN_BOOT_1_ID:
  case ADM_MAIN_BOOT_2_ID:
  case ADM_MAIN_BOOT_3_ID:
  case ADM_MAIN_PAGE_ADM_VIRTUAL_ID:
  case ADM_MAIN_PAGE_RESTORE_OPERATIONAL_ID:
  case ADM_MAIN_PAGE_COMPLEX_INSTALL_ID:
  case ADM_MAIN_PAGE_LOCAL_ADMIN_ID:
    CurrentEvent = QuestionId;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;

  case ADM_MAIN_PAGE_DATE_TIME_SETUP_ID:
  case ADM_MAIN_PAGE_BIOS_UPDATE_ID:
  case ADM_MAIN_PAGE_SET_DAD_ID:
  case ADM_MAIN_PAGE_ADV_MENU_ID:
    CurrentEvent = QuestionId;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;

  case ADM_MAIN_PAGE_SU_PASS_ID:
    if (Value == NULL) {
      break;      
    }
    if (Action == EFI_BROWSER_ACTION_RETRIEVE) {
      break;
    }
    UpdateSuPassword(Value->string);
    break;

  case ADM_MAIN_PAGE_DBG_LOAD_PARAM_ID:    
    if (Value == NULL) {
      break;      
    }
    if (EFI_SUCCESS != SetSetupFlag(Value->u8 ? TRUE : FALSE, 
         SETUP_FLAG_DBG_LOAD_PARAMS)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    }
    break;

  case ADM_MAIN_LEGACY_BIOS_ITEM1_ID:
    /* place here handler */
    InitApmdz();
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    break;

  case ADM_MAIN_PAGE_MEM_TEST_ID:
    CurrentEvent = QuestionId;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;

  case RUN_BOOT_MANAGER:
    {
      MULTIBOOT_ENTRY *Entry;
      
      Entry = FindEntryByIndex(CurrentConfig, ADM_MAIN_BOOT_MENU_ID);
      SetBootManagerMenuMode(Entry == NULL ? 
        BOOT_MNGR_BASIC_MODE : BOOT_MNGR_HIDE_CTRL_MODE);
      CallBootManager(GetDevicePathFromCfg(CurrentConfig, 
            RUN_BOOT_MANAGER));
      CurrentEvent = QuestionId;
    }
    break;

  case ADM_MAIN_BOOT_MENU_ID:
    SetBootManagerMenuMode(BOOT_MNGR_CTRL_ONLY_MODE);
    CallBootManager(GetDevicePathFromCfg(CurrentConfig, 
          RUN_BOOT_MANAGER));
    CurrentEvent = QuestionId;
    break;

  case ADM_MAIN_CHIPSET_CONFIG_ID:
    CallChipsetConfig();
    CurrentEvent = QuestionId;
    break;

  case ADM_MAIN_EQUIPMENT_MONITOR_ID:
    RunPciDevsMonitor();
    CurrentEvent = QuestionId;
    break;

  case ADM_MAIN_PAGE_DEV_MANAGER_ID:
    CurrentEvent = QuestionId;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;
  
  default:
    bFormExitFlag = FALSE;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
    CurrentEvent = 0;
    break;
  }
  return EFI_SUCCESS;
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
  EFI_GUID FormSetGuid = FORMSET_ADM_MAIN_PAGE_GUID;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_FORM_ID FormId = ADM_MAIN_PAGE_ID;
  
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
  StartLabel->Number       = LABEL_ADM_MAIN_PAGE_LIST_START;

  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      EndOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_ADM_MAIN_PAGE_LIST_END;
  
  Status = EFI_SUCCESS;
  
  HiiUpdateForm(CurrentHiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
  
_exit:  
  return Status;
}


STATIC
EFI_STATUS
AdminMainPageStrings(
IN EFI_HII_HANDLE HiiHandle
  )
{
  LIST_ENTRY *ListEntry;
  MULTIBOOT_FORM *CurrentForm;
  MULTIBOOT_ENTRY *Entry;
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_GUID FormSetGuid = FORMSET_ADM_MAIN_PAGE_GUID;
  EFI_FORM_ID FormId = ADM_MAIN_PAGE_ID;
  USER_INFO *pCurrUsr;
  EFI_STATUS Status;
  UINT16 Flags;
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  pCurrUsr = GetCurrentUser();
  
  if (EFI_SUCCESS != AllocateHiiResources()) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  CurrentForm = GetFormById(CurrentConfig, FormId);
  if (NULL == CurrentForm) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  ListEntry = CurrentForm->EntryHead.ForwardLink;
  
  HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);

  while (ListEntry != &CurrentForm->EntryHead) {
    Entry = _CR( ListEntry, MULTIBOOT_ENTRY, ListEntry );

    Token = HiiSetString (HiiHandle, 0, Entry->Name, NULL);
    QuestionId = (EFI_QUESTION_ID) (Entry->Index);

    if (Entry->Index == ADM_MAIN_PAGE_RECOVER_1_ID || 
        Entry->Index == ADM_MAIN_PAGE_RECOVER_2_ID) {
      goto _next_entry;
    } else if (Entry->Index == ADM_MAIN_PAGE_SU_PASS_ID) {      
      if (NULL == pCurrUsr) {
        DEBUG((EFI_D_ERROR, "%a.%d: Error!!!\n", __FUNCTION__, __LINE__));
        goto _next_entry;
      }
      if ((pCurrUsr->Flags & USER_SU_FLAG) == 0) {
        goto _next_entry;
      }
      VfrCreatePasswordOpCode(StartOpCodeHandle, PASSWORD_MIN_LEN,
        PASSWORD_MAX_LEN, QuestionId, 0, 0, Token, HelpToken);      
    } else if (Entry->Index == ADM_MAIN_PAGE_DBG_LOAD_PARAM_ID)  {
      Status = GetSetupFlags(&Flags);
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        goto _next_entry;
      }
      if (Entry->SecureGrayGuid != NULL) {
        Status = VfrCreateGraySecCheckBox (
              StartOpCodeHandle,
              ADM_MAIN_PAGE_DBG_LOAD_PARAM_ID,
              Token, 
              HelpToken,
              (Flags & SETUP_FLAG_DBG_LOAD_PARAMS) ? 
                    EFI_IFR_CHECKBOX_DEFAULT : 0,
              Entry->SecureGrayGuid
              );
      } else {      
        HiiCreateCheckBoxOpCode (StartOpCodeHandle, 
          ADM_MAIN_PAGE_DBG_LOAD_PARAM_ID, 0, 0, Token, HelpToken, 
          EFI_IFR_FLAG_CALLBACK,
          (Flags & SETUP_FLAG_DBG_LOAD_PARAMS) ? EFI_IFR_CHECKBOX_DEFAULT : 0, 
          NULL);
      }
    } else if (Entry->Index == ADM_MAIN_COMP_UNBLOCK_ID) {
      if (pCurrUsr->UserId != USER_SU_ID) {
        goto _next_entry;
      }
      if (NULL == HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
          HelpToken, EFI_IFR_FLAG_CALLBACK, 0)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
        return EFI_OUT_OF_RESOURCES;
      }
    } else if (Entry->Index == ADM_MAIN_LEGACY_BIOS_ITEM1_ID)  {
      if (!PciDevPresent(0xF005, 0x1172)) {
        goto _next_entry;
      }
      if (Entry->SecureGrayGuid != NULL) {
        Status = VfrCreateGraySecAction (StartOpCodeHandle,
                                         QuestionId,  
                                         Token, 
                                         HelpToken,  
                                         Entry->SecureGrayGuid);
        if (EFI_ERROR(Status)) {
          return Status;
        }
      } else {
        if (NULL == HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
            HelpToken, EFI_IFR_FLAG_CALLBACK, 0)) {
          DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
          return EFI_OUT_OF_RESOURCES;
        }
      }
    } else {
      if (Entry->SecureGrayGuid != NULL) {
        Status = VfrCreateGraySecAction (StartOpCodeHandle,
                                         QuestionId,  
                                         Token, 
                                         HelpToken,  
                                         Entry->SecureGrayGuid);
        if (EFI_ERROR(Status)) {
          return Status;
        }
      } else {
        if (NULL == HiiCreateActionOpCode(StartOpCodeHandle, QuestionId, Token,
            HelpToken, EFI_IFR_FLAG_CALLBACK, 0)) {
          DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
          return EFI_OUT_OF_RESOURCES;
        }
      }
      
    }

    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);

_next_entry:
    ListEntry  = ListEntry->ForwardLink;
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
AdminMainPage(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  EFI_GUID FormSetGuid = FORMSET_ADM_MAIN_PAGE_GUID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (EFI_SUCCESS != AllocateHiiResources()) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  
  Status = AdminMainPageStrings(HiiHandle);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
    goto _exit;
  }

  Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
    (VOID **) &gFormBrowser2);
  if (EFI_ERROR (Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
    goto _exit;
  }

  ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
  Status = EFI_SUCCESS;

  do {
    Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1,
      &FormSetGuid, ADM_MAIN_PAGE_ID, NULL, &ActionRequest);
    
    DEBUG((EFI_D_ERROR, "%a.%d: bFormExitFlag=%d\n",
      __FUNCTION__, __LINE__, bFormExitFlag));
    if (bFormExitFlag) {
      Status = EFI_SUCCESS;
      break;
    }
  } while (1);

_exit:  
  DestroyHiiResources();

  return Status;
}


VOID
AdminSetCurrentConfig(
  IN MULTIBOOT_CONFIG *Cfg
  )
{
  CurrentConfig = Cfg;
}


EFI_STATUS
AdminCheckCurrentUserPassExpiration(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  USER_INFO *pCurrUsr;
  USER_INFO_LOG_PASS *pUserLogPass;
  //EFI_STATUS Status;
  
  pCurrUsr = GetCurrentUser();
  if (NULL == pCurrUsr) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error!!!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  if (pCurrUsr->Flags & USER_SU_FLAG) {
    return EFI_SUCCESS;
  }
  pUserLogPass = (USER_INFO_LOG_PASS*)pCurrUsr->ExtData;
  
  if (TimeStampInFuture(pUserLogPass->PassCreateTime)) {
    DEBUG((EFI_D_ERROR, "%a.%d TimeStampInFuture...\n", 
      __FUNCTION__, __LINE__));

    ShowErrorPopup(HiiHandle, 
      HiiGetString(HiiHandle, 
        STRING_TOKEN(STR_WRONG_DATE_TIME_CHANGE_PASS), NULL));
    return EFI_ABORTED;
  }
  
  if (SixMonthExpired(pUserLogPass->PassCreateTime)) {
    DEBUG((EFI_D_ERROR, "%a.%d SixMonthExpired...\n", 
      __FUNCTION__, __LINE__));
    ShowErrorPopup(HiiHandle, 
      HiiGetString(HiiHandle, STRING_TOKEN(STR_ERR_USER_PASS_EXPIRE), NULL));
    return EFI_ABORTED;
  }
  return EFI_SUCCESS;
}


EFI_STATUS
AdminMainPageStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  EFI_STATUS Status;
  EFI_GUID FormSetGuid = FORMSET_ADM_MAIN_PAGE_GUID;
  
  HistoryAddRecord(HEVENT_ADMIN_MODE, GetCurrentUserId(), SEVERITY_LVL_DEBUG, 
    HISTORY_RECORD_FLAG_RESULT_OK);

  if (NULL == CurrentConfig) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!!!!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  SetAdminAdditionalFunction(0);

  Status = AdvancedMenuInit(HiiHandle, CurrentConfig);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=%X No Advanced menu!\n", 
      __FUNCTION__, __LINE__, Status));
  }

  HistorySetAddRecordQuietFlag (TRUE);
  
  do {
    bFormExitFlag = FALSE;
    CurrentHiiHandle = HiiHandle;
    CurrentEvent = 0;

    Status = AdminMainPage(HiiHandle);
    if (EFI_ERROR(Status)) {
      return Status;
    }    

    switch (CurrentEvent) {
    case ADM_MAIN_PAGE_USRS_CTRL_ID:
      HistoryAddRecord(HEVENT_USR_CTRL_MODE_ENTER, GetCurrentUserId(), 
        SEVERITY_LVL_DEBUG, HISTORY_RECORD_FLAG_RESULT_OK);
      UsersSetUserTypesFlags(USER_TYPE_USER | USER_TYPE_ADMIN);
      Status = UsersControlPage(HiiHandle, Language);
      HistoryAddRecord(HEVENT_USR_CTRL_MODE_EXIT, GetCurrentUserId(), 
        SEVERITY_LVL_DEBUG, 
        EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      break;

    case ADM_MAIN_PAGE_DATE_TIME_SETUP_ID:
      HistoryAddRecord(HEVENT_DATE_TIME_MODE_ENTER, GetCurrentUserId(), 
        SEVERITY_LVL_DEBUG, HISTORY_RECORD_FLAG_RESULT_OK);
      DEBUG((EFI_D_ERROR, "%a.%d ADM_MAIN_PAGE_DATE_TIME_SETUP_ID\n", 
        __FUNCTION__, __LINE__));
      Status = DateTimePageStart(HiiHandle,Language);
      HistoryAddRecord(HEVENT_DATE_TIME_MODE_EXIT, GetCurrentUserId(), 
        SEVERITY_LVL_DEBUG, 
        EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      break;

    case ADM_MAIN_PAGE_SET_DAD_ID:
      HistoryAddRecord(HEVENT_DAD_SETUP_MODE_ENTER, GetCurrentUserId(), 
        SEVERITY_LVL_DEBUG, HISTORY_RECORD_FLAG_RESULT_OK);
      DEBUG((EFI_D_ERROR, "%a.%d ADM_MAIN_PAGE_SET_DAD_ID\n", 
        __FUNCTION__, __LINE__));
      Status = PciDevListPageStart(HiiHandle);
      HistoryAddRecord(HEVENT_DAD_SETUP_MODE_EXIT, GetCurrentUserId(), 
        SEVERITY_LVL_DEBUG, 
        EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      break;

    case ADM_MAIN_PAGE_ADV_MENU_ID:
      {
        DEBUG((EFI_D_ERROR, "%a.%d ADM_MAIN_PAGE_ADV_MENU_ID\n", 
          __FUNCTION__, __LINE__));
      }

      break;
    
    case ADM_MAIN_PAGE_BIOS_UPDATE_ID:
      {
        CHAR16 *StrPtr16;
        UINT8 *Data = NULL;
        UINTN DataSize;
        BOOLEAN bUpdateEfiVars = FALSE;
        CHAR16 TmpPtr16[10];

        if (!HistoryOutswapped()) {
          ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
            STRING_TOKEN(STR_HISTORY_NEED_TO_OUTSWAP),NULL));
          break;
        }

        HistoryAddRecord(HEVENT_BIOS_UPDATE_MODE_ENTER, GetCurrentUserId(), 
          SEVERITY_LVL_DEBUG, HISTORY_RECORD_FLAG_RESULT_OK);
        CurrentEvent = 0;
        DEBUG((EFI_D_ERROR, "%a.%d ADM_MAIN_PAGE_BIOS_UPDATE_ID\n", 
          __FUNCTION__, __LINE__));
        StrPtr16 = GetDevicePathFromCfg(CurrentConfig, 
          ADM_MAIN_PAGE_BIOS_UPDATE_ID);
        if (StrPtr16 == NULL) {
          Status = FindUsbPath();
          if (!EFI_ERROR(Status)) {
            UnicodeSPrint(TmpPtr16, sizeof(TmpPtr16), L"%s:\\", 
              USB_PATH_SHORT_NAME);
            StrPtr16 = TmpPtr16;
          }
        }
        if (!CheckFsPathPresent(StrPtr16, NULL)) {
          Status = FindSpecialDevPath(L"Pci(0x16,0x2)/Ata");
          if (!EFI_ERROR(Status)) {
            UnicodeSPrint(TmpPtr16, sizeof(TmpPtr16), L"%s:\\", 
              SPEC_PATH_SHORT_NAME);
            StrPtr16 = TmpPtr16;
          } else {
            ShowErrorPopup(CurrentHiiHandle,
              HiiGetString(CurrentHiiHandle, 
                STRING_TOKEN(STR_PLEASE_INSERT_FLASH_IN_PROPER_PORT), NULL));
            Status = EFI_SUCCESS;
            break;
          }
        }
        FeLibSetDevicePath(StrPtr16);
        Status = FeLibTest(HiiHandle, &FormSetGuid, ADM_MAIN_PAGE_ID,
            ADM_BIOS_UPDATE_FILES_START_ID, LABEL_ADM_MAIN_PAGE_LIST_START, 
            LABEL_ADM_MAIN_PAGE_LIST_END);
        DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
          __FUNCTION__, __LINE__, Status));
        StrPtr16 = FeGetSelectedString();
        if (EFI_ERROR(Status) || NULL == StrPtr16) {
          Status = EFI_SUCCESS;
          break;
        }
        Status = CheckBiosFile(StrPtr16, &Data, &DataSize);
        if (EFI_ERROR(Status)) {
          HistoryAddRecord(HEVENT_BIOS_UPDATE_MODE_EXIT, GetCurrentUserId(), 
           SEVERITY_LVL_DEBUG, 0);
          Status = EFI_SUCCESS;
          if (Data) {
            FreePool(Data);
          }
          break;
        }
        BiosUpdateSetHelperStrings(
          HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BIOS_WRITTING), NULL),
          HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BIOS_ERASING), NULL),
          HiiGetString(HiiHandle, STRING_TOKEN(STR_BIOS_REST), NULL));

        DisableToken(TRUE);
        if (CheckPcdDebugPropertyMask()) {
          bUpdateEfiVars = NeedUpdateEfiVars();
        }

        BootManagerNeedReinit (TRUE);
        Status = BiosUpdateFromByteBuf(Data, DataSize, bUpdateEfiVars);
        HistoryAddRecord (
          HEVENT_BIOS_UPDATE,
          GetCurrentUserId (), 
          SEVERITY_LVL_INFO,
          EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK
          );
        if (EFI_ERROR(Status)) {
          ShowErrorPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
            STRING_TOKEN(STR_ERR_BIOS_UPDATE),NULL));
            SoundForError();
        } else {
          ShowSuccessPopup(CurrentHiiHandle, HiiGetString(CurrentHiiHandle, 
            STRING_TOKEN(STR_BIOS_UPDATE_OK),NULL));
          gST->ConOut->ClearScreen(gST->ConOut);
        }
        
        gRT->ResetSystem (EfiResetShutdown, Status, 0, NULL);
      }
      break;
    
    case ADM_MAIN_PAGE_BIOS_LOG_CTRL_ID:
      HistoryAddRecord(HEVENT_HISTORY_MENU_ENTER, GetCurrentUserId(), 
        SEVERITY_LVL_DEBUG, HISTORY_RECORD_FLAG_RESULT_OK);
      Status = HistoryCtrlMenuStart(HiiHandle, Language);
      HistoryAddRecord(HEVENT_HISTORY_MENU_EXIT, GetCurrentUserId(), 
          SEVERITY_LVL_DEBUG, 
          EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      if (EFI_ERROR(Status)) {
        MsgInternalError(INT_ERR_WHILE_READ_HISTORY_STORAGE);
      }
      break;

    case ADM_MAIN_AMT_FUNC:
      //AmtHelper ();
      bNeedAmt = TRUE;
      SetAdminAdditionalFunction(ADM_MAIN_PAGE_RESTORE_OPERATIONAL_ID);
      Status = EFI_INVALID_PARAMETER;   
      break;

    case ADM_MAIN_BOOT_1_ID:
    case ADM_MAIN_BOOT_2_ID:
    case ADM_MAIN_BOOT_3_ID:
    case ADM_MAIN_PAGE_ADM_VIRTUAL_ID:
    case ADM_MAIN_PAGE_COMPLEX_INSTALL_ID:
    case ADM_MAIN_PAGE_RESTORE_OPERATIONAL_ID:
    case ADM_MAIN_PAGE_LOCAL_ADMIN_ID:
    case ADM_MAIN_PAGE_MEM_TEST_ID:
      SetAdminAdditionalFunction(CurrentEvent);
      Status = EFI_INVALID_PARAMETER;
      break;

    case ADM_MAIN_PAGE_INTEGRITY_CTRL_ID:
      IntegrityCheckingPageStart(HiiHandle, Language);
      break;
    
    case ADM_MAIN_PAGE_DEV_MANAGER_ID:
      HistoryAddRecord(HEVENT_DEV_MANAGER_MODE_ENTER, GetCurrentUserId(), 
        SEVERITY_LVL_DEBUG, HISTORY_RECORD_FLAG_RESULT_OK);
      DEBUG((EFI_D_ERROR, "%a.%d ADM_MAIN_PAGE_DEV_MANAGER_ID\n", 
        __FUNCTION__, __LINE__));
      DeviceManagerStart();
      HistoryAddRecord(HEVENT_DEV_MANAGER_MODE_EXIT, GetCurrentUserId(), 
        SEVERITY_LVL_DEBUG, 
        EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      break;

    case RUN_BOOT_MANAGER:
    case ADM_MAIN_BOOT_MENU_ID:
      {
        EFI_GUID *pGuid;
        MULTIBOOT_ENTRY *MbEntry;

        pGuid = BootMngrGetSelectedOptGuid();
        if (pGuid && CurrentConfig) {
          MbEntry = FindEntryByGuid(CurrentConfig, pGuid);
          if (MbEntry) {
            SetAdminAdditionalFunction((int)MbEntry->Index);
          }
          Status = EFI_INVALID_PARAMETER;
        } else {
          Status = EFI_SUCCESS;
        }
        
      }
      break;

    case ADM_MAIN_COMP_UNBLOCK_ID:
    case ADM_MAIN_EQUIPMENT_MONITOR_ID:
      Status = EFI_SUCCESS;
      break;

    case ADM_MAIN_CHIPSET_CONFIG_ID:
      Status = EFI_SUCCESS;
      break;

    default:
      DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
        __FUNCTION__, __LINE__, Status));
      Status = AreYouSureWarning(CurrentHiiHandle, 
        STRING_TOKEN(STR_SAVE_AND_REBOOT), 
        STRING_TOKEN(STR_YOUR_CHOISE));
      if (!EFI_ERROR(Status)) {
        goto _exit;
      } else {
        Status = EFI_SUCCESS;
      }
    }
    CurrentEvent = 0;
    DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
  } while (!EFI_ERROR(Status));
_exit:  
  DestroyHiiResources();

  HistoryAddRecord(HEVENT_ADMIN_MODE_EXIT, GetCurrentUserId(), 
    SEVERITY_LVL_DEBUG, EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
  gST->ConOut->ClearScreen(gST->ConOut);
  return Status;
}
