/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "ChipsetConfig.h"
#include <Protocol/HistoryHandlerProto.h>
#include <Library/BIOSLib/History.h>


#if 1
#define LOG(MSG)
#else
#define LOG(MSG) DEBUG(MSG)
#endif

EFI_HII_HANDLE gStringPackHandle;
EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
enum {CCFG_MAIN_MENU, CCFG_BACK_TO_MAIN_MENU, CCFG_USB_SETTINGS};
STATIC UINT8 gChipsetConfigMenuMode = CCFG_MAIN_MENU;

STATIC MULTIBOOT_CONFIG *CurrentConfig;

enum {USB_LEGACY_SUPPORT_DISABLE, USB_LEGACY_SUPPORT_ENABLE};
enum {SATA_MODE_AHCI, SATA_MODE_IDE};
enum {SATA_AHCI_SLOW_DISABLE, SATA_AHCI_SLOW_ENABLE};
enum {PXE_OPROM_DISABLE, PXE_OPROM_ENABLE};
enum {SERIAL_PC_ANSI, SERIAL_VT100, SERIAL_VT100_PLUS, SERIAL_UTF8};

STATIC UINT16 UsbLegacyOpt[2];
STATIC UINT16 SataModeOpt[2];
STATIC UINT16 SataAhciSlowOpt[2];
STATIC UINT16 PxeOpromOpt[2];
STATIC UINT16 SerialTypeOpt[4];

STATIC VOID *StartOpCodeHandle, *EndOpCodeHandle;
extern MULTIBOOT_DATA *gMultibootData;
STATIC HISTORY_HANDLER_PROTOCOL *gHistoryHandlerProtocol;

EFI_STATUS
SerialConsoleOff (
  VOID
  )
{
  UINTN                     Index;
  EFI_DEVICE_PATH_PROTOCOL  *ConDevicePath;
  UINTN                     HandleCount;
  EFI_HANDLE                *HandleBuffer = NULL;
  EFI_STATUS                Status;

  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
  Status = gBS->LocateHandleBuffer (
          ByProtocol,
          &gEfiSerialIoProtocolGuid,
          NULL,
          &HandleCount,
          &HandleBuffer
          );
  DEBUG ((EFI_D_INFO, "%a.%d Status=%r HandleCount=%d\n", 
    __FUNCTION__, __LINE__, Status, HandleCount));
  if (EFI_ERROR(Status)) {
    return Status;
  }

  for (Index = 0; Index < HandleCount; Index++) {
    CHAR16 *Str16;
    
    gBS->HandleProtocol (
            HandleBuffer[Index],
            &gEfiDevicePathProtocolGuid,
            (VOID **) &ConDevicePath
            );
    Str16 = DevPathToString(ConDevicePath, FALSE, TRUE);
    if (Str16) {
      DEBUG ((EFI_D_INFO, "%d %s\n", Index, Str16));      
    }
    
    DEBUG ((EFI_D_INFO, "%a.%d Disconnect...\n", __FUNCTION__, __LINE__));
    Status = gBS->DisconnectController (HandleBuffer[Index], NULL, NULL);
    
    DEBUG ((EFI_D_INFO, "%a.%d Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
  }

  if (HandleBuffer != NULL) {
    FreePool(HandleBuffer);
  }

  return EFI_SUCCESS;
}


EFI_STATUS
GetCurrentConsoleType(
  UINT8 *ConsoleType
  )
{
  EFI_STATUS Status;
  EFI_GUID TerminalType;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = GetCurrentConsoleTypeGuid ( &TerminalType );
  if ( EFI_ERROR(Status) )return Status;

  if (CompareGuid (&TerminalType, &gEfiPcAnsiGuid)) {
    *ConsoleType = SERIAL_PC_ANSI;
  } else if (CompareGuid (&TerminalType, &gEfiVT100Guid)) {
    *ConsoleType = SERIAL_VT100;
  } else if (CompareGuid (&TerminalType, &gEfiVT100PlusGuid)) {
    *ConsoleType = SERIAL_VT100_PLUS;
  } else if (CompareGuid (&TerminalType, &gEfiVTUTF8Guid)) {
    *ConsoleType = SERIAL_UTF8;
  } else {
    DEBUG((EFI_D_INFO, "%a.%d TerminalType = %g\n", __FUNCTION__, __LINE__, &TerminalType));
    return EFI_INVALID_PARAMETER;
  }

  DEBUG((EFI_D_INFO, "%a.%d *ConsoleType = %d\n", __FUNCTION__, __LINE__, *ConsoleType));

  return EFI_SUCCESS;
}

EFI_STATUS
GetCurrentConsoleTypeGuid(
  EFI_GUID *pGUIdConsType
  )
{
  EFI_STATUS Status;
  EFI_GUID GUIdTermType;
  UINTN nTermTypeSize = sizeof(EFI_GUID);
  BDS_HELPER_PROTOCOL *pBDSHlpProt;

  DEBUG((EFI_D_INFO, "\nEntry "__FUNCTION__".%d\n", __LINE__));

  Status = gRT->GetVariable (CONSOLE_TYPE_VARIABLE_NAME, &gVendorGuid, NULL, &nTermTypeSize, &GUIdTermType);
  if (Status != EFI_SUCCESS)
  {
    DEBUG((EFI_D_INFO, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));

    Status = gBS->LocateProtocol ( &gBdsHelperProtocolGuid, NULL, &pBDSHlpProt );
    if (EFI_ERROR(Status))
	 {
      DEBUG((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
      return Status;
    }

    CopyGuid ( &GUIdTermType, pBDSHlpProt->GetDefaultTerminalTypeGuid( pBDSHlpProt ) );
  }

  CopyGuid ( pGUIdConsType, &GUIdTermType );
  DEBUG((EFI_D_INFO, __FUNCTION__".ConsoleTypeGuid = %g.%d\n", &GUIdTermType, __LINE__));

  return EFI_SUCCESS;
}

EFI_STATUS
SetCurrentConsoleType(
  UINT8 ConsoleType
  )
{
  EFI_STATUS Status;
  EFI_GUID TerminalType;

  DEBUG((EFI_D_INFO, "%a.%d ConsoleType = %d\n", __FUNCTION__, __LINE__, ConsoleType));

  if (ConsoleType == SERIAL_PC_ANSI) {
    CopyGuid (&TerminalType, &gEfiPcAnsiGuid);
  } else if (ConsoleType == SERIAL_VT100) {
    CopyGuid (&TerminalType, &gEfiVT100Guid);
  } else if (ConsoleType == SERIAL_VT100_PLUS) {
    CopyGuid (&TerminalType, &gEfiVT100PlusGuid);
  } else if (ConsoleType == SERIAL_UTF8) {
    CopyGuid (&TerminalType, &gEfiVTUTF8Guid);
  } else {
    DEBUG((EFI_D_ERROR, "%a.%d unexpected ConsoleType = %d\n", __FUNCTION__, __LINE__, ConsoleType));
    return EFI_INVALID_PARAMETER;
  }

  Status = gRT->SetVariable (CONSOLE_TYPE_VARIABLE_NAME, 
                             &gVendorGuid, 
                             (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | 
                              EFI_VARIABLE_RUNTIME_ACCESS), 
                             sizeof(EFI_GUID), 
                             &TerminalType);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  Status = gRT->SetVariable (VarConsoleInp, &gEfiGlobalVariableGuid, 0, 0, NULL);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
  }
  Status = gRT->SetVariable (VarConsoleOut, &gEfiGlobalVariableGuid, 0, 0, NULL);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
  }
  Status = gRT->SetVariable (VarErrorOut, &gEfiGlobalVariableGuid, 0, 0, NULL);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
  }

  return EFI_SUCCESS;
}

EFI_STATUS
ResetCurrentConsoleType(
  UINT8 *DefaultConsoleType
  )
{
  EFI_STATUS Status;
  EFI_GUID TerminalType;
  BDS_HELPER_PROTOCOL *Bhp;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = gBS->LocateProtocol (&gBdsHelperProtocolGuid, NULL, &Bhp);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  CopyGuid (&TerminalType, Bhp->GetDefaultTerminalTypeGuid(Bhp));
  if (CompareGuid (&TerminalType, &gEfiPcAnsiGuid)) {
    *DefaultConsoleType = SERIAL_PC_ANSI;
  } else if (CompareGuid (&TerminalType, &gEfiVT100Guid)) {
    *DefaultConsoleType = SERIAL_VT100;
  } else if (CompareGuid (&TerminalType, &gEfiVT100PlusGuid)) {
    *DefaultConsoleType = SERIAL_VT100_PLUS;
  } else if (CompareGuid (&TerminalType, &gEfiVTUTF8Guid)) {
    *DefaultConsoleType = SERIAL_UTF8;
  } else {
    DEBUG((EFI_D_ERROR, "%a.%d unexpected TerminalType = %g\n", __FUNCTION__, __LINE__, &TerminalType));
    return EFI_INVALID_PARAMETER;
  }

  Status = gRT->SetVariable (CONSOLE_TYPE_VARIABLE_NAME, &gVendorGuid, 0, sizeof(EFI_GUID), &TerminalType);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Status = gRT->SetVariable (VarConsoleInp, &gEfiGlobalVariableGuid, 0, 0, NULL);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
  }
  Status = gRT->SetVariable (VarConsoleOut, &gEfiGlobalVariableGuid, 0, 0, NULL);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
  }
  Status = gRT->SetVariable (VarErrorOut, &gEfiGlobalVariableGuid, 0, 0, NULL);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
  }
  DEBUG((EFI_D_ERROR, "%a.%d *DefaultConsoleType = %d\n", __FUNCTION__, __LINE__, *DefaultConsoleType));
  return EFI_SUCCESS;
}


STATIC
CHAR16 *
GetStringById_1 (
  IN  EFI_STRING_ID   Id
  )
{
  return HiiGetString (gStringPackHandle, Id, NULL);
}

static EFI_GUID mChipsetConfigGuid = CHIPSET_CONFIG_FORMSET_GUID;

HII_VENDOR_DEVICE_PATH  mChipsetConfigHiiVendorDevicePath = {
  {
    {
      HARDWARE_DEVICE_PATH,
      HW_VENDOR_DP,
      {
        (UINT8) (sizeof (VENDOR_DEVICE_PATH)),
        (UINT8) ((sizeof (VENDOR_DEVICE_PATH)) >> 8)
      }
    },
    //
    // {1DDDBE16-481D-4d2b-8277-B191EAF66525}
    //
    { 0x1dddbe16, 0x481d, 0x4d2b, { 0x82, 0x77, 0xb1, 0x91, 0xea, 0xf6, 0x65, 0x25 } }
  },
  {
    END_DEVICE_PATH_TYPE,
    END_ENTIRE_DEVICE_PATH_SUBTYPE,
    { 
      (UINT8) (END_DEVICE_PATH_LENGTH),
      (UINT8) ((END_DEVICE_PATH_LENGTH) >> 8)
    }
  }
};

EFI_STATUS
ObtainUsb30Settings (
  IN OUT USB30_CONTROLLER_SETTINGS **pUsb30Settings
  )
{
  USB30_CONTROLLER_SETTINGS *Usb30Settings;
  EFI_STATUS Status;
  UINTN Size;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (gRT == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  Size = 0;
  Status = gRT->GetVariable(USB30_SETTINGS_VARIABLE_NAME, &gVendorGuid, NULL,
    &Size, NULL);
  if (Status == EFI_NOT_FOUND) {
    *pUsb30Settings = NULL;
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }
  Usb30Settings = (USB30_CONTROLLER_SETTINGS *)AllocateZeroPool(Size);
  if (Usb30Settings == NULL) {
    *pUsb30Settings = NULL;
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  Status = gRT->GetVariable(USB30_SETTINGS_VARIABLE_NAME, &gVendorGuid, NULL,
    &Size, Usb30Settings);
  if (!EFI_ERROR(Status) && Size == sizeof (*Usb30Settings)) {
    *pUsb30Settings = Usb30Settings;
  } else {
    FreePool(Usb30Settings);
    Usb30Settings = NULL;
    Status = EFI_VOLUME_CORRUPTED;
  }
  return Status;
}


EFI_STATUS
ObtainUsbSetupEfiVar(
  IN OUT USB_SETUP **UsbSetupPtr
  )
{
  STATIC USB_SETUP *UsbSetup;
  EFI_STATUS Status;
  UINTN Size;
  extern EFI_RUNTIME_SERVICES  *gRT; 

  if (gRT == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  Size = 0;

  if (UsbSetup != NULL) {
    FreePool(UsbSetup);
    UsbSetup = NULL;
  }
  
  Status = gRT->GetVariable(USB_SETUP_VARIABLE_NAME, &gVendorGuid, NULL,
    &Size, NULL);
  if (Status == EFI_NOT_FOUND) {
    *UsbSetupPtr = NULL;
    DEBUG((EFI_D_ERROR, "%a.%d Status = 0x%X\n",  __FUNCTION__, __LINE__, Status));
    return Status;
  }
  UsbSetup = (USB_SETUP *)AllocateZeroPool(Size);
  if (UsbSetup == NULL) {
    *UsbSetupPtr = NULL;
    DEBUG((EFI_D_ERROR, "%a.%d Status = 0x%X\n",  __FUNCTION__, __LINE__, Status));
    return EFI_OUT_OF_RESOURCES;
  }
  Status = gRT->GetVariable(USB_SETUP_VARIABLE_NAME, &gVendorGuid, NULL,
    &Size, UsbSetup);
  if (Size == (sizeof(UsbSetup->PortsNumber) + sizeof(UsbSetup->PortsData[0])*(UsbSetup->PortsNumber==0?1:UsbSetup->PortsNumber))) {
    *UsbSetupPtr = UsbSetup;
  } else {
    FreePool(UsbSetup);
    UsbSetup = NULL;
    Status = EFI_VOLUME_CORRUPTED;
  }
  DEBUG((EFI_D_INFO, "%a.%d Status = 0x%X\n",  __FUNCTION__, __LINE__, Status));
  return Status;
}




/**
  This function allows a caller to extract the current configuration for one
  or more named elements from the target driver.
**/
STATIC
EFI_STATUS
EFIAPI
FakeExtractConfigBm (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  CONST EFI_STRING                       Request,
  OUT EFI_STRING                             *Progress,
  OUT EFI_STRING                             *Results
  )
{
  if (Progress == NULL || Results == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Progress = Request;
  return EFI_NOT_FOUND;
}

/**
  This function processes the results of changes in configuration.
**/
STATIC
EFI_STATUS
EFIAPI
FakeRouteConfigBm (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  CONST EFI_STRING                       Configuration,
  OUT EFI_STRING                             *Progress
  )
{
  if (Configuration == NULL || Progress == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
}

STATIC CHIPSET_CONFIG_CALLBACK_DATA  gChipsetConfigPrivate = {
  CHIPSET_CONFIG_CALLBACK_DATA_SIGNATURE,
  NULL,
  NULL,
  {
    FakeExtractConfigBm,
    FakeRouteConfigBm,
    ChipsetConfigCallback
  }
};

EFI_STATUS
EFIAPI
CCMainModeCallback (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  EFI_BROWSER_ACTION                     Action,
  IN  EFI_QUESTION_ID                        QuestionId,
  IN  UINT8                                  Type,
  IN  EFI_IFR_TYPE_VALUE                     *Value,
  OUT EFI_BROWSER_ACTION_REQUEST             *ActionRequest
  )
{
  STATIC BOOLEAN bFormClose;
  STATIC BOOLEAN bStayCurrent;
  EFI_STATUS Status;
  
  DEBUG((EFI_D_INFO, "MainModeCallback bFormClose %x QuestionId %x\n", bFormClose, QuestionId));

  if (Action == EFI_BROWSER_ACTION_FORM_OPEN) {
    bFormClose = FALSE;
    bStayCurrent = FALSE;
    return EFI_SUCCESS;
  }
  if (Action == EFI_BROWSER_ACTION_FORM_CLOSE) {
    if (!bStayCurrent && !bFormClose && 
        gChipsetConfigMenuMode != CCFG_MAIN_MENU) {
      gChipsetConfigMenuMode = CCFG_BACK_TO_MAIN_MENU;
    }
    return EFI_SUCCESS;
  }
  if ((Value == NULL) || (ActionRequest == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (Action == EFI_BROWSER_ACTION_RETRIEVE) {
    return EFI_SUCCESS;
  }

  *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
  if (gChipsetConfigMenuMode == CCFG_MAIN_MENU) {
    gChipsetConfigMenuMode = CCFG_BACK_TO_MAIN_MENU;
  } else {
    bStayCurrent = TRUE;
  }

  switch (QuestionId) {

  case USB_LEGACY_SUPPORT_ID:
    if (Value != NULL) {
      if (Value->u8 == UsbLegacyOpt[USB_LEGACY_SUPPORT_DISABLE]) {
        Status = SetSetupFlag(FALSE, SETUP_FLAG_USB_LEGACY_ENABLE);
      } else {
        Status = SetSetupFlag(TRUE, SETUP_FLAG_USB_LEGACY_ENABLE);
      }
      if (gHistoryHandlerProtocol != NULL && Status != EFI_ALREADY_STARTED) {
        gHistoryHandlerProtocol->AddRecord(
          gHistoryHandlerProtocol,
          HEVENT_USB_LEGACY_SUPPORT_CHANGE, 
          EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
          EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      }
    }
    break;

  case PXE_OPROM_SWITCH_ID:
    if (Value != NULL) {
      if (Value->u8 == PxeOpromOpt[PXE_OPROM_DISABLE]) {
        Status = SetSetupFlag(FALSE, SETUP_FLAG_LAUNCH_PXE_OPROM);
      } else {
        Status = SetSetupFlag(TRUE, SETUP_FLAG_LAUNCH_PXE_OPROM);
      }
      if (gHistoryHandlerProtocol != NULL && Status != EFI_ALREADY_STARTED) {
        gHistoryHandlerProtocol->AddRecord(
          gHistoryHandlerProtocol,
          HEVENT_PXE_OPROM_SWITCH_CHANGE, 
          EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
          EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      }
    }
    break;

  case SATA_MODE_SELECT_ID:
    if (Value != NULL) {
      if (Value->u8 == SataModeOpt[SATA_MODE_AHCI]) {
        Status = SetSetupFlag(FALSE, SETUP_FLAG_SATA_MODE);
      } else {
        Status = SetSetupFlag(TRUE, SETUP_FLAG_SATA_MODE);
      }
      if (gHistoryHandlerProtocol != NULL && Status != EFI_ALREADY_STARTED) {
        gHistoryHandlerProtocol->AddRecord(
          gHistoryHandlerProtocol,
          HEVENT_SATA_MODE_CHANGE, 
          EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
          EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      }
      gChipsetConfigMenuMode = CCFG_BACK_TO_MAIN_MENU;
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    }
    break;

  case SATA_AHCI_SLOW_SELECT_ID:
    if (Value != NULL) {
      if (Value->u8 == SataAhciSlowOpt[SATA_AHCI_SLOW_DISABLE]) {
        Status = SetSetupFlag(FALSE, SETUP_FLAG_SATA_AHCI_SLOW);
      } else {
        Status = SetSetupFlag(TRUE, SETUP_FLAG_SATA_AHCI_SLOW);
      }
      if (gHistoryHandlerProtocol != NULL && Status != EFI_ALREADY_STARTED) {
        gHistoryHandlerProtocol->AddRecord(
          gHistoryHandlerProtocol,
          HEVENT_SATA_AHCI_SLOW_CHANGE, 
          EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
          EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      }
    }
    break;

  case DISABLE_SERIAL_CONSOLE_ID:
    if (Value != NULL) {
      if (Value->u8) {
        Status = SetSetupFlag(TRUE, SETUP_FLAG_DISABLE_SERIAL_CON);        
      } else {
        Status = SetSetupFlag(FALSE, SETUP_FLAG_DISABLE_SERIAL_CON);
      }

      if (gHistoryHandlerProtocol != NULL && Status != EFI_ALREADY_STARTED) {
        gHistoryHandlerProtocol->AddRecord(
          gHistoryHandlerProtocol,
          HEVENT_DISABLE_SERIAL_CON_CHANGE, 
          EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
          EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      }
    }
    break;

  case SERIAL_CONSOLE_TYPE:
    if (Value != NULL)
	 {
		 DEBUG ((EFI_D_INFO, __FUNCTION__".Value->u8=%d.%d\n", Value->u8, __LINE__));

      if (Value->u8 == SerialTypeOpt[SERIAL_PC_ANSI]) {
        Status = SetCurrentConsoleType (SERIAL_PC_ANSI);
      } else if (Value->u8 == SerialTypeOpt[SERIAL_VT100]) {
        Status = SetCurrentConsoleType (SERIAL_VT100);
      } else if (Value->u8 == SerialTypeOpt[SERIAL_VT100_PLUS]) {
        Status = SetCurrentConsoleType (SERIAL_VT100_PLUS);
      } else if (Value->u8 == SerialTypeOpt[SERIAL_UTF8]) {
        Status = SetCurrentConsoleType (SERIAL_UTF8);
      } else {
        Status = EFI_INVALID_PARAMETER;
      }
      if (gHistoryHandlerProtocol != NULL && Status != EFI_ALREADY_STARTED) {
        gHistoryHandlerProtocol->AddRecord(
          gHistoryHandlerProtocol,
          HEVENT_SERIAL_CONSOLE_TYPE_CHANGE, 
          EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
          EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      }
    }
    break;

  case AMT_LOCK_KEYBORD_ID:
    if (Value != NULL) {
      if (Value->u8) {
        Status = SetSetupFlag(TRUE, SETUP_FLAG_AMT_KBC_LOCK);
      } else {
        Status = SetSetupFlag(FALSE, SETUP_FLAG_AMT_KBC_LOCK);
      }
      if (gHistoryHandlerProtocol != NULL && Status != EFI_ALREADY_STARTED) {
        gHistoryHandlerProtocol->AddRecord(
          gHistoryHandlerProtocol,
          HEVENT_AMT_KBC_LOCK_CFG_CHANGE, 
          EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
          EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      }
    }
    break;

   case USB30_MODE_ENABLE_ID:
    if (Value != NULL) {
      USB30_CONTROLLER_SETTINGS *pUsb30Settings = NULL;

      Status = ObtainUsb30Settings(&pUsb30Settings);
      if (pUsb30Settings != NULL) {
        if (Value->u8) {
          pUsb30Settings->Mode = 2; // auto
        } else {
          pUsb30Settings->Mode = 0; // off
        }
        Status = gRT->SetVariable (
              USB30_SETTINGS_VARIABLE_NAME,
              &gVendorGuid,
              (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | 
               EFI_VARIABLE_RUNTIME_ACCESS),
              sizeof(*pUsb30Settings),
              pUsb30Settings
              );
        FreePool (pUsb30Settings);
      } else {
        Status = EFI_ABORTED;
      }
      
      if (gHistoryHandlerProtocol != NULL && Status != EFI_ALREADY_STARTED) {
        gHistoryHandlerProtocol->AddRecord(
          gHistoryHandlerProtocol,
          HEVENT_USB30_MODE_ENABLE_CHANGE, 
          EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
          EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      }
    }
    break;

  case PS2_PORT_CFG_ID:
    if (Value != NULL) {
      if (Value->u8) {
        Status = SetSetupFlag(TRUE, SETUP_FLAG_PS2_EN);
      } else {
        Status = SetSetupFlag(FALSE, SETUP_FLAG_PS2_EN);
      }
      if (gHistoryHandlerProtocol != NULL && Status != EFI_ALREADY_STARTED) {
        gHistoryHandlerProtocol->AddRecord(
          gHistoryHandlerProtocol,
          HEVENT_PS2_PORT_CFG_CHANGE, 
          EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
          EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      }
    }
    break;

  case USB_PORTS_CFG_START_ID:
    gChipsetConfigMenuMode = CCFG_USB_SETTINGS;
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    bFormClose = TRUE;
    break;

  default:
    if (QuestionId > USB_PORTS_CFG_START_ID &&
        QuestionId <= USB_PORTS_CFG_END_ID && 
        Value != NULL) {
      UINT16 PortNum;
      USB_SETUP *pUsbSet;
      
      PortNum = QuestionId - USB_PORTS_CFG_START_ID - 1;
      Status = ObtainUsbSetupEfiVar(&pUsbSet);
      if (!EFI_ERROR(Status)) {
        Status = EFI_ABORTED;
        if (pUsbSet && PortNum < pUsbSet->PortsNumber) {
          pUsbSet->PortsData[PortNum] = Value->u8;
          Status = gRT->SetVariable (
              USB_SETUP_VARIABLE_NAME,
              &gVendorGuid,
              (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | 
               EFI_VARIABLE_RUNTIME_ACCESS),
              sizeof(*pUsbSet) - 1 + 
                pUsbSet->PortsNumber * sizeof(pUsbSet->PortsData[1]),
              pUsbSet
              );
        }
      }
      if (gHistoryHandlerProtocol != NULL) {
        gHistoryHandlerProtocol->AddRecord(
          gHistoryHandlerProtocol,
          HEVENT_USB_PORT_CFG_CHANGE, 
          EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
          EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
      }
      break;
    } else {      
      bFormClose = TRUE;
    }
  }
  
  return EFI_SUCCESS;
}


EFI_STATUS
EFIAPI
ChipsetConfigCallback (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL   *This,
  IN  EFI_BROWSER_ACTION                     Action,
  IN  EFI_QUESTION_ID                        QuestionId,
  IN  UINT8                                  Type,
  IN  EFI_IFR_TYPE_VALUE                     *Value,
  OUT EFI_BROWSER_ACTION_REQUEST             *ActionRequest
  )
{
  DEBUG((EFI_D_INFO, "\n%a.%d Action=0x%X QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, Action, QuestionId));

  return CCMainModeCallback(
              This,
              Action,
              QuestionId,
              Type,
              Value,
              ActionRequest);
}

EFI_STATUS
InitializeChipsetConfig (
  VOID
  )
{
  EFI_STATUS	Status;
  UINT16 Flags;

  Status = GetSetupFlags(&Flags);
  if (!EFI_ERROR(Status)) {
    if (Flags & SETUP_FLAG_DISABLE_SERIAL_CON) {
      SerialConsoleOff ();
    }
  }

  //
  // Set ChipsetConfig flags from INI file
  // Don't check a result - if error, the config stays empty
  if(IsNeedToConfigFirstTime() == TRUE) {
    CHAR8 Fname[255];
    AsciiSPrint(Fname, sizeof(Fname), "fv:%g", PcdGetPtr(PcdChipsetConfigFile));
    DEBUG((EFI_D_INFO, "PcdChipsetConfigFile: %a \n", Fname));
    SetChipsetConfigFromINIFile(Fname);
  }

  CurrentConfig = &gMultibootData->Config;

  //
  // Install Device Path Protocol and Config Access protocol to driver handle
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &gChipsetConfigPrivate.DriverHandle,
                  &gEfiDevicePathProtocolGuid,
                  &mChipsetConfigHiiVendorDevicePath,
                  &gEfiHiiConfigAccessProtocolGuid,
                  &gChipsetConfigPrivate.ConfigAccess,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  Status = gBS->LocateProtocol (&gHistoryHandlerProtocolGuid, NULL, 
    (VOID **) &gHistoryHandlerProtocol);
  if (EFI_ERROR (Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
  }

  //
  // Publish our HII data
  //
  gChipsetConfigPrivate.HiiHandle = HiiAddPackages (
                                    &mChipsetConfigGuid,
                                    gChipsetConfigPrivate.DriverHandle,
                                    ChipsetConfigVfrBin,
                                    ChipsetConfigLibStrings,
                                    NULL
                                    );
  if (gChipsetConfigPrivate.HiiHandle == NULL) {
    return EFI_OUT_OF_RESOURCES;
  } else {
    return EFI_SUCCESS;
  }
}

STATIC 
EFI_STATUS
UsbLegacySupportOneOfString(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId
  )
{
  VOID *OptionsOpCodeHandle = NULL, *Opt1, *Opt2;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID Str16_1, Str16_2;
  UINT16 Flags;
  UINT8 Mode;
  
  DEBUG((EFI_D_INFO, "%a.%d QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, QuestionId));

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  if (Flags & SETUP_FLAG_USB_LEGACY_ENABLE) {
    Mode = USB_LEGACY_SUPPORT_ENABLE;
  } else {
    Mode = USB_LEGACY_SUPPORT_DISABLE;
  }

  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (OptionsOpCodeHandle == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  ZeroMem(UsbLegacyOpt, sizeof(UsbLegacyOpt));
  if (Mode == USB_LEGACY_SUPPORT_DISABLE) {
    UsbLegacyOpt[USB_LEGACY_SUPPORT_ENABLE] = 1;
    Str16_1 = STRING_TOKEN (STR_USB_LEGACY_SUPPORT_DISABLE);
    Str16_2 = STRING_TOKEN (STR_USB_LEGACY_SUPPORT_ENABLE);
  } else {
    UsbLegacyOpt[USB_LEGACY_SUPPORT_DISABLE] = 1;
    Str16_1 = STRING_TOKEN (STR_USB_LEGACY_SUPPORT_ENABLE);
    Str16_2 = STRING_TOKEN (STR_USB_LEGACY_SUPPORT_DISABLE);
  }

  Opt1 = HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    Str16_1, 0, EFI_IFR_NUMERIC_SIZE_1, 0);
  Opt2 = HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    Str16_2, 0, EFI_IFR_NUMERIC_SIZE_1, 1);

  if (NULL == Opt1 || NULL == Opt2) {
    goto _exit;
  }

  Status = HiiCreateOneOfOpCode (
      StartOpCodeHandle, QuestionId, 0, 0,
      Caption, STRING_TOKEN (STR_USB_LEGACY_SUPPORT_HELP),
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

STATIC 
EFI_STATUS
PxeOpromOneOfString(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId
  )
{
  VOID *OptionsOpCodeHandle = NULL, *Opt1, *Opt2;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID Str16_1, Str16_2;
  UINT16 Flags;
  UINT8 Mode;
  EFI_STRING_ID HelpToken;
  CHAR16 HelpStr[255];
  
  DEBUG((EFI_D_INFO, "%a.%d QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, QuestionId));

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  if (Flags & SETUP_FLAG_LAUNCH_PXE_OPROM) {
    Mode = PXE_OPROM_ENABLE;
  } else {
    Mode = PXE_OPROM_DISABLE;
  }

  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (OptionsOpCodeHandle == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  ZeroMem(PxeOpromOpt, sizeof(PxeOpromOpt));
  if (Mode == PXE_OPROM_DISABLE) {
    PxeOpromOpt[PXE_OPROM_ENABLE] = 1;
    Str16_1 = STRING_TOKEN (STR_PXE_OPROM_SWITCH_DISABLE);
    Str16_2 = STRING_TOKEN (STR_PXE_OPROM_SWITCH_ENABLE);
  } else {
    PxeOpromOpt[PXE_OPROM_DISABLE] = 1;
    Str16_1 = STRING_TOKEN (STR_PXE_OPROM_SWITCH_ENABLE);
    Str16_2 = STRING_TOKEN (STR_PXE_OPROM_SWITCH_DISABLE);
  }

  Opt1 = HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    Str16_1, 0, EFI_IFR_NUMERIC_SIZE_1, 0);
  Opt2 = HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    Str16_2, 0, EFI_IFR_NUMERIC_SIZE_1, 1);

  if (NULL == Opt1 || NULL == Opt2) {
    goto _exit;
  }

  UnicodeSPrint(HelpStr, sizeof (HelpStr), L"%s\n\n%s",
    HiiGetString(HiiHandle, STRING_TOKEN (STR_PXE_OPROM_SWITCH_HELP),NULL),
    HiiGetString(HiiHandle, STRING_TOKEN (STR_REBOOT_REQUIRE),NULL)
    );
  HelpToken = HiiSetString(HiiHandle, 0, HelpStr, NULL);

  Status = HiiCreateOneOfOpCode (
      StartOpCodeHandle, QuestionId, 0, 0,
      Caption, 
      HelpToken,
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

STATIC 
EFI_STATUS
UsbPortsStrings (
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_QUESTION_ID QuestionId
  )
{  
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID Token, HelpToken;
  CHAR16 Str[50], *UsbStr;
  USB_SETUP *pUsb;
  UINT32 Idx;
  EFI_STRING_ID Caption;
  CHAR16 HelpStr[255];

  DEBUG((EFI_D_INFO, "%a.%d QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, QuestionId));

  Caption = STRING_TOKEN (STR_USB_PORTS_SETTINGS);

  Status = ObtainUsbSetupEfiVar(&pUsb);
  if (EFI_ERROR(Status) || pUsb == NULL) {
    return EFI_NOT_FOUND;
  }
  
  HiiCreateSubTitleOpCode(
    StartOpCodeHandle,
    Caption,
    0,
    0,
    0);
  
  UsbStr = HiiGetString(HiiHandle, STRING_TOKEN (STR_USB_PORT), NULL);
  UnicodeSPrint(HelpStr, sizeof (HelpStr), L"%s\n\n%s",
      HiiGetString(HiiHandle, STRING_TOKEN (STR_USB_PORT_CFG_HELP),NULL),
      HiiGetString(HiiHandle, STRING_TOKEN (STR_REBOOT_REQUIRE),NULL)
      );
  HelpToken = HiiSetString(HiiHandle, 0, HelpStr, NULL);

  for (Idx = 0; Idx < pUsb->PortsNumber; Idx++) {
    UnicodeSPrint(Str, sizeof (Str), L"%s #%02d", UsbStr, Idx);
    Token = HiiSetString(HiiHandle, 0, Str, NULL);
    if (NULL == HiiCreateCheckBoxOpCode (
        StartOpCodeHandle, 
        QuestionId++,
        0, 0,
        Token,
        HelpToken, 
        EFI_IFR_FLAG_CALLBACK, //EFI_IFR_FLAG_READ_ONLY, 
        pUsb->PortsData[Idx] & 1 ? EFI_IFR_CHECKBOX_DEFAULT : 0, 
        NULL)) {
      return EFI_OUT_OF_RESOURCES;
    }
  }

  return EFI_SUCCESS;
}

STATIC 
EFI_STATUS
Ps2PortsStrings (
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId
  )
{  
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID Token, HelpToken;
  UINT16 Flags;
  CHAR16 HelpStr[255];

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  DEBUG((EFI_D_INFO, "%a.%d QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, QuestionId));
  
  
  Token = STRING_TOKEN (STR_PS2_PORT);
  
  UnicodeSPrint(HelpStr, sizeof (HelpStr), L"%s\n\n%s",
      HiiGetString(HiiHandle, STRING_TOKEN (STR_PS2_PORT_CFG_HELP),NULL),
      HiiGetString(HiiHandle, STRING_TOKEN (STR_REBOOT_REQUIRE),NULL)
      );
  HelpToken = HiiSetString(HiiHandle, 0, HelpStr, NULL);

  if (NULL == HiiCreateCheckBoxOpCode (
      StartOpCodeHandle, 
      QuestionId++,
      0, 0,
      Token,
      HelpToken, 
      EFI_IFR_FLAG_CALLBACK, //EFI_IFR_FLAG_READ_ONLY, 
      Flags & SETUP_FLAG_PS2_EN ? EFI_IFR_CHECKBOX_DEFAULT : 0, 
      NULL)) {
    return EFI_OUT_OF_RESOURCES;
  }
  return EFI_SUCCESS;
}

STATIC 
EFI_STATUS
AmtKbcStr (
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId
  )
{  
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID Token, HelpToken;
  UINT16 Flags;

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  DEBUG((EFI_D_INFO, "%a.%d QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, QuestionId));
  
  
  Token = STRING_TOKEN (STR_AMT_KBC_LOCK);
  HelpToken = STRING_TOKEN (STR_AMT_KBC_LOCK_HELP);

  if (NULL == HiiCreateCheckBoxOpCode (
      StartOpCodeHandle, 
      QuestionId++,
      0, 0,
      Token,
      HelpToken, 
      EFI_IFR_FLAG_CALLBACK, //EFI_IFR_FLAG_READ_ONLY, 
      Flags & SETUP_FLAG_AMT_KBC_LOCK ? EFI_IFR_CHECKBOX_DEFAULT : 0, 
      NULL)) {
    return EFI_OUT_OF_RESOURCES;
  }
  return EFI_SUCCESS;
}


STATIC 
EFI_STATUS
DisableSerialConsoleStr (
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId
  )
{  
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID Token, HelpToken;
  UINT16 Flags;
  CHAR16 HelpStr[255];

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  DEBUG((EFI_D_INFO, "%a.%d QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, QuestionId));
  
  
  Token = STRING_TOKEN (STR_DISABLE_SERIAL_CON);

  UnicodeSPrint(HelpStr, sizeof (HelpStr), L"%s\n\n%s",
    HiiGetString(HiiHandle, STRING_TOKEN (STR_DISABLE_SERIAL_CON_HELP),NULL),
    HiiGetString(HiiHandle, STRING_TOKEN (STR_REBOOT_REQUIRE),NULL)
    );
  HelpToken = HiiSetString(HiiHandle, 0, HelpStr, NULL);

  if (NULL == HiiCreateCheckBoxOpCode (
      StartOpCodeHandle, 
      QuestionId++,
      0, 0,
      Token,
      HelpToken, 
      EFI_IFR_FLAG_CALLBACK, //EFI_IFR_FLAG_READ_ONLY, 
      Flags & SETUP_FLAG_DISABLE_SERIAL_CON ? EFI_IFR_CHECKBOX_DEFAULT : 0, 
      NULL)) {
    return EFI_OUT_OF_RESOURCES;
  }
  return EFI_SUCCESS;
}

STATIC 
EFI_STATUS
EnableUSB30Str (
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId
  )
{  
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID HelpToken;
  UINT16 Mode;
  CHAR16 HelpStr[255];
  USB30_CONTROLLER_SETTINGS *pUsb30Settings;

  Status = ObtainUsb30Settings(&pUsb30Settings);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  Mode = pUsb30Settings->Mode;
  FreePool (pUsb30Settings);

  DEBUG((EFI_D_INFO, "%a.%d QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, QuestionId));
  
  
  UnicodeSPrint(HelpStr, sizeof (HelpStr), L"%s\n\n%s",
    HiiGetString(HiiHandle, STRING_TOKEN (STR_USB30_MODE_ENABLE_HELP),NULL),
    HiiGetString(HiiHandle, STRING_TOKEN (STR_REBOOT_REQUIRE),NULL)
    );
  HelpToken = HiiSetString(HiiHandle, 0, HelpStr, NULL);

  if (NULL == HiiCreateCheckBoxOpCode (
      StartOpCodeHandle, 
      QuestionId++,
      0, 0,
      Caption,
      HelpToken, 
      EFI_IFR_FLAG_CALLBACK, //EFI_IFR_FLAG_READ_ONLY, 
      Mode ? EFI_IFR_CHECKBOX_DEFAULT : 0, 
      NULL)) {
    return EFI_OUT_OF_RESOURCES;
  }
  return EFI_SUCCESS;
}

STATIC 
EFI_STATUS
SataModeOneOfString(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId
  )
{
  VOID *OptionsOpCodeHandle = NULL, *Opt1, *Opt2;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID Str16_1, Str16_2;
  UINT16 Flags;
  UINT8 Mode;
  EFI_STRING_ID HelpToken;
  CHAR16 HelpStr[255];
  
  DEBUG((EFI_D_INFO, "%a.%d QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, QuestionId));

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  if (Flags & SETUP_FLAG_SATA_MODE) {
    Mode = SATA_MODE_IDE;
  } else {
    Mode = SATA_MODE_AHCI;
  }

  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (OptionsOpCodeHandle == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  ZeroMem(SataModeOpt, sizeof(SataModeOpt));
  if (Mode == SATA_MODE_AHCI) {
    SataModeOpt[SATA_MODE_IDE] = 1;
    Str16_1 = STRING_TOKEN (STR_SATA_MODE_AHCI);
    Str16_2 = STRING_TOKEN (STR_SATA_MODE_IDE);
  } else {
    SataModeOpt[SATA_MODE_AHCI] = 1;
    Str16_1 = STRING_TOKEN (STR_SATA_MODE_IDE);
    Str16_2 = STRING_TOKEN (STR_SATA_MODE_AHCI);
  }

  Opt1 = HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    Str16_1, 0, EFI_IFR_NUMERIC_SIZE_1, 0);
  Opt2 = HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    Str16_2, 0, EFI_IFR_NUMERIC_SIZE_1, 1);

  if (NULL == Opt1 || NULL == Opt2) {
    goto _exit;
  }

  UnicodeSPrint(HelpStr, sizeof (HelpStr), L"%s\n\n%s",
    HiiGetString(HiiHandle, STRING_TOKEN (STR_SATA_MODE_HELP),NULL),
    HiiGetString(HiiHandle, STRING_TOKEN (STR_REBOOT_REQUIRE),NULL)
    );
  HelpToken = HiiSetString(HiiHandle, 0, HelpStr, NULL);

  Status = HiiCreateOneOfOpCode (
      StartOpCodeHandle, QuestionId, 0, 0,
      Caption, HelpToken,
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

STATIC 
EFI_STATUS
SataAhciSlowOneOfString(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId
  )
{
  VOID *OptionsOpCodeHandle = NULL, *Opt1, *Opt2;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID Str16_1, Str16_2;
  UINT16 Flags;
  UINT8 Mode;
  EFI_STRING_ID HelpToken;
  CHAR16 HelpStr[255];

  DEBUG((EFI_D_INFO, "%a.%d QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, QuestionId));

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  if ((Flags & SETUP_FLAG_SATA_MODE)) {
    return EFI_SUCCESS;
  }

  if (Flags & SETUP_FLAG_SATA_AHCI_SLOW) {
    Mode = SATA_AHCI_SLOW_ENABLE;
  } else {
    Mode = SATA_AHCI_SLOW_DISABLE;
  }

  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (OptionsOpCodeHandle == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem(SataAhciSlowOpt, sizeof(SataAhciSlowOpt));
  if (Mode == SATA_AHCI_SLOW_DISABLE) {
    SataAhciSlowOpt[SATA_AHCI_SLOW_ENABLE] = 1;
    Str16_1 = STRING_TOKEN (STR_SATA_AHCI_SLOW_DISABLE);
    Str16_2 = STRING_TOKEN (STR_SATA_AHCI_SLOW_ENABLE);
  } else {
    SataAhciSlowOpt[SATA_AHCI_SLOW_DISABLE] = 1;
    Str16_1 = STRING_TOKEN (STR_SATA_AHCI_SLOW_ENABLE);
    Str16_2 = STRING_TOKEN (STR_SATA_AHCI_SLOW_DISABLE);
  }

  Opt1 = HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    Str16_1, 0, EFI_IFR_NUMERIC_SIZE_1, 0);
  Opt2 = HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    Str16_2, 0, EFI_IFR_NUMERIC_SIZE_1, 1);

  if (NULL == Opt1 || NULL == Opt2) {
    goto _exit;
  }

  UnicodeSPrint(HelpStr, sizeof (HelpStr), L"%s\n\n%s",
    HiiGetString(HiiHandle, STRING_TOKEN (STR_SATA_AHCI_SLOW_HELP),NULL),
    HiiGetString(HiiHandle, STRING_TOKEN (STR_REBOOT_REQUIRE),NULL)
    );
  HelpToken = HiiSetString(HiiHandle, 0, HelpStr, NULL);

  Status = HiiCreateOneOfOpCode (
    StartOpCodeHandle, QuestionId, 0, 0,
    Caption, 
    HelpToken,
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

STATIC 
EFI_STATUS
SerialConsoleTypeOneOfString(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId
  )
{
  VOID *OptionsOpCodeHandle = NULL, *Opt1, *Opt2, *Opt3, *Opt4;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID Str16_1, Str16_2, Str16_3, Str16_4;
  UINT8 Mode;
  
  DEBUG((EFI_D_INFO, "%a.%d QuestionId=0x%X\n", 
    __FUNCTION__, __LINE__, QuestionId));

  Status = GetCurrentConsoleType (&Mode);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_INFO, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
    Status = ResetCurrentConsoleType (&Mode);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
      return Status;
    }
  }

  OptionsOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (OptionsOpCodeHandle == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  ZeroMem(SerialTypeOpt, sizeof(SerialTypeOpt));
  if (Mode == SERIAL_PC_ANSI) {
    SerialTypeOpt[SERIAL_PC_ANSI] = 0;
    SerialTypeOpt[SERIAL_VT100] = 1;
    SerialTypeOpt[SERIAL_VT100_PLUS] = 2;
    SerialTypeOpt[SERIAL_UTF8] = 3;
    Str16_1 = STRING_TOKEN (STR_SERIAL_CONSOLE_PC_ANSI);
    Str16_2 = STRING_TOKEN (STR_SERIAL_CONSOLE_VT100);
    Str16_3 = STRING_TOKEN (STR_SERIAL_CONSOLE_VT100_PLUS);
    Str16_4 = STRING_TOKEN (STR_SERIAL_CONSOLE_UTF8);
  } else if (Mode == SERIAL_VT100) {
    SerialTypeOpt[SERIAL_PC_ANSI] = 3;
    SerialTypeOpt[SERIAL_VT100] = 0;
    SerialTypeOpt[SERIAL_VT100_PLUS] = 1;
    SerialTypeOpt[SERIAL_UTF8] = 2;
    Str16_4 = STRING_TOKEN (STR_SERIAL_CONSOLE_PC_ANSI);
    Str16_1 = STRING_TOKEN (STR_SERIAL_CONSOLE_VT100);
    Str16_2 = STRING_TOKEN (STR_SERIAL_CONSOLE_VT100_PLUS);
    Str16_3 = STRING_TOKEN (STR_SERIAL_CONSOLE_UTF8);
  } else if (Mode == SERIAL_VT100_PLUS) {
    SerialTypeOpt[SERIAL_PC_ANSI] = 2;
    SerialTypeOpt[SERIAL_VT100] = 3;
    SerialTypeOpt[SERIAL_VT100_PLUS] = 0;
    SerialTypeOpt[SERIAL_UTF8] = 1;
    Str16_3 = STRING_TOKEN (STR_SERIAL_CONSOLE_PC_ANSI);
    Str16_4 = STRING_TOKEN (STR_SERIAL_CONSOLE_VT100);
    Str16_1 = STRING_TOKEN (STR_SERIAL_CONSOLE_VT100_PLUS);
    Str16_2 = STRING_TOKEN (STR_SERIAL_CONSOLE_UTF8);
  } else if (Mode == SERIAL_UTF8) {
    SerialTypeOpt[SERIAL_PC_ANSI] = 1;
    SerialTypeOpt[SERIAL_VT100] = 2;
    SerialTypeOpt[SERIAL_VT100_PLUS] = 3;
    SerialTypeOpt[SERIAL_UTF8] = 0;
    Str16_2 = STRING_TOKEN (STR_SERIAL_CONSOLE_PC_ANSI);
    Str16_3 = STRING_TOKEN (STR_SERIAL_CONSOLE_VT100);
    Str16_4 = STRING_TOKEN (STR_SERIAL_CONSOLE_VT100_PLUS);
    Str16_1 = STRING_TOKEN (STR_SERIAL_CONSOLE_UTF8);
  } else {
    Status = EFI_INVALID_PARAMETER;
    goto _exit;
  }

  Opt1 = HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    Str16_1, 0, EFI_IFR_NUMERIC_SIZE_1, 0);
  Opt2 = HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    Str16_2, 0, EFI_IFR_NUMERIC_SIZE_1, 1);
  Opt3 = HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    Str16_3, 0, EFI_IFR_NUMERIC_SIZE_1, 2);
  Opt4 = HiiCreateOneOfOptionOpCode (OptionsOpCodeHandle,
    Str16_4, 0, EFI_IFR_NUMERIC_SIZE_1, 3);

  if (NULL == Opt1 || NULL == Opt2 || NULL == Opt3 || NULL == Opt4) {
    goto _exit;
  }

  Status = HiiCreateOneOfOpCode (
      StartOpCodeHandle, QuestionId, 0, 0,
      Caption, STRING_TOKEN (STR_SERIAL_CONSOLE_TYPE_HELP),
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
CreateChipsetConfigMainMenu(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle
  )
{
  LIST_ENTRY *ListEntry;
  MULTIBOOT_FORM *CurrentForm;
  MULTIBOOT_ENTRY *Entry;
  EFI_STRING_ID Token, HelpToken;
  EFI_QUESTION_ID QuestionId;
  EFI_FORM_ID FormId = CHIPSET_CONFIG_FORM_ID;
  EFI_STATUS Status;


  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

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

    if (Entry->Index == USB_LEGACY_SUPPORT_ID) {
      DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));      
      Status = UsbLegacySupportOneOfString(HiiHandle, StartOpCodeHandle,
        Token, QuestionId);
      if (EFI_ERROR(Status)) {
        return Status;
      }

    } else if (Entry->Index == PXE_OPROM_SWITCH_ID) {
      DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      Status = PxeOpromOneOfString(HiiHandle, StartOpCodeHandle,
        Token, QuestionId);
      if (EFI_ERROR(Status)) {
        return Status;
      }
    } else if (Entry->Index == SATA_MODE_SELECT_ID) {
      DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      Status = SataModeOneOfString(HiiHandle, StartOpCodeHandle,
        Token, QuestionId);
      if (EFI_ERROR(Status)) {
        return Status;
      }
    } else if (Entry->Index == SATA_AHCI_SLOW_SELECT_ID) {
      DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      Status = SataAhciSlowOneOfString(HiiHandle, StartOpCodeHandle,
        Token, QuestionId);
      if (EFI_ERROR(Status)) {
        return Status;
      }
    } else if (Entry->Index == PS2_PORT_CFG_ID) {
      DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      Ps2PortsStrings(HiiHandle, StartOpCodeHandle,
        Token, QuestionId);
    } else if (Entry->Index == USB_PORTS_CFG_START_ID) {      
    
      USB_SETUP *pUsb = NULL;

      DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      Status = ObtainUsbSetupEfiVar(&pUsb);
      if (!EFI_ERROR(Status) && pUsb != NULL) {        
        Token = STRING_TOKEN (STR_USB_PORTS_SETTINGS_BTN);
        if (NULL == HiiCreateActionOpCode (
                      StartOpCodeHandle, 
                      QuestionId, 
                      Token,
                      HelpToken, 
                      EFI_IFR_FLAG_CALLBACK, 
                      0)) {
          DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
          return EFI_OUT_OF_RESOURCES;
        }
        if (pUsb == NULL) {
          FreePool (pUsb);
        }
      }
    } else if (Entry->Index == AMT_LOCK_KEYBORD_ID) {
      DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      AmtKbcStr (HiiHandle, StartOpCodeHandle,
        Token, QuestionId);
    } else if (Entry->Index == DISABLE_SERIAL_CONSOLE_ID) {
      DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      DisableSerialConsoleStr (HiiHandle, StartOpCodeHandle,
        Token, QuestionId);
    } else if (Entry->Index == SERIAL_CONSOLE_TYPE) {
      DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      Status = SerialConsoleTypeOneOfString(HiiHandle, StartOpCodeHandle,
        Token, QuestionId);
      if (EFI_ERROR(Status)) {
        return Status;
      }
    } else if (Entry->Index == USB30_MODE_ENABLE_ID) {
      EnableUSB30Str (HiiHandle, StartOpCodeHandle,
        Token, QuestionId);
    } else {

    }

    ListEntry  = ListEntry->ForwardLink;
  }

  return EFI_SUCCESS;
}

/**
  This function invokes Chipset Config.
**/
VOID
CallChipsetConfig (
  VOID
  )
{
  EFI_STATUS                  Status;
  EFI_HII_HANDLE              HiiHandle;
  EFI_BROWSER_ACTION_REQUEST  ActionRequest;
  VOID                        *StartOpCodeHandle = NULL;
  VOID                        *EndOpCodeHandle = NULL;
  EFI_IFR_GUID_LABEL          *StartLabel;
  EFI_IFR_GUID_LABEL          *EndLabel;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
  gST->ConOut->ClearScreen(gST->ConOut);
  CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE, NULL, L"", 
    HiiGetString(
      gChipsetConfigPrivate.HiiHandle,
      STRING_TOKEN(STR_WAIT_FOR_CC_START), NULL
      ), 
    L"", L"", NULL);

  for (gChipsetConfigMenuMode = CCFG_MAIN_MENU;;) {

    DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    HiiHandle = gChipsetConfigPrivate.HiiHandle;

    //
    // Allocate space for creation of UpdateData Buffer
    //
    StartOpCodeHandle = HiiAllocateOpCodeHandle ();
    ASSERT (StartOpCodeHandle != NULL);

    EndOpCodeHandle = HiiAllocateOpCodeHandle ();
    ASSERT (EndOpCodeHandle != NULL);

    //
    // Create Hii Extend Label OpCode as the start opcode
    //
    StartLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
                                            StartOpCodeHandle, 
                                            &gEfiIfrTianoGuid, 
                                            NULL, 
                                            sizeof (EFI_IFR_GUID_LABEL));
    StartLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
    StartLabel->Number       = /*LABEL_BOOT_OPTION*/ LABEL_SETUP_OPTION;

    //
    // Create Hii Extend Label OpCode as the end opcode
    //
    EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
                                            EndOpCodeHandle, 
                                            &gEfiIfrTianoGuid, 
                                            NULL, 
                                            sizeof (EFI_IFR_GUID_LABEL));
    EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
    EndLabel->Number       = /*LABEL_BOOT_OPTION_END*/ LABEL_SETUP_OPTION_END;

    if (gChipsetConfigMenuMode == CCFG_USB_SETTINGS) {
      Status = UsbPortsStrings (
                  HiiHandle,
                  StartOpCodeHandle,
                  (EFI_QUESTION_ID)(USB_PORTS_CFG_START_ID + 1)
                  );
    } else {
      Status = CreateChipsetConfigMainMenu(HiiHandle, StartOpCodeHandle);
      if (EFI_ERROR(Status)) {
        return;
      }
    }

    HiiUpdateForm (
      HiiHandle,
      &mChipsetConfigGuid,
      CHIPSET_CONFIG_FORM_ID,
      StartOpCodeHandle,
      EndOpCodeHandle
      );

    gStringPackHandle = HiiHandle;

    DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    
    if (StartOpCodeHandle != NULL) {
      HiiFreeOpCodeHandle (StartOpCodeHandle);
      StartOpCodeHandle = NULL;
    }
    DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    if (EndOpCodeHandle != NULL) {
      HiiFreeOpCodeHandle (EndOpCodeHandle);
      EndOpCodeHandle = NULL;
    }

    DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

    Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
      (VOID **) &gFormBrowser2);
    if (EFI_ERROR (Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return;
    }

    ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
    Status = gFormBrowser2->SendForm (
                             gFormBrowser2,
                             &HiiHandle,
                             1,
                             &mChipsetConfigGuid,
                             CHIPSET_CONFIG_FORM_ID,
                             NULL,
                             &ActionRequest
                             );

    DEBUG((EFI_D_INFO, "%a.%d Status=%X\n", 
      __FUNCTION__, __LINE__, Status));

    if (gChipsetConfigMenuMode == CCFG_MAIN_MENU) {
      break;
    } if (gChipsetConfigMenuMode == CCFG_BACK_TO_MAIN_MENU) {
      gChipsetConfigMenuMode = CCFG_MAIN_MENU;
    }
  }
  if (ActionRequest == EFI_BROWSER_ACTION_REQUEST_RESET) {
    EnableResetRequired ();
  }
}

