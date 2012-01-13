/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Protocol/GlobalConfigDxe.h>
#include <Protocol/IniParserDxe.h>

#include "ChipsetConfig.h"

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

static CHAR8 chipsetConfigSectionName[] = "ChipsetConfig";

static CHAR8 usbLegasyKey[]       = "USB Legasy Support";
static CHAR8 sataModeKey[]        = "SATA Mode";
static CHAR8 sataAhciSlowKey[]    = "SATA AHCI Slow";
static CHAR8 pxeOpromKey[]        = "Pxe OpRom";
static CHAR8 Ps2CfgKey[]          = "PS/2 ports enabled";
static CHAR8 AmtKeyboardLockKey[] = "AMT keyboard lock enabled";
static CHAR8 UsbPortsNumCfgKey[]  = "USB ports num";
static CHAR8 UsbPortNCfgKey[]     = "USB port %d";




//------------------------------------------------------------------------------
/*! \brief Read Usb Legasy support flag and set */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
static
EFI_STATUS
SetUsbLegasySupportFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status;
  UINT16 Flags = 0;
  BOOLEAN isUsbLegasyOn = FALSE;

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return EFI_LOAD_ERROR;
  }

  Status = iniParserProtocol->GetBoolean(dict, chipsetConfigSectionName, usbLegasyKey, &isUsbLegasyOn);
  if (!EFI_ERROR(Status)) {
    if (FALSE == isUsbLegasyOn) {
      LOG((EFI_D_ERROR, "%a.%d Disable\n", __FUNCTION__, __LINE__));
      Status = SetSetupFlag(FALSE, SETUP_FLAG_USB_LEGACY_ENABLE);
    } else {
      LOG((EFI_D_ERROR, "%a.%d Enable\n", __FUNCTION__, __LINE__));
      Status = SetSetupFlag(TRUE, SETUP_FLAG_USB_LEGACY_ENABLE);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read Pxe oprom support flag and set */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
static
EFI_STATUS
SetPxeOpromFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status;
  UINT16 Flags = 0;
  BOOLEAN isPxeOpromOn = FALSE;

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return EFI_LOAD_ERROR;
  }

  Status = iniParserProtocol->GetBoolean(dict, chipsetConfigSectionName, pxeOpromKey, &isPxeOpromOn);
  if (!EFI_ERROR(Status)) {
    if (FALSE == isPxeOpromOn) {
      DEBUG((EFI_D_ERROR, "%a.%d Disable\n", __FUNCTION__, __LINE__));
      Status = SetSetupFlag(FALSE, SETUP_FLAG_LAUNCH_PXE_OPROM);
    } else {
      DEBUG((EFI_D_ERROR, "%a.%d Enable\n", __FUNCTION__, __LINE__));
      Status = SetSetupFlag(TRUE, SETUP_FLAG_LAUNCH_PXE_OPROM);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read SATA mode and set */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
static
EFI_STATUS
SetSataModeFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status;
  UINT16 Flags = 0;
  UINT32 sataMode = 0;

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return EFI_LOAD_ERROR;
  }

  Status = iniParserProtocol->GetInteger(dict, chipsetConfigSectionName, sataModeKey, &sataMode);
  if (!EFI_ERROR(Status)) {
    switch(sataMode) {
      case 0:
        LOG((EFI_D_ERROR, "%a.%d SATA\n", __FUNCTION__, __LINE__));
        Status = SetSetupFlag(TRUE, SETUP_FLAG_SATA_MODE);
        break;
      case 1:
        LOG((EFI_D_ERROR, "%a.%d IDE\n", __FUNCTION__, __LINE__));
        Status = SetSetupFlag(FALSE, SETUP_FLAG_SATA_MODE);
        break;
      default:
        LOG((EFI_D_ERROR, "%a.%d UNSUPPORTED\n", __FUNCTION__, __LINE__));
        Status = EFI_UNSUPPORTED;
        break;
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read SATA AHCI Slow flag and set */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
static
EFI_STATUS
SetSataAhciSlowFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status;
  UINT16 Flags = 0;
  BOOLEAN isSataAhciSlowOn = FALSE;

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return EFI_LOAD_ERROR;
  }

  Status = iniParserProtocol->GetBoolean(dict, chipsetConfigSectionName, sataAhciSlowKey, &isSataAhciSlowOn);
  if (!EFI_ERROR(Status)) {
    if (FALSE == isSataAhciSlowOn) {
      DEBUG((EFI_D_ERROR, "%a.%d Disable\n", __FUNCTION__, __LINE__));
      Status = SetSetupFlag(FALSE, SETUP_FLAG_SATA_AHCI_SLOW);
    } else {
      DEBUG((EFI_D_ERROR, "%a.%d Enable\n", __FUNCTION__, __LINE__));
      Status = SetSetupFlag(TRUE, SETUP_FLAG_SATA_AHCI_SLOW);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read PS/2 enabled flag and set */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
static
EFI_STATUS
SetPs2CfgFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status;
  UINT16 Flags = 0;
  UINT32 Ps2Cfg = 0;

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return EFI_LOAD_ERROR;
  }

  Status = iniParserProtocol->GetInteger(dict, chipsetConfigSectionName, Ps2CfgKey, &Ps2Cfg);
  if (!EFI_ERROR(Status)) {
    switch(Ps2Cfg) {
      case 0:
        LOG((EFI_D_ERROR, "%a.%d DISABLED\n", __FUNCTION__, __LINE__));
        Status = SetSetupFlag(FALSE, SETUP_FLAG_PS2_EN);
        break;
      case 1:
        LOG((EFI_D_ERROR, "%a.%d ENABLED\n", __FUNCTION__, __LINE__));
        Status = SetSetupFlag(TRUE, SETUP_FLAG_PS2_EN);
        break;
      default:
        LOG((EFI_D_ERROR, "%a.%d UNSUPPORTED\n", __FUNCTION__, __LINE__));
        Status = EFI_UNSUPPORTED;
        break;
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read lock keyboard if AMT enabled flag and set */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
static
EFI_STATUS
SetAmtKeyboardLockFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status;
  UINT16 Flags = 0;
  UINT32 AmtKeyboardLockCfg = 0;

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return EFI_LOAD_ERROR;
  }

  Status = iniParserProtocol->GetInteger(dict, chipsetConfigSectionName, AmtKeyboardLockKey, &AmtKeyboardLockCfg);
  if (!EFI_ERROR(Status)) {
    switch(AmtKeyboardLockCfg) {
      case 0:
        LOG((EFI_D_ERROR, "%a.%d DISABLED\n", __FUNCTION__, __LINE__));
        Status = SetSetupFlag(FALSE, SETUP_FLAG_AMT_KBC_LOCK);
        break;
      case 1:
        LOG((EFI_D_ERROR, "%a.%d ENABLED\n", __FUNCTION__, __LINE__));
        Status = SetSetupFlag(TRUE, SETUP_FLAG_AMT_KBC_LOCK);
        break;
      default:
        LOG((EFI_D_ERROR, "%a.%d UNSUPPORTED\n", __FUNCTION__, __LINE__));
        Status = EFI_UNSUPPORTED;
        break;
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read USB ports settings and set */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
static
EFI_STATUS
SetUsbPortsCfgFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status;
  USB_SETUP* UsbFlags = NULL;
  UINT32 UsbPortsNumCfg = 0;
  UINT32 UsbPortsNCfg = 0;
  CHAR8* UsbPortNKey = NULL;
  UINTN UsbPortNKeyMaxLen = 0, i;

  UsbPortNKeyMaxLen = AsciiStrLen(UsbPortNCfgKey) + MAXIMUM_VALUE_CHARACTERS;
  UsbPortNKey = AllocatePool(UsbPortNKeyMaxLen);
  if (UsbPortNKey == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto _exit;
  }

  Status = ObtainUsbSetupEfiVar(&UsbFlags);
  if (Status == EFI_NOT_FOUND) {
    //var not found -> no USB ports -> nothing to set -> just exit
    Status = EFI_SUCCESS;
    goto _exit;
  } else if (EFI_ERROR(Status)) {
    Status = EFI_LOAD_ERROR;
    goto _exit;
  }

  Status = iniParserProtocol->GetInteger(dict, chipsetConfigSectionName, UsbPortsNumCfgKey, &UsbPortsNumCfg);
  if (!EFI_ERROR(Status)) {
    for (i = 0; i < UsbPortsNumCfg && i < UsbFlags->PortsNumber; i++) {
      AsciiSPrint(UsbPortNKey, UsbPortNKeyMaxLen, UsbPortNCfgKey, i);
      Status = iniParserProtocol->GetInteger(dict, chipsetConfigSectionName, UsbPortNKey, &UsbPortsNCfg);
      if (EFI_ERROR(Status)) {
        break;
      } else {
        if ((UsbPortsNCfg & 1) == 1) {
          UsbFlags->PortsData[i] |= 1;
          LOG((EFI_D_ERROR, "%a.%d %d ENABLED\n", __FUNCTION__, __LINE__, i));
        } else {
          UsbFlags->PortsData[i] &= ~((UINT8)1);
          LOG((EFI_D_ERROR, "%a.%d %d DISABLED\n", __FUNCTION__, __LINE__, i));
        }
      }
    }
    if (!EFI_ERROR(Status)) {
      Status = gRT->SetVariable (USB_SETUP_VARIABLE_NAME, &gVendorGuid,
                                 EFI_VARIABLE_NON_VOLATILE |
                                 EFI_VARIABLE_BOOTSERVICE_ACCESS |
                                 EFI_VARIABLE_RUNTIME_ACCESS,
                                 sizeof(UsbFlags->PortsNumber) + sizeof(UsbFlags->PortsData[0])*(UsbFlags->PortsNumber==0?1:UsbFlags->PortsNumber) , 
                                 UsbFlags);
    }
  } else {
    Status = EFI_NOT_FOUND;
  }

_exit:
  if (UsbPortNKey != NULL)
    FreePool(UsbPortNKey);

  LOG((EFI_D_ERROR, "%a.%d Status = 0x%X\n",  __FUNCTION__, __LINE__, Status));
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read config from dictionary and set */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
static
CONFIG_ERROR_T
SetChipsetConfigFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status;

  status = SetUsbLegasySupportFromDictionary(iniParserProtocol, dict);
  switch(status) {
  case EFI_ALREADY_STARTED:
  case EFI_SUCCESS:
  case EFI_NOT_FOUND:
    break;

  default:
    return ERROR_OUT_OF_MEMORY;
  }

  status = SetPxeOpromFromDictionary(iniParserProtocol, dict);
  switch(status) {
  case EFI_ALREADY_STARTED:
  case EFI_SUCCESS:
  case EFI_NOT_FOUND:
    break;

  default:
    return ERROR_OUT_OF_MEMORY;
  }

  status = SetSataModeFromDictionary(iniParserProtocol, dict);
  switch(status) {
  case EFI_ALREADY_STARTED:
  case EFI_SUCCESS:
  case EFI_NOT_FOUND:
    break;

  default:
    return ERROR_OUT_OF_MEMORY;
  }

  status = SetSataAhciSlowFromDictionary(iniParserProtocol, dict);
  switch(status) {
  case EFI_ALREADY_STARTED:
  case EFI_SUCCESS:
  case EFI_NOT_FOUND:
    break;

  default:
    return ERROR_OUT_OF_MEMORY;
  }

  status = SetPs2CfgFromDictionary(iniParserProtocol, dict);
  switch(status) {
  case EFI_ALREADY_STARTED:
  case EFI_SUCCESS:
  case EFI_NOT_FOUND:
    break;

  default:
    return ERROR_OUT_OF_MEMORY;
  }

  status = SetAmtKeyboardLockFromDictionary(iniParserProtocol, dict);
  switch(status) {
  case EFI_ALREADY_STARTED:
  case EFI_SUCCESS:
  case EFI_NOT_FOUND:
    break;

  default:
    return ERROR_OUT_OF_MEMORY;
  }

  status = SetUsbPortsCfgFromDictionary(iniParserProtocol, dict);
  switch(status) {
  case EFI_ALREADY_STARTED:
  case EFI_SUCCESS:
  case EFI_NOT_FOUND:
    break;

  default:
    return ERROR_OUT_OF_MEMORY;
  }

  // Configure is successful. Has to prevent reconfigure next time
  status = SetSetupFlag(TRUE, SETUP_FLAG_CHIPSET_STATUS);
  switch(status) {
  case EFI_ALREADY_STARTED:
  case EFI_SUCCESS:
  case EFI_NOT_FOUND:
    break;
  
  default:
    return ERROR_OUT_OF_MEMORY;
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief ChipsetConfig config with INI dictionary */
/*! Register this function as a callback config method in the GlobalConfigDxe */
/*! \param[in] *dict A pointer to the INI dictionary */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
static
CONFIG_ERROR_T
SetConfigFromDictionary (
  IN dictionary *dict
)
{
  CONFIG_ERROR_T status;
  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;

  if (dict == NULL) {
    return ERROR_INVALID_PARAMETER;
  }

  if (gBS->LocateProtocol (
             &gIniParserDxeProtocolGuid,
             NULL,
             (VOID **) &iniParserProtocol
             ) != EFI_SUCCESS) {
    return CANT_LOCATE_INI_PARSER_PROTOCOL;
  }

  if (!iniParserProtocol->CheckSecPresent(dict, chipsetConfigSectionName)) {
    return NO_CONFIG_SECTION;
  }

  status = SetChipsetConfigFromDictionary(iniParserProtocol, dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief ChipsetConfig config with config INI file */
/*! Read ChipsetConfig config from INI file and save to the variable. Use this function
    to config ChipsetConfig directly without using GlobalConfigDxe */
/*! \param[in] *filePath Path to the config file */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetChipsetConfigFromINIFile (
  CHAR8 *filePath
)
{
  CONFIG_ERROR_T status;
  dictionary *dict;
  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;

  status = gBS->LocateProtocol (
             &gIniParserDxeProtocolGuid,
             NULL,
             (VOID **) &iniParserProtocol
             );
  if (EFI_ERROR(status)) {
    return CANT_LOCATE_INI_PARSER_PROTOCOL;
  }

  dict = iniParserProtocol->NewIniDictionary(filePath);
  if (dict == NULL) {
    return ERROR_OUT_OF_MEMORY;
  }

  status = SetChipsetConfigFromDictionary(iniParserProtocol, dict);

  iniParserProtocol->DeleteIniDictionary(dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check if config has been configured at least one time */
/*! \return TRUE if ChipsetConfig hasn't never been configured from INI file, 
            FALSE otherwise */
//------------------------------------------------------------------------------
BOOLEAN
IsNeedToConfigFirstTime (
  VOID
)
{
  CHAR16 Flags = 0;
  EFI_STATUS Status;

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return TRUE;
  }

  if (Flags & SETUP_FLAG_CHIPSET_STATUS) {
    return FALSE;
  } else {
    return TRUE;
  }
}
//------------------------------------------------------------------------------



//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveUsbLegacySupportToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  UINT16 Flags = 0;
  BOOLEAN isUsbLegasyOn = FALSE;

  EFI_STATUS Status = EFI_ABORTED;

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return EFI_LOAD_ERROR;
  }

  if ((Flags & SETUP_FLAG_USB_LEGACY_ENABLE) == SETUP_FLAG_USB_LEGACY_ENABLE)
    isUsbLegasyOn = TRUE;
  else
    isUsbLegasyOn = FALSE;

  Status = iniParserProtocol->SetBoolean(dict, chipsetConfigSectionName,
                                usbLegasyKey, isUsbLegasyOn);
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SavePxeOpromToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  UINT16 Flags = 0;
  BOOLEAN isPxeOpromOn = FALSE;

  EFI_STATUS Status = EFI_ABORTED;

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return EFI_LOAD_ERROR;
  }

  if ((Flags & SETUP_FLAG_LAUNCH_PXE_OPROM) == SETUP_FLAG_LAUNCH_PXE_OPROM)
    isPxeOpromOn = TRUE;
  else
    isPxeOpromOn = FALSE;

  Status = iniParserProtocol->SetBoolean(dict, chipsetConfigSectionName,
                                pxeOpromKey, isPxeOpromOn);
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveSataModeToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  UINT16 Flags = 0;
  UINT32 sataMode = 0;

  EFI_STATUS Status = EFI_ABORTED;

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return EFI_LOAD_ERROR;
  }

  if ((Flags & SETUP_FLAG_SATA_MODE) == SETUP_FLAG_SATA_MODE)
    sataMode = 0;
  else
    sataMode = 1;

  Status = iniParserProtocol->SetInteger(dict, chipsetConfigSectionName,
                                sataModeKey, sataMode);
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveSataAhciSlowToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  UINT16 Flags = 0;
  BOOLEAN isSataAhciSlowOn = FALSE;

  EFI_STATUS Status = EFI_ABORTED;

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return EFI_LOAD_ERROR;
  }

  if ((Flags & SETUP_FLAG_SATA_AHCI_SLOW) == SETUP_FLAG_SATA_AHCI_SLOW)
    isSataAhciSlowOn = TRUE;
  else
    isSataAhciSlowOn = FALSE;

  Status = iniParserProtocol->SetBoolean(dict, chipsetConfigSectionName,
                                sataAhciSlowKey, isSataAhciSlowOn);
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SavePs2CfgToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  UINT16 Flags = 0;
  UINT32 Ps2Cfg = 0;

  EFI_STATUS Status = EFI_ABORTED;

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return EFI_LOAD_ERROR;
  }

  if ((Flags & SETUP_FLAG_PS2_EN) == SETUP_FLAG_PS2_EN)
    Ps2Cfg = 1;
  else
    Ps2Cfg = 0;

  Status = iniParserProtocol->SetInteger(dict, chipsetConfigSectionName,
                                Ps2CfgKey, Ps2Cfg);
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveAmtKeyboardLockToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  UINT16 Flags = 0;
  UINT32 AmtKeyboardLockCfg = 0;

  EFI_STATUS Status = EFI_ABORTED;

  Status = GetSetupFlags(&Flags);
  if (EFI_ERROR(Status)) {
    return EFI_LOAD_ERROR;
  }

  if ((Flags & SETUP_FLAG_AMT_KBC_LOCK) == SETUP_FLAG_AMT_KBC_LOCK)
    AmtKeyboardLockCfg = 1;
  else
    AmtKeyboardLockCfg = 0;

  Status = iniParserProtocol->SetInteger(dict, chipsetConfigSectionName,
                                AmtKeyboardLockKey, AmtKeyboardLockCfg);
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveUsbPortsCfgToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_ABORTED;

  USB_SETUP *UsbFlags = NULL;
  UINT32 UsbPortFlag = 0;
  CHAR8* UsbPortNKey = NULL;
  UINTN UsbPortNKeyMaxLen = 0, i;

  UsbPortNKeyMaxLen = AsciiStrLen(UsbPortNCfgKey) + MAXIMUM_VALUE_CHARACTERS;
  UsbPortNKey = AllocateZeroPool(UsbPortNKeyMaxLen);
  if (UsbPortNKey == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto _exit;
  }

  Status = ObtainUsbSetupEfiVar(&UsbFlags);
  if (Status == EFI_NOT_FOUND) {
    //var not found -> no USB ports -> nothing to set -> just exit
    Status = EFI_SUCCESS;
    goto _exit;
  } else if (EFI_ERROR(Status)) {
    Status = EFI_LOAD_ERROR;
    goto _exit;
  }

  Status = iniParserProtocol->SetInteger(dict, chipsetConfigSectionName,
                                UsbPortsNumCfgKey, UsbFlags->PortsNumber);
  if (!EFI_ERROR(Status)) {
    for (i = 0; i < UsbFlags->PortsNumber; i++) {
      AsciiSPrint(UsbPortNKey, UsbPortNKeyMaxLen, UsbPortNCfgKey, i);
      UsbPortFlag = UsbFlags->PortsData[i] & 1;
      Status = iniParserProtocol->SetInteger(dict, chipsetConfigSectionName, UsbPortNKey, UsbPortFlag);
      if (EFI_ERROR(Status))
        break;
    }
  }

_exit:
  if (UsbPortNKey != NULL)
    FreePool(UsbPortNKey);

  LOG((EFI_D_ERROR, "%a.%d Status = 0x%X\n",  __FUNCTION__, __LINE__, Status));
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
StoreChipsetConfigToDict (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status = EFI_SUCCESS;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  status = SaveUsbLegacySupportToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return status;
  }

  status = SavePxeOpromToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return status;
  }

  status = SaveSataModeToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return status;
  }

  status = SaveSataAhciSlowToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return status;
  }

  status = SavePs2CfgToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return status;
  }

  status = SaveAmtKeyboardLockToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return status;
  }

  status = SaveUsbPortsCfgToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    return status;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
CONFIG_ERROR_T
DumpChipsetConfigToDictionary (
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;
  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;

  if (dict == NULL)
    return ERROR_INVALID_PARAMETER;

  if (gBS->LocateProtocol (
             &gIniParserDxeProtocolGuid,
             NULL,
             (VOID **) &iniParserProtocol
             ) != EFI_SUCCESS)
    return CANT_LOCATE_INI_PARSER_PROTOCOL;

  Status = StoreChipsetConfigToDict(iniParserProtocol, dict);
  if (EFI_ERROR(Status)) {
    switch(Status) {
    case EFI_UNSUPPORTED:
      return UNSUPPORTED_SETTING_COMBINATION;
    default:
      return NO_CONFIG_KEY;
    }
  }

  return SUCCESS_TO_SET_CONFIG;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Constructor of ChipsetConfig */
/*! The task of this constructor is to register ChipsetConfig in the
    GlobalConfigDxe */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
ChipsetConfigConstructor (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
)
{
  EFI_STATUS status;
  GLOBAL_CONFIG_PROTOCOL *pGlobalConfigProtocol = NULL;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  status = gBS->LocateProtocol (
           &gGlobalConfigProtocolGuid,
           NULL,
           (VOID **) &pGlobalConfigProtocol
           );
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d: Error: status = 0x%x\n", __FUNCTION__, __LINE__, status));
    return status;
  }

  status = pGlobalConfigProtocol->AddConfig(chipsetConfigSectionName,
                                    SetConfigFromDictionary, DumpChipsetConfigToDictionary);

  LOG((EFI_D_ERROR, "%a.%d:  status: 0x%x\n", __FUNCTION__, __LINE__, status));

  return status;
}
//------------------------------------------------------------------------------

