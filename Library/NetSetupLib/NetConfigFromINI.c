/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/GlobalConfigDxe.h>
#include <Protocol/IniParserDxe.h>

#include "NetSetupInternal.h"

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

static CHAR8 nicSectionName[] = "NetConfig";
static CHAR8 ethSectionName[]     = "NetConfig/Eth%d";

static CHAR8 enableKey[]     = "Enable";
static CHAR8 useDhcpKey[]    = "EnableDHCP";
static CHAR8 localAddrKey[]  = "LocalIP";
static CHAR8 subnetMaskKey[] = "SubnetMask";
static CHAR8 gatewayKey[]    = "Gateway";
static CHAR8 primaryDnsKey[] = "PrimaryDns";
static CHAR8 secondaryDnsKey[] = "SecondaryDns";
static CHAR8 dnsDomainNameKey[] = "DnsDomainName";

static CHAR8 removeSettingStr[] = "\"\"";

//------------------------------------------------------------------------------
/*! \brief Get NIC config by section name */
//------------------------------------------------------------------------------
NIC_CONFIG_T
GetNicConfigBySectionName (
  IN CHAR8 *sectionName,
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict,
  OUT EFI_STATUS *retval
)
{
  NIC_CONFIG_T config = {FALSE, FALSE, NULL, NULL, NULL, NULL, NULL, NULL};

  CHAR8 *localAddr8, *netMask8, *gateway8;
  CHAR8 *primaryDns8, *secondaryDns8, *dnsDomainName8;

  if (retval == NULL)
    return config;

  if (sectionName == NULL || iniParserProtocol == NULL || dict == NULL) {
    *retval = EFI_INVALID_PARAMETER;
    return config;
  }

  *retval = iniParserProtocol->GetBoolean(dict, sectionName, enableKey, &config.enable);
  if (EFI_ERROR(*retval))
    return config;

  if (config.enable == FALSE)
    return config;

  *retval = iniParserProtocol->GetBoolean(dict, sectionName, useDhcpKey, &config.useDHCP);
  if (EFI_ERROR(*retval))
    return config;

  localAddr8 = iniParserProtocol->GetString(dict, sectionName, localAddrKey);
  if (localAddr8 == NULL) {
    *retval = EFI_NOT_FOUND;
    return config;
  }
  config.localAddr = AllocateZeroPool(AsciiStrLen(localAddr8)*sizeof(CHAR16) + sizeof(CHAR16));
  if (config.localAddr == NULL) {
    *retval = EFI_OUT_OF_RESOURCES;
    return config;
  }
  if (AsciiStrCmp(removeSettingStr, localAddr8) != 0)
    AsciiStrToUnicodeStr(localAddr8, config.localAddr);

  netMask8 = iniParserProtocol->GetString(dict, sectionName, subnetMaskKey);
  if (netMask8 == NULL) {
    *retval = EFI_NOT_FOUND;
    return config;
  }
  config.netMask = AllocateZeroPool(AsciiStrLen(netMask8)*sizeof(CHAR16) + sizeof(CHAR16));
  if (config.netMask == NULL) {
    *retval = EFI_OUT_OF_RESOURCES;
    return config;
  }
  if (AsciiStrCmp(removeSettingStr, netMask8) != 0)
    AsciiStrToUnicodeStr(netMask8, config.netMask);

  gateway8 = iniParserProtocol->GetString(dict, sectionName, gatewayKey);
  if (gateway8 != NULL) {
    config.gateway = AllocateZeroPool(AsciiStrLen(gateway8)*sizeof(CHAR16) + sizeof(CHAR16));
    if (config.gateway == NULL) {
      *retval = EFI_OUT_OF_RESOURCES;
      return config;
    }
    if (AsciiStrCmp(removeSettingStr, gateway8) != 0)
      AsciiStrToUnicodeStr(gateway8, config.gateway);
  }

  primaryDns8 = iniParserProtocol->GetString(dict, sectionName, primaryDnsKey);
  if (primaryDns8 != NULL) {
    config.primaryDns = AllocateZeroPool(AsciiStrLen(primaryDns8)*sizeof(CHAR16) + sizeof(CHAR16));
    if (config.primaryDns == NULL) {
      *retval = EFI_OUT_OF_RESOURCES;
      return config;
    }
    if (AsciiStrCmp(removeSettingStr, primaryDns8) != 0)
      AsciiStrToUnicodeStr(primaryDns8, config.primaryDns);
  }

  secondaryDns8 = iniParserProtocol->GetString(dict, sectionName, secondaryDnsKey);
  if (secondaryDns8 != NULL) {
    config.secondaryDns = AllocateZeroPool(AsciiStrLen(secondaryDns8)*sizeof(CHAR16) + sizeof(CHAR16));
    if (config.secondaryDns == NULL) {
      *retval = EFI_OUT_OF_RESOURCES;
      return config;
    }
    if (AsciiStrCmp(removeSettingStr, secondaryDns8) != 0)
      AsciiStrToUnicodeStr(secondaryDns8, config.secondaryDns);
  }

  dnsDomainName8 = iniParserProtocol->GetString(dict, sectionName, dnsDomainNameKey);
  if (dnsDomainName8 != NULL) {
    config.dnsDomainName = AllocateZeroPool(AsciiStrLen(dnsDomainName8)*sizeof(CHAR16) + sizeof(CHAR16));
    if (config.dnsDomainName == NULL) {
      *retval = EFI_OUT_OF_RESOURCES;
      return config;
    }
    if (AsciiStrCmp(removeSettingStr, dnsDomainName8) != 0)
      AsciiStrToUnicodeStr(dnsDomainName8, config.dnsDomainName);
  }

  *retval = EFI_SUCCESS;

  return config;
}
//------------------------------------------------------------------------------


STATIC
VOID
DestroyEthConfig (
  IN NIC_CONFIG_T *ConfigEth
  )
{
  if (ConfigEth == NULL) {
    return;
  }
  if (ConfigEth->localAddr != NULL)
    FreePool(ConfigEth->localAddr);
  if (ConfigEth->netMask != NULL)
    FreePool(ConfigEth->netMask);
  if (ConfigEth->gateway != NULL)
    FreePool(ConfigEth->gateway);
  if (ConfigEth->primaryDns != NULL)
    FreePool(ConfigEth->primaryDns);
  if (ConfigEth->secondaryDns != NULL)
    FreePool(ConfigEth->secondaryDns);
  if (ConfigEth->dnsDomainName != NULL)
    FreePool(ConfigEth->dnsDomainName);
}

//------------------------------------------------------------------------------
/*! \brief Setup all NICs */
//------------------------------------------------------------------------------
static
CONFIG_ERROR_T
SetNicConfigFromDictionaryWithProtocol (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CONFIG_ERROR_T retval;
  UINTN nicCount = 0, i;
  EFI_STATUS Status = EFI_SUCCESS;
  CHAR8 ethNicSectionNameTemplate[255];
  NIC_CONFIG_T ConfigEth;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = IfconfigGetAllNicCount(&nicCount);
  if (EFI_ERROR(Status) || nicCount == 0) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  for (i = 0; i < nicCount; i++) {
    AsciiSPrint (
      ethNicSectionNameTemplate,
      sizeof (ethNicSectionNameTemplate),
      ethSectionName,
      i
      );
    ZeroMem(&ConfigEth, sizeof (ConfigEth));
    ConfigEth = GetNicConfigBySectionName (
                  ethNicSectionNameTemplate, 
                  iniParserProtocol, 
                  dict, 
                  &Status
                  );
    switch(Status) {
    case EFI_SUCCESS:
      break;

    case EFI_NOT_FOUND:
      continue;

    default:
      return ERROR_OUT_OF_MEMORY;
    }
    Status = SetNicConfigByIndex(i, ConfigEth);
    DestroyEthConfig (&ConfigEth);
    switch (Status) {
    case EFI_SUCCESS:
      break;

    case EFI_INVALID_PARAMETER:
      retval = UNSUPPORTED_KEY_VALUE;
      goto _exit;

    default:
      retval = CANT_SAVE_CONFIG_TO_VARIABLE;
      goto _exit;
    }
  }
  
  retval = SUCCESS_TO_SET_CONFIG;

_exit:
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief NicConfig with INI dictionary */
/*! Register this function as a callback config method in the GlobalConfigDxe */
/*! \param[in] *dict A pointer to the INI dictionary */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetNicConfigFromDictionary (
  IN dictionary *dict
)
{
  CONFIG_ERROR_T status = ERROR_INVALID_PARAMETER;
  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;

  if (dict == NULL)
    return ERROR_INVALID_PARAMETER;

  if (gBS->LocateProtocol (
             &gIniParserDxeProtocolGuid,
             NULL,
             (VOID **) &iniParserProtocol
             ) != EFI_SUCCESS) {
    return CANT_LOCATE_INI_PARSER_PROTOCOL;
  }

  if (!iniParserProtocol->CheckSecPresent(dict, nicSectionName)) {
    return NO_CONFIG_SECTION;
  }

  status = SetNicConfigFromDictionaryWithProtocol(iniParserProtocol, dict);

  return status;

}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Net config with config INI file */
/*! Read Net config from config INI file and save to the variables. Use this function
    to config Net directly without using GlobalConfigDxe */
/*! \param[in] *filePath Path to the config file */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetNetConfigFromINIFile (
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
  if (EFI_ERROR(status))
    return CANT_LOCATE_INI_PARSER_PROTOCOL;

  dict = iniParserProtocol->NewIniDictionary(filePath);
  if (dict == NULL)
    return ERROR_OUT_OF_MEMORY;

  status = SetNicConfigFromDictionaryWithProtocol(iniParserProtocol, dict);

  iniParserProtocol->DeleteIniDictionary(dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveEnableFlagToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN CHAR8 *sectionName,
  IN NIC_CONFIG_T *Settings
)
{
  EFI_STATUS Status = EFI_SUCCESS;
  Status = iniParserProtocol->SetBoolean(dict, sectionName, enableKey, Settings->enable);
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveUseDhcpFlagToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN CHAR8 *sectionName,
  IN NIC_CONFIG_T *Settings
)
{
  EFI_STATUS Status = EFI_SUCCESS;
  Status = iniParserProtocol->SetBoolean(dict, sectionName, useDhcpKey, Settings->useDHCP);
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveLocalAddressToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN CHAR8 *sectionName,
  IN NIC_CONFIG_T *Settings
)
{
  CHAR8  *localAddress8  = NULL;
  CHAR16 *localAddress16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  localAddress16 = Settings->localAddr;
   if (localAddress16 == NULL) {
    Status = iniParserProtocol->SetString(dict, sectionName,
                                  localAddrKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(localAddress16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, sectionName,
                                  localAddrKey, removeSettingStr);
  } else {
    localAddress8 = AllocateZeroPool(StrLen(localAddress16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (localAddress8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (localAddress16, localAddress8);
      Status = iniParserProtocol->SetString(dict, sectionName, localAddrKey, localAddress8);
      FreePool(localAddress8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveNetMaskToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN CHAR8 *sectionName,
  IN NIC_CONFIG_T *Settings
)
{
  CHAR8  *netmask8  = NULL;
  CHAR16 *netmask16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  netmask16 = Settings->netMask;
   if (netmask16 == NULL) {
    Status = iniParserProtocol->SetString(dict, sectionName,
                                  subnetMaskKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(netmask16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, sectionName,
                                  subnetMaskKey, removeSettingStr);
  } else {
    netmask8 = AllocateZeroPool(StrLen(netmask16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (netmask8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (netmask16, netmask8);
      Status = iniParserProtocol->SetString(dict, sectionName, subnetMaskKey, netmask8);
      FreePool(netmask8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveGatewayToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN CHAR8 *sectionName,
  IN NIC_CONFIG_T *Settings
)
{
  CHAR8  *gateway8  = NULL;
  CHAR16 *gateway16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  gateway16 = Settings->gateway;
   if (gateway16 == NULL) {
    Status = iniParserProtocol->SetString(dict, sectionName,
                                  gatewayKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(gateway16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, sectionName,
                                  gatewayKey, removeSettingStr);
  } else {
    gateway8 = AllocateZeroPool(StrLen(gateway16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (gateway8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (gateway16, gateway8);
      Status = iniParserProtocol->SetString(dict, sectionName, gatewayKey, gateway8);
      FreePool(gateway8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SavePrimaryDnsToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN CHAR8 *sectionName,
  IN NIC_CONFIG_T *Settings
)
{
  CHAR8  *primDns8  = NULL;
  CHAR16 *primDns16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  primDns16 = Settings->primaryDns;
   if (primDns16 == NULL) {
    Status = iniParserProtocol->SetString(dict, sectionName,
                                  primaryDnsKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(primDns16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, sectionName,
                                  primaryDnsKey, removeSettingStr);
  } else {
    primDns8 = AllocateZeroPool(StrLen(primDns16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (primDns8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (primDns16, primDns8);
      Status = iniParserProtocol->SetString(dict, sectionName, primaryDnsKey, primDns8);
      FreePool(primDns8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveSecondaryDnsToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN CHAR8 *sectionName,
  IN NIC_CONFIG_T *Settings
)
{
  CHAR8  *secondaryDns8  = NULL;
  CHAR16 *secondaryDns16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  secondaryDns16 = Settings->secondaryDns;
   if (secondaryDns16 == NULL) {
    Status = iniParserProtocol->SetString(dict, sectionName,
                                  primaryDnsKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(secondaryDns16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, sectionName,
                                  primaryDnsKey, removeSettingStr);
  } else {
    secondaryDns8 = AllocateZeroPool(StrLen(secondaryDns16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (secondaryDns8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (secondaryDns16, secondaryDns8);
      Status = iniParserProtocol->SetString(dict, sectionName, primaryDnsKey, secondaryDns8);
      FreePool(secondaryDns8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveDnsDomainNameToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN CHAR8 *sectionName,
  IN NIC_CONFIG_T *Settings
)
{
  CHAR8  *dnsDomainName8  = NULL;
  CHAR16 *dnsDomainName16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  dnsDomainName16 = Settings->dnsDomainName;
   if (dnsDomainName16 == NULL) {
    Status = iniParserProtocol->SetString(dict, sectionName,
                                  dnsDomainNameKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(dnsDomainName16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, sectionName,
                                  dnsDomainNameKey, removeSettingStr);
  } else {
    dnsDomainName8 = AllocateZeroPool(StrLen(dnsDomainName16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (dnsDomainName8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (dnsDomainName16, dnsDomainName8);
      Status = iniParserProtocol->SetString(dict, sectionName, dnsDomainNameKey, dnsDomainName8);
      FreePool(dnsDomainName8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveNicConfigToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN UINTN nicIndex,
  IN NIC_CONFIG_T *nicConfig
)
{
  EFI_STATUS Status = EFI_SUCCESS, retval = EFI_SUCCESS;

  CHAR8 *sectionName;
  UINTN sectionNameMaxLen;

  sectionNameMaxLen = AsciiStrLen(ethSectionName) + MAXIMUM_VALUE_CHARACTERS;
  sectionName = AllocateZeroPool(sectionNameMaxLen);
  if (sectionName == NULL) 
    return EFI_OUT_OF_RESOURCES;

  AsciiSPrint(sectionName, sectionNameMaxLen, ethSectionName, nicIndex);

  LOG((EFI_D_ERROR, "%a.%d %d sectionName %a\n", __FUNCTION__, __LINE__, sectionName));

  Status = SaveEnableFlagToDictionary(iniParserProtocol, dict, sectionName, nicConfig);
  if (EFI_ERROR(Status))
    retval = Status;
  
  Status = SaveUseDhcpFlagToDictionary(iniParserProtocol, dict, sectionName, nicConfig);
  if (EFI_ERROR(Status))
    retval = Status;
  
  Status = SaveLocalAddressToDictionary(iniParserProtocol, dict, sectionName, nicConfig);
  if (EFI_ERROR(Status))
    retval = Status;
  
  Status = SaveNetMaskToDictionary(iniParserProtocol, dict, sectionName, nicConfig);
  if (EFI_ERROR(Status))
    retval = Status;
  
  Status = SaveGatewayToDictionary(iniParserProtocol, dict, sectionName, nicConfig);
  if (EFI_ERROR(Status))
    retval = Status;
  
  Status = SavePrimaryDnsToDictionary(iniParserProtocol, dict, sectionName, nicConfig);
  if (EFI_ERROR(Status))
    retval = Status;
  
  Status = SaveSecondaryDnsToDictionary(iniParserProtocol, dict, sectionName, nicConfig);
  if (EFI_ERROR(Status))
    retval = Status;
  
  Status = SaveDnsDomainNameToDictionary(iniParserProtocol, dict, sectionName, nicConfig);
  if (EFI_ERROR(Status))
    retval = Status;

  if (sectionName != NULL)
    FreePool(sectionName);

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
StoreNetSetupConfigToDict (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  UINTN nicCount = 0, i;
  EFI_STATUS Status = EFI_SUCCESS, retval = EFI_SUCCESS;

  Status = IfconfigGetAllNicCount(&nicCount);
  if (EFI_ERROR(Status) || nicCount == 0)
    return EFI_ABORTED;

  for (i = 0; i < nicCount; i++) {
    NIC_CONFIG_T *nicConfig = NULL;

    Status = IfconfigGetNicInfoByIndex(i, &nicConfig);
    if (EFI_ERROR(Status) || nicConfig == NULL)
      continue;

    Status = SaveNicConfigToDictionary(iniParserProtocol, dict, i, nicConfig);
    if (EFI_ERROR(Status))
      retval = Status;

    if (nicConfig != NULL)
      IfConfigFree(nicConfig);
  }

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
CONFIG_ERROR_T
DumpNetSetupConfigToDictionary (
  IN dictionary *dict
)
{
  EFI_STATUS status = EFI_SUCCESS;
  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (dict == NULL)
    return ERROR_INVALID_PARAMETER;

  if (gBS->LocateProtocol (
           &gIniParserDxeProtocolGuid,
           NULL,
           (VOID **) &iniParserProtocol
           ) != EFI_SUCCESS)
    return CANT_LOCATE_INI_PARSER_PROTOCOL;

  status = StoreNetSetupConfigToDict(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    return CANT_SAVE_CONFIG_TO_DICTIONARY;

  return SUCCESS_TO_SET_CONFIG;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief NetSetup Constructor */
/*! The task of this constructor is to register NetSetupConfig in the
    GlobalConfigDxe */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
NetSetupConstructor (
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

  status = pGlobalConfigProtocol->AddConfig(nicSectionName,
                                    SetNicConfigFromDictionary, DumpNetSetupConfigToDictionary);
    
  return status;
}
//------------------------------------------------------------------------------

