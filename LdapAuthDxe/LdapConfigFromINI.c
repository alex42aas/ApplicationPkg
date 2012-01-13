/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

#include <Protocol/IniParserDxe.h>
#include <Protocol/LdapConfigOp.h>

#include <Protocol/GlobalConfigDxe.h>
#include <Protocol/GlobalConfigType.h>

#include "LdapConfigInternal.h"

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

STATIC CHAR8 ldapSectionName[] = "LdapConfig";

STATIC CHAR8 ldapUsageKey[]      = "UseLdap";
STATIC CHAR8 ldapTlsKey[]        = "UseTLS";
STATIC CHAR8 ldapPortKey[]       = "LdapPort";
STATIC CHAR8 ldapServAdressKey[] = "LdapServerAddress";
STATIC CHAR8 ldapServNameKey[]   = "LdapServerName";
STATIC CHAR8 ldapDomainKey[]     = "LdapDomain";
STATIC CHAR8 ldapBindDnKey[]     = "LdapBindDn";
STATIC CHAR8 ldapBindPwKey[]     = "LdapBindPw";
STATIC CHAR8 ldapPcBaseKey[]     = "LdapPcBase";

STATIC CHAR8 removeSettingStr[] = "\"\"";

STATIC
CONFIG_ERROR_T
DumpLdapConfigToDictionary (
  IN dictionary *dict
);


//------------------------------------------------------------------------------
/*! \brief Read ldap usage flag from dictionary and set */
/*! You have to call SaveLdapConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetLdapUsageStatusFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  BOOLEAN ldapUsage = FALSE;
  EFI_STATUS Status = EFI_SUCCESS;

  Status = iniParserProtocol->GetBoolean(dict, ldapSectionName, ldapUsageKey, &ldapUsage);
  if (!EFI_ERROR(Status)) {
    if (ldapUsage == TRUE)
      SetLdapAuthUsageStatus(USE_LDAP_AUTH);
    else
      SetLdapAuthUsageStatus(NOT_USE_LDAP_AUTH);
  }
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read server IP address from dictionary and set */
/*! You have to call SaveLdapConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetServerIpAddressFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CHAR8 *ldapIpAddr8 = NULL;
  CHAR16 *ldapIpAddr16 = NULL;
  EFI_STATUS Status = EFI_SUCCESS;

  ldapIpAddr8 = iniParserProtocol->GetString(dict, ldapSectionName, ldapServAdressKey);
  if (ldapIpAddr8 != NULL) {
    LOG((EFI_D_ERROR, "ldapIpAddr8: %a\n", ldapIpAddr8));
    if (AsciiStrCmp(ldapIpAddr8, removeSettingStr) == 0) {
      Status = SetLdapServerAddr(L""); // Clear IP address
    } else {
      ldapIpAddr16 = AllocateZeroPool(AsciiStrLen(ldapIpAddr8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (ldapIpAddr16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(ldapIpAddr8, ldapIpAddr16);
        Status = SetLdapServerAddr(ldapIpAddr16);
        FreePool(ldapIpAddr16);
      }
    }
  } else {
    LOG((EFI_D_ERROR, "ldapIpAddr8 is NULL\n"));
  }
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read server port from dictionary and set */
/*! You have to call SaveLdapConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetLdapPortFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  INT32 ldapPort = 0;
  EFI_STATUS Status = EFI_SUCCESS;

  Status = iniParserProtocol->GetInteger(dict, ldapSectionName, ldapPortKey, &ldapPort);
  switch(Status) {
    case EFI_SUCCESS:
      if(ldapPort < 0) {
        Status = EFI_UNSUPPORTED;
      } else {
        Status = SetLdapPort(ldapPort);
      }
      break;
    default:
      break;
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read server name from dictionary and set */
/*! You have to call SaveLdapConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetServerNameFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CHAR8  *ldapServName8  = NULL;
  CHAR16 *ldapServName16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapServName8 = iniParserProtocol->GetString(dict, ldapSectionName, ldapServNameKey);
  if (ldapServName8 != NULL) {
    LOG((EFI_D_ERROR, "ldapServName8: %a\n", ldapServName8));
    if (AsciiStrCmp(ldapServName8, removeSettingStr) == 0) {
      Status = SetLdapServerName(L""); // Clear server name
    } else {
      ldapServName16 = AllocateZeroPool(AsciiStrLen(ldapServName8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (ldapServName16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(ldapServName8, ldapServName16);
        Status = SetLdapServerName(ldapServName16);
        FreePool(ldapServName16);
      }
    }
  } else {
    LOG((EFI_D_ERROR, "ldapServName8 is NULL\n"));
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read ldap search base domain from dictionary and set */
/*! You have to call SaveLdapConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetLdapDomainFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CHAR8  *ldapDomain8  = NULL;
  CHAR16 *ldapDomain16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapDomain8 = iniParserProtocol->GetString(dict, ldapSectionName, ldapDomainKey);
  if (ldapDomain8 != NULL) {
    LOG((EFI_D_ERROR, "ldapDomain8: %a\n", ldapDomain8));
    if (AsciiStrCmp(ldapDomain8, removeSettingStr) == 0) {
      Status = SetLdapSuffix(L""); // Clear search base domain
    } else {
      ldapDomain16 = AllocateZeroPool(AsciiStrLen(ldapDomain8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (ldapDomain16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(ldapDomain8, ldapDomain16);
        Status = SetLdapSuffix(ldapDomain16);
        FreePool(ldapDomain16);
      }
    }
  } else {
    LOG((EFI_D_ERROR, "ldapDomain8 is NULL\n"));
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read Bind DN from dictionary and set */
/*! You have to call SaveLdapConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetLdapBindDnFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CHAR8  *ldapBindDn8  = NULL;
  CHAR16 *ldapBindDn16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapBindDn8 = iniParserProtocol->GetString(dict, ldapSectionName, ldapBindDnKey);
  if (ldapBindDn8 != NULL) {
    LOG((EFI_D_ERROR, "ldapBindDn8: %a\n", ldapBindDn8));
    if (AsciiStrCmp(ldapBindDn8, removeSettingStr) == 0) {
      Status = SetLdapRootdn(L""); // Clear root dn
    } else {
      ldapBindDn16 = AllocateZeroPool(AsciiStrLen(ldapBindDn8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (ldapBindDn16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(ldapBindDn8, ldapBindDn16);
        Status = SetLdapRootdn(ldapBindDn16);
        FreePool(ldapBindDn16);
      }
    }
  } else {
    LOG((EFI_D_ERROR, "ldapBindDn16 is NULL\n"));
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read Bind PW from dictionary and set */
/*! You have to call SaveLdapConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetLdapBindPwFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CHAR8 *ldapBindPw8 = NULL;
  CHAR16 *ldapBindPw16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapBindPw8 = iniParserProtocol->GetString(dict, ldapSectionName, ldapBindPwKey);
  if (ldapBindPw8 != NULL) {
    LOG((EFI_D_ERROR, "ldapBindPw8: %a\n", ldapBindPw8));
    if (AsciiStrCmp(ldapBindPw8, removeSettingStr) == 0) {
      Status = SetLdapRootpw(L""); // Clear root pw
    } else {
      ldapBindPw16 = AllocateZeroPool(AsciiStrLen(ldapBindPw8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (ldapBindPw16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(ldapBindPw8, ldapBindPw16);
        Status = SetLdapRootpw(ldapBindPw16);
        FreePool(ldapBindPw16);
      }
    }
  } else {
    LOG((EFI_D_ERROR, "ldapBindPw16 is NULL\n"));
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read TLS usage flag from dictionary and set */
/*! You have to call SaveLdapConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetTLSUsageStatusFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  BOOLEAN tlsUsage = FALSE;

  EFI_STATUS Status = EFI_SUCCESS;

  Status = iniParserProtocol->GetBoolean(dict, ldapSectionName, ldapTlsKey, &tlsUsage);
  if (!EFI_ERROR(Status)) {
    SetTLSUsage(tlsUsage);
  }
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read search pc base from dictionary and set */
/*! You have to call SaveLdapConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetPcBaseFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CHAR8  *ldapPcBase8  = NULL;
  CHAR16 *ldapPcBase16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapPcBase8 = iniParserProtocol->GetString(dict, ldapSectionName, ldapPcBaseKey);
  if (ldapPcBase8 != NULL) {
    LOG((EFI_D_ERROR, "ldapPcBase8: %a\n", ldapPcBase8));
    if (AsciiStrCmp(ldapPcBase8, removeSettingStr) == 0) {
      Status = SetLdapPCBase(L""); // Clear root dn
    } else {
      ldapPcBase16 = AllocateZeroPool(AsciiStrLen(ldapPcBase8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (ldapPcBase16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(ldapPcBase8, ldapPcBase16);
        Status = SetLdapPCBase(ldapPcBase16);
        FreePool(ldapPcBase16);
      }
    }
  } else {
    LOG((EFI_D_ERROR, "ldapPcBase16 is NULL\n"));
  }

  return Status;
}

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Setup LDAP config from dictionary and save */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
STATIC
CONFIG_ERROR_T
SetLdapConfigFromDictionaryWithProtocol(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status;

  status = ReadLdapConfig();
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d  Error to read ldap config\n", __FUNCTION__, __LINE__));
    return CANT_READ_CONFIG_FROM_VARIABLE;
  }

  status = SetLdapUsageStatusFromDictionary(iniParserProtocol, dict);
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return ERROR_OUT_OF_MEMORY;
  }

  status = SetServerIpAddressFromDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    return CANT_SAVE_CONFIG_TO_VARIABLE;

  status = SetLdapPortFromDictionary(iniParserProtocol, dict);
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return UNSUPPORTED_KEY_VALUE;
  }

  status = SetServerNameFromDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    return UNSUPPORTED_KEY_VALUE;

  status = SetLdapDomainFromDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    return UNSUPPORTED_KEY_VALUE;

  status = SetLdapBindDnFromDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    return UNSUPPORTED_KEY_VALUE;

  status = SetLdapBindPwFromDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    return UNSUPPORTED_KEY_VALUE;

  status = SetTLSUsageStatusFromDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    return UNSUPPORTED_KEY_VALUE;

  status = SetPcBaseFromDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    return UNSUPPORTED_KEY_VALUE;

  status = SaveLdapConfig();
  switch(status) {
    case EFI_SUCCESS:
      return SUCCESS_TO_SET_CONFIG;
    default:
      return CANT_SAVE_CONFIG_TO_VARIABLE;
  }
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Setup LDAP config with config INI file */
/*! Read LDAP config from INI file and save to the variable. Use this function
    to config LDAP directly without using GlobalConfigDxe */
/*! \param[in] *filePath Path to the config file */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */  
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetConfigFromINIFile(
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
  if (dict == NULL) {
    return ERROR_OUT_OF_MEMORY;
  }  

  status = SetLdapConfigFromDictionaryWithProtocol(iniParserProtocol, dict);

  iniParserProtocol->DeleteIniDictionary(dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Setup LDAP config with config data */
/*! Read LDAP config from config data and save to the variable. Use this function
    to config LDAP directly without using GlobalConfigDxe */
/*! \param[in] *configData Path to the config file
    \param[in] dataLen  A length of data */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */    
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetConfigFromData(
  UINT8 *configData,
  UINTN dataLen
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

  dict = iniParserProtocol->NewIniDictionaryWithData(configData, dataLen);
  if (dict == NULL)
    return ERROR_OUT_OF_MEMORY;

  status = SetLdapConfigFromDictionaryWithProtocol(iniParserProtocol, dict);

  iniParserProtocol->DeleteIniDictionary(dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Setup LDAP config with config INI file */
/*! Register this function as callback config method in the GlobalConfigDxe */
/*! \param[in] *dict A pointer to the INI dictionary */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetConfigFromDictionary(
  IN dictionary *dict
)
{
  CONFIG_ERROR_T status;
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

  if (!iniParserProtocol->CheckSecPresent(dict, ldapSectionName)) {
    return NO_CONFIG_SECTION;
  }

  status = SetLdapConfigFromDictionaryWithProtocol(iniParserProtocol, dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Register LdapConfig in GlobalConfig */
//------------------------------------------------------------------------------
EFI_STATUS
RegisterSelfInGlobalConfig (
  VOID
)
{
  EFI_STATUS Status = EFI_ABORTED;

  GLOBAL_CONFIG_PROTOCOL *pGlobalConfigProtocol = NULL;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = gBS->LocateProtocol (
           &gGlobalConfigProtocolGuid,
           NULL,
           (VOID **) &pGlobalConfigProtocol
           );
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d: Error: status = 0x%x\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Status = pGlobalConfigProtocol->AddConfig(ldapSectionName,
                                    SetConfigFromDictionary, DumpLdapConfigToDictionary);

  LOG((EFI_D_ERROR, "%a.%d: Status: 0x%x\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a server name and store to the dictionary */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveServerNameToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CHAR8        *ldapServerName8  = NULL;
  const CHAR16 *ldapServerName16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapServerName16 = GetLdapServerName();
  if (ldapServerName16 == NULL) {
    Status = iniParserProtocol->SetString(dict, ldapSectionName,
                                  ldapServNameKey, removeSettingStr);
    return Status;
  }
  
  if (StrCmp(ldapServerName16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, ldapSectionName,
                                  ldapServNameKey, removeSettingStr);
  } else {
    ldapServerName8 = AllocateZeroPool(StrLen(ldapServerName16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (ldapServerName8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (ldapServerName16, ldapServerName8);
      Status = iniParserProtocol->SetString(dict, ldapSectionName, ldapServNameKey, ldapServerName8);
      FreePool(ldapServerName8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a ldap port and store to the dicitonary */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveLdapPortToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status = EFI_SUCCESS;
  status = iniParserProtocol->SetInteger(dict, ldapSectionName,
                                ldapPortKey, GetLdapServerPort());
  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a server address and store to the dictionary */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveServerIpAddressToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
        CHAR8  *ldapServerAddr8  = NULL;
  const CHAR16 *ldapServerAddr16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapServerAddr16 = GetLdapServerAddr();
  if (ldapServerAddr16 == NULL) {
    Status = iniParserProtocol->SetString(dict, ldapSectionName,
                                  ldapServAdressKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(ldapServerAddr16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, ldapSectionName,
                                  ldapServAdressKey, removeSettingStr);
  } else {
    ldapServerAddr8 = AllocateZeroPool(StrLen(ldapServerAddr16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (ldapServerAddr8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (ldapServerAddr16, ldapServerAddr8);
      Status = iniParserProtocol->SetString(dict, ldapSectionName, ldapServAdressKey, ldapServerAddr8);
      FreePool(ldapServerAddr8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a ldap search domain and store to the dictionary */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveLdapDomaintToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
        CHAR8  *ldapDomain8  = NULL;
  const CHAR16 *ldapDomain16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapDomain16 = GetLdapSuffix();
  if (ldapDomain16 == NULL) {
    Status = iniParserProtocol->SetString(dict, ldapSectionName,
                                  ldapDomainKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(ldapDomain16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, ldapSectionName,
                                  ldapDomainKey, removeSettingStr);
  } else {
    ldapDomain8 = AllocateZeroPool(StrLen(ldapDomain16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (ldapDomain8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (ldapDomain16, ldapDomain8);
      Status = iniParserProtocol->SetString(dict, ldapSectionName, ldapDomainKey, ldapDomain8);
      FreePool(ldapDomain8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a ldap search PC base and store to the dictionary */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SavePcBaseToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
        CHAR8  *ldapPcBase8  = NULL;
  const CHAR16 *ldapPcBase16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapPcBase16 = GetLdapPCBase();
  if (ldapPcBase16 == NULL) {
    Status = iniParserProtocol->SetString(dict, ldapSectionName,
                                  ldapPcBaseKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(ldapPcBase16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, ldapSectionName,
                                  ldapPcBaseKey, removeSettingStr);
  } else {
    ldapPcBase8 = AllocateZeroPool(StrLen(ldapPcBase16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (ldapPcBase8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (ldapPcBase16, ldapPcBase8);
      Status = iniParserProtocol->SetString(dict, ldapSectionName, ldapPcBaseKey, ldapPcBase8);
      FreePool(ldapPcBase8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a bind DN and store to the dictionary */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveLdapBindDnToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
        CHAR8  *ldapBindDn8  = NULL;
  const CHAR16 *ldapBindDn16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapBindDn16 = GetLdapRootdn();
  if (ldapBindDn16 == NULL) {
    Status = iniParserProtocol->SetString(dict, ldapSectionName,
                                  ldapBindDnKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(ldapBindDn16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, ldapSectionName,
                                  ldapBindDnKey, removeSettingStr);
  } else {
    ldapBindDn8 = AllocateZeroPool(StrLen(ldapBindDn16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (ldapBindDn8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (ldapBindDn16, ldapBindDn8);
      Status = iniParserProtocol->SetString(dict, ldapSectionName, ldapBindDnKey, ldapBindDn8);
      FreePool(ldapBindDn8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Ge a bind password and store to the dictionary */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveLdapBindPwToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
        CHAR8  *ldapBindPw8  = NULL;
  const CHAR16 *ldapBindPw16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapBindPw16 = GetLdapRootpw();
  if (ldapBindPw16 == NULL) {
    Status = iniParserProtocol->SetString(dict, ldapSectionName,
                                  ldapBindPwKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(ldapBindPw16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, ldapSectionName,
                                  ldapBindPwKey, removeSettingStr);
  } else {
    ldapBindPw8 = AllocateZeroPool(StrLen(ldapBindPw16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (ldapBindPw8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (ldapBindPw16, ldapBindPw8);
      Status = iniParserProtocol->SetString(dict, ldapSectionName, ldapBindPwKey, ldapBindPw8);
      FreePool(ldapBindPw8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a ldap TLS usage status and store to the dictionary */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveTLSUsageStatusToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status = EFI_SUCCESS;
  status = iniParserProtocol->SetBoolean(dict, ldapSectionName,
                                ldapTlsKey, IsUseTLS());
  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get ldap config and store to the dictionary */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
StoreLdapConfigToDict (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status = EFI_SUCCESS, retval = EFI_SUCCESS;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  switch(GetLdapAuthUsageStatus()) {
    case NOT_USE_LDAP_AUTH:
      status = iniParserProtocol->SetBoolean(dict, ldapSectionName, ldapUsageKey, FALSE);
      break;
    case USE_LDAP_AUTH:
      status = iniParserProtocol->SetBoolean(dict, ldapSectionName, ldapUsageKey, TRUE);
      break;
    default:
      status = EFI_UNSUPPORTED;
      break;
  }
  if (EFI_ERROR(status))
    retval = status;

  status = SaveServerIpAddressToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  status = SaveLdapPortToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  status = SaveServerNameToDictionary(iniParserProtocol,dict);
  if (EFI_ERROR(status))
    retval = status;

  status = SaveLdapDomaintToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  status = SavePcBaseToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  status = SaveLdapBindDnToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  status = SaveLdapBindPwToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  status = SaveTLSUsageStatusToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  LOG((EFI_D_ERROR, "%a.%d retval: %d\n", __FUNCTION__, __LINE__, retval));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a dictionary with the ldap config */
//------------------------------------------------------------------------------
STATIC
CONFIG_ERROR_T
DumpLdapConfigToDictionary (
  IN dictionary *dict
)
{
  EFI_STATUS status = EFI_SUCCESS;
  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (dict == NULL)
    return ERROR_INVALID_PARAMETER;

  status = ReadLdapConfig();
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d  Error to read ldap config: %d\n", __FUNCTION__, __LINE__, status));
    return CANT_READ_CONFIG_FROM_VARIABLE;
  }

  if (gBS->LocateProtocol (
             &gIniParserDxeProtocolGuid,
             NULL,
             (VOID **) &iniParserProtocol
             ) != EFI_SUCCESS)
    return CANT_LOCATE_INI_PARSER_PROTOCOL;

  status = StoreLdapConfigToDict(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    return CANT_SAVE_CONFIG_TO_DICTIONARY;

  return SUCCESS_TO_SET_CONFIG;
}
//------------------------------------------------------------------------------

