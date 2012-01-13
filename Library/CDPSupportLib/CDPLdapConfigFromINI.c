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
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/GlobalConfigDxe.h>
#include <Protocol/IniParserDxe.h>

#include <Library/CDPSupportLib/CDPInternal.h>

#include "CDPLdapConfig.h"

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

CHAR8 cdpLdapSectionName[] = "CDPLdapConfig";

static CHAR8 ldapPortKey[]       = "LdapPort";
static CHAR8 ldapServAdressKey[] = "LdapServerAddress";
static CHAR8 ldapServNameKey[]   = "LdapServerName";
static CHAR8 ldapBindDnKey[]     = "LdapBindDn";
static CHAR8 ldapBindPwKey[]     = "LdapBindPw";

static CHAR8 removeSettingStr[] = "\"\"";

//------------------------------------------------------------------------------
/*! \brief Read server name from dictionary and set */
/*! You have to call SaveCDPLdapConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
static
EFI_STATUS
SetServerNameFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CHAR8  *ldapServName8  = NULL;
  CHAR16 *ldapServName16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapServName8 = iniParserProtocol->GetString(dict, cdpLdapSectionName, ldapServNameKey);
  if (ldapServName8 != NULL) {
    LOG((EFI_D_ERROR, "ldapServName8: %a\n", ldapServName8));
    if (AsciiStrCmp(ldapServName8, removeSettingStr) == 0) {
      Status = SetCDPLdapServerName(L""); // Clear server name
    } else {
      ldapServName16 = AllocateZeroPool(AsciiStrLen(ldapServName8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (ldapServName16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(ldapServName8, ldapServName16);
        Status = SetCDPLdapServerName(ldapServName16);
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
/*! \brief Read server port from dictionary and set */
/*! You have to call SaveCDPLdapConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
static
EFI_STATUS
SetLdapPortFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  INT32 ldapPort = 0;
  EFI_STATUS Status = EFI_SUCCESS;

  Status = iniParserProtocol->GetInteger(dict, cdpLdapSectionName, ldapPortKey, &ldapPort);
  switch(Status) {
    case EFI_SUCCESS:
      if(ldapPort < 0) {
        Status = EFI_UNSUPPORTED;
      } else {
        Status = SetCDPLdapPort(ldapPort);
      }
      break;
    default:
      break;
  }

  return Status;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Read server IP address from dictionary and set */
/*! You have to call SaveCDPLdapConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
static
EFI_STATUS
SetServerIpAddressFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CHAR8 *ldapIpAddr8 = NULL;
  CHAR16 *ldapIpAddr16 = NULL;
  EFI_STATUS Status = EFI_SUCCESS;

  ldapIpAddr8 = iniParserProtocol->GetString(dict, cdpLdapSectionName, ldapServAdressKey);
  if (ldapIpAddr8 != NULL) {
    LOG((EFI_D_ERROR, "ldapIpAddr8: %a\n", ldapIpAddr8));
    if (AsciiStrCmp(ldapIpAddr8, removeSettingStr) == 0) {
      Status = SetCDPLdapServerAddr(L""); // Clear IP address
    } else {
      ldapIpAddr16 = AllocateZeroPool(AsciiStrLen(ldapIpAddr8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (ldapIpAddr16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(ldapIpAddr8, ldapIpAddr16);
        Status = SetCDPLdapServerAddr(ldapIpAddr16);
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
/*! \brief Read Bind DN from dictionary and set */
/*! You have to call SaveCDPLdapConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
static
EFI_STATUS
SetLdapBindDnFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CHAR8  *ldapBindDn8  = NULL;
  CHAR16 *ldapBindDn16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapBindDn8 = iniParserProtocol->GetString(dict, cdpLdapSectionName, ldapBindDnKey);
  if (ldapBindDn8 != NULL) {
    LOG((EFI_D_ERROR, "ldapBindDn8: %a\n", ldapBindDn8));
    if (AsciiStrCmp(ldapBindDn8, removeSettingStr) == 0) {
      Status = SetCDPLdapRootdn(L""); // Clear root dn
    } else {
      ldapBindDn16 = AllocateZeroPool(AsciiStrLen(ldapBindDn8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (ldapBindDn16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(ldapBindDn8, ldapBindDn16);
        Status = SetCDPLdapRootdn(ldapBindDn16);
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
/*! You have to call SaveCDPLdapConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
static
EFI_STATUS
SetLdapBindPwFromDictionary(
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CHAR8 *ldapBindPw8 = NULL;
  CHAR16 *ldapBindPw16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapBindPw8 = iniParserProtocol->GetString(dict, cdpLdapSectionName, ldapBindPwKey);
  if (ldapBindPw8 != NULL) {
    LOG((EFI_D_ERROR, "ldapBindPw8: %a\n", ldapBindPw8));
    if (AsciiStrCmp(ldapBindPw8, removeSettingStr) == 0) {
      Status = SetCDPLdapRootpw(L""); // Clear root pw
    } else {
      ldapBindPw16 = AllocateZeroPool(AsciiStrLen(ldapBindPw8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (ldapBindPw16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(ldapBindPw8, ldapBindPw16);
        Status = SetCDPLdapRootpw(ldapBindPw16);
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
/*! \brief Read config from dictionary and set */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
static
CONFIG_ERROR_T
SetSelfConfigFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status;

  status = ReadCDPLdapConfig();
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d  Error to read ldap config\n", __FUNCTION__, __LINE__));
    return CANT_READ_CONFIG_FROM_VARIABLE;
  }

  status = SetServerIpAddressFromDictionary(iniParserProtocol, dict);
  switch(status) {
  case EFI_SUCCESS:
  case EFI_NOT_FOUND:
    break;

  default:
    return UNSUPPORTED_KEY_VALUE;
  }

  status = SetLdapPortFromDictionary(iniParserProtocol, dict);
  switch(status) {
  case EFI_SUCCESS:
  case EFI_NOT_FOUND:
    break;

  default:
    return UNSUPPORTED_KEY_VALUE;
  }

  status = SetServerNameFromDictionary(iniParserProtocol, dict);
  switch(status) {
  case EFI_SUCCESS:
  case EFI_NOT_FOUND:
    break;

  default:
    return UNSUPPORTED_KEY_VALUE;
  }

  status = SetLdapBindDnFromDictionary(iniParserProtocol, dict);
  switch(status) {
  case EFI_SUCCESS:
  case EFI_NOT_FOUND:
    break;

  default:
    return UNSUPPORTED_KEY_VALUE;
  }

  status = SetLdapBindPwFromDictionary(iniParserProtocol, dict);
  switch(status) {
  case EFI_SUCCESS:
  case EFI_NOT_FOUND:
    break;

  default:
    return UNSUPPORTED_KEY_VALUE;
  }

  status = SaveCDPLdapConfig();
  switch(status) {
  case EFI_SUCCESS:
  case EFI_NOT_FOUND:
    break;

  default:
    return UNSUPPORTED_KEY_VALUE;
  }
  return SUCCESS_TO_SET_CONFIG;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Setup CDP LDAP config with config INI file */
/*! Read LDAP config from INI file and save to the variable. Use this function
    to config LDAP directly without using GlobalConfigDxe */
/*! \param[in] *filePath Path to the config file */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */  
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetCDPLdapConfigFromINIFile(
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

  status = SetSelfConfigFromDictionary(iniParserProtocol, dict);

  iniParserProtocol->DeleteIniDictionary(dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief CDPLdap config with INI dictionary */
/*! Register this function as a callback config method in the GlobalConfigDxe */
/*! \param[in] *dict A pointer to the INI dictionary */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetCDPLdapConfigFromDictionary (
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

  if (!iniParserProtocol->CheckSecPresent(dict, cdpLdapSectionName)) {
    return NO_CONFIG_SECTION;
  }

  status = SetSelfConfigFromDictionary(iniParserProtocol, dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveServerIpAddressToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
        CHAR8  *ldapServerAddr8  = NULL;
  const CHAR16 *ldapServerAddr16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapServerAddr16 = GetCDPLdapServerAddr();
  if (ldapServerAddr16 == NULL) {
    Status = iniParserProtocol->SetString(dict, cdpLdapSectionName,
                                  ldapServAdressKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(ldapServerAddr16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, cdpLdapSectionName, ldapServAdressKey, removeSettingStr);
  } else {
    ldapServerAddr8 = AllocateZeroPool(StrLen(ldapServerAddr16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (ldapServerAddr8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (ldapServerAddr16, ldapServerAddr8);
      Status = iniParserProtocol->SetString(dict, cdpLdapSectionName, ldapServAdressKey, ldapServerAddr8);
      FreePool(ldapServerAddr8);
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
SaveServerNameToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
        CHAR8  *ldapServerName8  = NULL;
  const CHAR16 *ldapServerName16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapServerName16 = GetCDPLdapServerName();
  if (ldapServerName16 == NULL) {
    Status = iniParserProtocol->SetString(dict, cdpLdapSectionName,
                                  ldapServNameKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(ldapServerName16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, cdpLdapSectionName,
                                  ldapServNameKey, removeSettingStr);
  } else {
    ldapServerName8 = AllocateZeroPool(StrLen(ldapServerName16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (ldapServerName8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (ldapServerName16, ldapServerName8);
      Status = iniParserProtocol->SetString(dict, cdpLdapSectionName, ldapServNameKey, ldapServerName8);
      FreePool(ldapServerName8);
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
SaveLdapPortToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS status = EFI_SUCCESS;
  status = iniParserProtocol->SetInteger(dict, cdpLdapSectionName,
                                ldapPortKey, GetCDPLdapServerPort());
  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a bind DN and store to the dictionary */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SaveLdapBindDnToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
        CHAR8  *ldapBindDn8  = NULL;
  const CHAR16 *ldapBindDn16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapBindDn16 = GetCDPLdapRootdn();
  if (ldapBindDn16 == NULL) {
    Status = iniParserProtocol->SetString(dict, cdpLdapSectionName,
                                  ldapBindDnKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(ldapBindDn16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, cdpLdapSectionName,
                                  ldapBindDnKey, removeSettingStr);
  } else {
    ldapBindDn8 = AllocateZeroPool(StrLen(ldapBindDn16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (ldapBindDn8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (ldapBindDn16, ldapBindDn8);
      Status = iniParserProtocol->SetString(dict, cdpLdapSectionName, ldapBindDnKey, ldapBindDn8);
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
  IN OUT dictionary *dict
)
{
        CHAR8  *ldapBindPw8  = NULL;
  const CHAR16 *ldapBindPw16 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  ldapBindPw16 = GetCDPLdapRootpw();
  if (ldapBindPw16 == NULL) {
    Status = iniParserProtocol->SetString(dict, cdpLdapSectionName,
                                  ldapBindPwKey, removeSettingStr);
    return Status;
  }

  if (StrCmp(ldapBindPw16, L"") == 0) {
    Status = iniParserProtocol->SetString(dict, cdpLdapSectionName,
                                  ldapBindPwKey, removeSettingStr);
  } else {
    ldapBindPw8 = AllocateZeroPool(StrLen(ldapBindPw16)*sizeof(CHAR8) + sizeof(CHAR8));
    if (ldapBindPw8 == NULL) {
      return EFI_OUT_OF_RESOURCES;
    } else {
      UnicodeStrToAsciiStr (ldapBindPw16, ldapBindPw8);
      Status = iniParserProtocol->SetString(dict, cdpLdapSectionName, ldapBindPwKey, ldapBindPw8);
      FreePool(ldapBindPw8);
    }
  }

  return Status;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
CONFIG_ERROR_T
StoreCDPLdapConfigToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict
)
{
  EFI_STATUS Status, retval = EFI_SUCCESS;

  Status = ReadCDPLdapConfig();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d  Error to read cdp ldap config\n", __FUNCTION__, __LINE__));
    return CANT_READ_CONFIG_FROM_VARIABLE;
  }

  Status = SaveServerIpAddressToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    retval = Status;

  Status = SaveServerNameToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    retval = Status;

  Status = SaveLdapPortToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    retval = Status;

  Status = SaveLdapBindDnToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    retval = Status;

  Status = SaveLdapBindPwToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    retval = Status;

  if (EFI_ERROR(retval))
    return CANT_SAVE_CONFIG_TO_DICTIONARY;

  return SUCCESS_TO_SET_CONFIG;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
DumpCDPLdapConfigToDictionary (
  IN OUT dictionary *dict
)
{
  CONFIG_ERROR_T Status;

  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;

  if (dict == NULL)
    return ERROR_INVALID_PARAMETER;

  if (gBS->LocateProtocol (
             &gIniParserDxeProtocolGuid,
             NULL,
             (VOID **) &iniParserProtocol
             ) != EFI_SUCCESS)
    return CANT_LOCATE_INI_PARSER_PROTOCOL;

  Status = StoreCDPLdapConfigToDictionary(iniParserProtocol, dict);

  return Status;
}
//------------------------------------------------------------------------------

