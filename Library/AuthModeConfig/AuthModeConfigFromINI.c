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

#include <Library/AuthModeConfig/AuthModeConfig.h>
#include <Library/AuthModeConfig/AuthModeConfigInternal.h>

#include <Protocol/GlobalConfigDxe.h>
#include <Protocol/IniParserDxe.h>

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

STATIC CHAR8 authModeSectionName[] = "AuthModeConfig";

STATIC CHAR8 authModeKey[]          = "AuthMode";
STATIC CHAR8 useLocalKey[]          = "UseLocal";
STATIC CHAR8 localCnKey[]           = "Local_CN";
STATIC CHAR8 localCnValueKey[]      = "Local_CN_val";
STATIC CHAR8 localOuKey[]           = "Local_OU";
STATIC CHAR8 localOuValueKey[]      = "Local_OU_val";
STATIC CHAR8 localSubjectKey[]      = "Local_SUBJECT";
STATIC CHAR8 localSubjectValueKey[] = "Local_SUBJECT_val";
STATIC CHAR8 useLdapKey[]           = "UseLDAP";

STATIC CHAR8 removeSettingStr[] = "\"\"";

STATIC CHAR8 authModeNormalStr8[] = "NORMAL"; // Setting string in the INI (NORMAL)
STATIC CHAR8 authModeGuestStr8[]  = "GUEST";   // Setting string in the INI (GUEST)

//------------------------------------------------------------------------------
/*! \brief Read LocalUsage Status and set */
/*! You have to call SaveAuthModeConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetLocalUsageFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  BOOLEAN useLocal = FALSE;

  Status = iniParserProtocol->GetBoolean(dict, authModeSectionName, useLocalKey, &useLocal);
  if (!EFI_ERROR(Status)) {
    if (TRUE == useLocal)
      SetLocalUsageStatus(USE_SETTING);
    else
      SetLocalUsageStatus(DONT_USE_SETTING);
  }

  return Status;
}

STATIC
EFI_STATUS
DumpLocalUsageToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;
  Status = iniParserProtocol->SetBoolean(dict, authModeSectionName, useLocalKey, IsUseLocalGuestLogin());
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read LdapAuthUsage Status and set */
/*! You have to call SaveAuthModeConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetLdapAuthUsageFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  BOOLEAN useLdap = FALSE;

  Status = iniParserProtocol->GetBoolean(dict, authModeSectionName, useLdapKey, &useLdap);
  if (!EFI_ERROR(Status)) {
    if (TRUE == useLdap)
      SetLdapUsageStatus(USE_SETTING);
    else
      SetLdapUsageStatus(DONT_USE_SETTING);
  }

  return Status;
}

STATIC
EFI_STATUS
DumpLdapAuthUsageToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;
  Status = iniParserProtocol->SetBoolean(dict, authModeSectionName, useLdapKey, IsUseLdapGuestLogin());
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read LocalCN flag, value and set */
/*! You have to call SaveAuthModeConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetLocalCNFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  BOOLEAN localCNUsage = FALSE;

  CHAR8  *localCN8  = NULL;
  CHAR16 *localCN16 = NULL;

  Status = iniParserProtocol->GetBoolean(dict, authModeSectionName, localCnKey, &localCNUsage);
  if (!EFI_ERROR(Status)) {
    if (TRUE == localCNUsage) {
      LOG((EFI_D_ERROR, "localCNUsage = TRUE\n"));
      SetTypeOfComparison(CN_CMP);
    } else {
      LOG((EFI_D_ERROR, "localCNUsage = FASLE\n"));
      ClearTypeOfComparison(CN_CMP);
    }
  }

  localCN8 = iniParserProtocol->GetString(dict, authModeSectionName, localCnValueKey);
  if (localCN8 != NULL) {
      LOG((EFI_D_ERROR, "localCN8: %a\n", localCN8));
    if (AsciiStrCmp(localCN8, removeSettingStr) == 0) {
      Status = SetCmpDataByType(CN_CMP, L""); // Clear local CN
    } else {
      localCN16 = AllocateZeroPool(AsciiStrLen(localCN8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (localCN16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(localCN8, localCN16);
        Status = SetCmpDataByType(CN_CMP, localCN16);
        FreePool(localCN16);
      }
    }
  } else {
    LOG((EFI_D_ERROR, "localCN8 is NULL\n"));
  }
  return Status;
}

STATIC
EFI_STATUS
DumpLocalCNToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  CHAR8  *localCN8  = NULL;
  const CHAR16 *localCN16 = NULL;

  Status = iniParserProtocol->SetBoolean(dict, authModeSectionName, localCnKey, IsTypeOfComparison(CN_CMP));
  if (EFI_ERROR(Status)) {
    return Status;
  }

  localCN16 = GetCmpDataByType(CN_CMP);  
  if (localCN16 != NULL) {
    if (StrCmp(localCN16, L"") == 0) {
      Status = iniParserProtocol->SetString(dict, authModeSectionName, localCnValueKey, removeSettingStr);
    } else {
      localCN8 = AllocateZeroPool(StrLen(localCN16)*sizeof(CHAR8) + sizeof(CHAR8));
      if (localCN8 == NULL) {
        return EFI_OUT_OF_RESOURCES;
      } else {
        UnicodeStrToAsciiStr (localCN16, localCN8);
        Status = iniParserProtocol->SetString(dict, authModeSectionName, localCnValueKey, localCN8);
        FreePool(localCN8);
      }
    }
  } else {
    Status = iniParserProtocol->SetString(dict, authModeSectionName, localCnValueKey, removeSettingStr);
  }
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read LocalOU flag, value and set */
/*! You have to call SaveAuthModeConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetLocalOUFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  BOOLEAN localOUusage = FALSE;

  CHAR8  *localOU8  = NULL;
  CHAR16 *localOU16 = NULL;

  Status = iniParserProtocol->GetBoolean(dict, authModeSectionName, localOuKey, &localOUusage);
  if (!EFI_ERROR(Status)) {
    if (TRUE == localOUusage)
      SetTypeOfComparison(OU_CMP);
    else
      ClearTypeOfComparison(OU_CMP);
  }

  localOU8 = iniParserProtocol->GetString(dict, authModeSectionName, localOuValueKey);
  if (localOU8 != NULL) {
      LOG((EFI_D_ERROR, "localOU8: %a\n", localOU8));
    if (AsciiStrCmp(localOU8, removeSettingStr) == 0) {
      Status = SetCmpDataByType(OU_CMP, L""); // Clear local OU
    } else {
      localOU16 = AllocateZeroPool(AsciiStrLen(localOU8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (localOU16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(localOU8, localOU16);
        Status = SetCmpDataByType(OU_CMP, localOU16);
        FreePool(localOU16);
      }
    }
  } else {
    LOG((EFI_D_ERROR, "localOU8 is NULL\n"));
  }
  return Status;
}

STATIC
EFI_STATUS
DumpLocalOUToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  CHAR8  *localOU8  = NULL;
  const CHAR16 *localOU16 = NULL;

  Status = iniParserProtocol->SetBoolean(dict, authModeSectionName, localOuKey, IsTypeOfComparison(OU_CMP));
  if (EFI_ERROR(Status)) {
    return Status;
  }

  localOU16 = GetCmpDataByType(OU_CMP);  
  if (localOU16 != NULL) {
    if (StrCmp(localOU16, L"") == 0) {
      Status = iniParserProtocol->SetString(dict, authModeSectionName, localOuValueKey, removeSettingStr);
    } else {
      localOU8 = AllocateZeroPool(StrLen(localOU16)*sizeof(CHAR8) + sizeof(CHAR8));
      if (localOU8 == NULL) {
        return EFI_OUT_OF_RESOURCES;
      } else {
        UnicodeStrToAsciiStr (localOU16, localOU8);
        Status = iniParserProtocol->SetString(dict, authModeSectionName, localOuValueKey, localOU8);
        FreePool(localOU8);
      }
    }
  } else {
    Status = iniParserProtocol->SetString(dict, authModeSectionName, localOuValueKey, removeSettingStr);
  }
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read LocalSUBJECT flag, value and set */
/*! You have to call SaveAuthModeConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetLocalSubjectFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  BOOLEAN localSubjectUsage = FALSE;

  CHAR8  *localSubject8  = NULL;
  CHAR16 *localSubject16 = NULL;

  Status = iniParserProtocol->GetBoolean(dict, authModeSectionName, localSubjectKey, &localSubjectUsage);
  if (!EFI_ERROR(Status)) {
    if (TRUE == localSubjectUsage)
      SetTypeOfComparison(SUBJECT_CMP);
    else
      ClearTypeOfComparison(SUBJECT_CMP);
  }

  localSubject8 = iniParserProtocol->GetString(dict, authModeSectionName, localSubjectValueKey);
  if (localSubject8 != NULL) {
      LOG((EFI_D_ERROR, "localSubject8: %a\n", localSubject8));
    if (AsciiStrCmp(localSubject8, removeSettingStr) == 0) {
      Status = SetCmpDataByType(SUBJECT_CMP, L""); // Clear local SUBJECT
    } else {
      localSubject16 = AllocateZeroPool(AsciiStrLen(localSubject8)*sizeof(CHAR16) + sizeof(CHAR16));
      if (localSubject16 == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
      } else {
        AsciiStrToUnicodeStr(localSubject8, localSubject16);
        Status = SetCmpDataByType(SUBJECT_CMP, localSubject16);
        FreePool(localSubject16);
      }
    }
  } else {
    LOG((EFI_D_ERROR, "localSubject8 is NULL\n"));
  }
  return Status;
}

STATIC
EFI_STATUS
DumpLocalSubjectToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  CHAR8  *localSubject8  = NULL;
  const CHAR16 *localSubject16 = NULL;

  
  Status = iniParserProtocol->SetBoolean(dict, authModeSectionName, localSubjectKey, IsTypeOfComparison(SUBJECT_CMP));
  if (EFI_ERROR(Status)) {
    return Status;
  }

  localSubject16 = GetCmpDataByType(SUBJECT_CMP);  
  if (localSubject16 != NULL) {
    if (StrCmp(localSubject16, L"") == 0) {
      Status = iniParserProtocol->SetString(dict, authModeSectionName, localSubjectValueKey, removeSettingStr);
    } else {
      localSubject8 = AllocateZeroPool(StrLen(localSubject16)*sizeof(CHAR8) + sizeof(CHAR8));
      if (localSubject8 == NULL) {
        return EFI_OUT_OF_RESOURCES;
      } else {
        UnicodeStrToAsciiStr (localSubject16, localSubject8);
        Status = iniParserProtocol->SetString(dict, authModeSectionName, localSubjectValueKey, localSubject8);
        FreePool(localSubject8);
      }
    }
  } else {
    Status = iniParserProtocol->SetString(dict, authModeSectionName, localSubjectValueKey, removeSettingStr);
  }
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read GUEST parameters from dictionary and set*/
/*! You have to call SaveAuthModeConfig() to confirm changing of the setting */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
SetAuthModeFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  CHAR8 *authMode8 = NULL;
  EFI_STATUS status = EFI_SUCCESS;

  authMode8 = iniParserProtocol->GetString(dict, authModeSectionName, authModeKey);
  if (authMode8 != NULL) {
    LOG((EFI_D_ERROR, "authMode8: %a\n", authMode8));
    if (AsciiStrCmp(authMode8, authModeNormalStr8) == 0) {
      status = SetAuthMode(DEFAULT_AUTH_MODE);
    } else if (AsciiStrCmp(authMode8, authModeGuestStr8) == 0) {
      status = SetAuthMode(GUEST_AUTH_MODE);
      if (EFI_ERROR(status)) {
        return status;
      }

      status = SetLdapAuthUsageFromDictionary(iniParserProtocol, dict);
      if (EFI_ERROR(status)) {
        return status;
      }
      status = SetLocalUsageFromDictionary(iniParserProtocol, dict);
      if (EFI_ERROR(status)) {
        return status;
      }
      status = SetLocalCNFromDictionary(iniParserProtocol, dict);
      if (EFI_ERROR(status)) {
        return status;
      }
      status = SetLocalOUFromDictionary(iniParserProtocol, dict);
      if (EFI_ERROR(status)) {
        return status;
      }
      status = SetLocalSubjectFromDictionary(iniParserProtocol, dict);
      if (EFI_ERROR(status)) {
        return status;
      }
    } else {
      return EFI_INVALID_PARAMETER;
    }
  } 

  return status;
}

STATIC
EFI_STATUS
DumpAuthModeToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status = EFI_SUCCESS, retval = EFI_SUCCESS;

  switch(GetAuthMode()) {
    case DEFAULT_AUTH_MODE:
      status = iniParserProtocol->SetString(dict, authModeSectionName, authModeKey, authModeNormalStr8);
      break;

    case GUEST_AUTH_MODE:
      status = iniParserProtocol->SetString(dict, authModeSectionName, authModeKey, authModeGuestStr8);
      break;

    default:
      status = EFI_UNSUPPORTED;
      break;
  }
  if (EFI_ERROR(status))
    retval = status;

  status = DumpLdapAuthUsageToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  status = DumpLocalUsageToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  status = DumpLocalCNToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  status = DumpLocalOUToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  status = DumpLocalSubjectToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    retval = status;

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read config from dictionary and set */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
  /*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
STATIC
CONFIG_ERROR_T
SetAuthModeConfigFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status;

  status = ReadAuthModeConfig();
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d  Error to read auth mode config: %d\n", __FUNCTION__, __LINE__, status));
    return CANT_READ_CONFIG_FROM_VARIABLE;
  }

  status = SetAuthModeFromDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status)) {
    switch(status) {
    case EFI_UNSUPPORTED:
      return UNSUPPORTED_SETTING_COMBINATION;
    case EFI_INVALID_PARAMETER:
      return UNSUPPORTED_KEY_VALUE;
    default:
      return NO_CONFIG_KEY;
    }
  }

  status = SaveAuthModeConfig();
  switch(status) {
    case EFI_UNSUPPORTED:
      return UNSUPPORTED_SETTING_COMBINATION;
    case EFI_INVALID_PARAMETER:
      return UNSUPPORTED_KEY_VALUE;
    case EFI_SUCCESS:
      return SUCCESS_TO_SET_CONFIG;
    default:
      return CANT_SAVE_CONFIG_TO_VARIABLE;
  }
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
STATIC
CONFIG_ERROR_T
DumpAuthModeConfigToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status = EFI_SUCCESS;

  status = ReadAuthModeConfig();
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d  Error to read auth mode config: %d\n", __FUNCTION__, __LINE__, status));
    return CANT_READ_CONFIG_FROM_VARIABLE;
  }

  status = DumpAuthModeToDictionary(iniParserProtocol, dict);
  if (EFI_ERROR(status))
    return CANT_SAVE_CONFIG_TO_DICTIONARY;

  return SUCCESS_TO_SET_CONFIG;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Setup auth mode config with config INI file */
/*! Read auth mode config from INI file and save to the variable. Use this function
    to config AuthMode directly without using GlobalConfigDxe */
/*! \param[in] *filePath Path to the config file */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetAuthConfigFromINIFile (
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

  status = SetAuthModeConfigFromDictionary(iniParserProtocol, dict);

  iniParserProtocol->DeleteIniDictionary(dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Setup auth mode config with config data */
/*! Read auth mode config from config data and save to the variable. Use this function
    to config AuthMode directly without using GlobalConfigDxe */
/*! \param[in] *configData Path to the config file
    \param[in] dataLen  A length of data */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetAuthConfigFromData (
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

  status = SetAuthModeConfigFromDictionary(iniParserProtocol, dict);

  iniParserProtocol->DeleteIniDictionary(dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Setup AuthModeConfig with INI dictionary */
/*! Register this function as a callback config method in the GlobalConfigDxe */
/*! \param[in] *dict A pointer to the INI dictionary */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetAuthConfigFromDictionary (
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
  if (!iniParserProtocol->CheckSecPresent(dict, authModeSectionName)) {
    return NO_CONFIG_SECTION;
  }

  status = SetAuthModeConfigFromDictionary(iniParserProtocol, dict);

  return status;
}

CONFIG_ERROR_T
DumpAuthConfigToDictionary (
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
             ) != EFI_SUCCESS)
    return CANT_LOCATE_INI_PARSER_PROTOCOL;

  status = DumpAuthModeConfigToDictionary(iniParserProtocol, dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief AuthMode Constructor */
/*! The task of this constructor is to register AuthModeConfig in the
    GlobalConfigDxe */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
AuthModeConstructor (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
)
{
  EFI_STATUS status = EFI_ABORTED;
  GLOBAL_CONFIG_PROTOCOL *pGlobalConfigProtocol = NULL;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  status = gBS->LocateProtocol (
           &gGlobalConfigProtocolGuid,
           NULL,
           (VOID **) &pGlobalConfigProtocol
           );
  if (EFI_ERROR(status)) {
    LOG((EFI_D_ERROR, "%a.%d: status = 0x%x\n", __FUNCTION__, __LINE__, status));
    return status;
  }

  status = pGlobalConfigProtocol->AddConfig(authModeSectionName, SetAuthConfigFromDictionary, DumpAuthConfigToDictionary);

  LOG((EFI_D_ERROR, "%a.%d:  status: 0x%x\n", __FUNCTION__, __LINE__, status));

  return status;
}
//------------------------------------------------------------------------------

