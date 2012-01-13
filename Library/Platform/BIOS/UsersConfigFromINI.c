/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/DebugLib.h>
#include <Library/Lib/Users.h>
#include <Protocol/GlobalConfigDxe.h>
#include <Protocol/IniParserDxe.h>

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

static CHAR8 UsersConfigSectionName[] = "UsersConfig";

static CHAR8 LoadUsersFromLDAPKey[] = "LoadUsersFromLdap";

STATIC
CONFIG_ERROR_T
DumpUserConfigToDictionary (
  IN dictionary *dict
);

//------------------------------------------------------------------------------
/*! \brief Read lock keyboard if AMT enabled flag and set */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Status of operation */
//------------------------------------------------------------------------------
static
EFI_STATUS
SetLoadUsersFromLDAPKeyFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status;
  UINT32 LoadUsersFromLDAPCfg = 0;

  Status = iniParserProtocol->GetInteger(dict, UsersConfigSectionName, LoadUsersFromLDAPKey, &LoadUsersFromLDAPCfg);
  if (!EFI_ERROR(Status)) {
    switch(LoadUsersFromLDAPCfg) {
      case 0:
        LOG((EFI_D_ERROR, "%a.%d DISABLED\n", __FUNCTION__, __LINE__));
        Status = SetIsLoadUsersFromLdapFlag(FALSE);
        break;
      case 1:
        LOG((EFI_D_ERROR, "%a.%d ENABLED\n", __FUNCTION__, __LINE__));
        Status = SetIsLoadUsersFromLdapFlag(TRUE);
        break;
      default:
        LOG((EFI_D_ERROR, "%a.%d UNSUPPORTED\n", __FUNCTION__, __LINE__));
        Status = EFI_UNSUPPORTED;
        break;
    }
  }

  return Status;
}
//-----------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read config from dictionary and set */
/*! \param[in] *iniParserProtocol A pointer to the IniParser
    \param[in] *dict A dictionary */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
static
CONFIG_ERROR_T
SetUsersConfigFromDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS status;

  status = SetLoadUsersFromLDAPKeyFromDictionary(iniParserProtocol, dict);
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return ERROR_OUT_OF_MEMORY;
  }

  // Configure is successful. Has to prevent reconfigure next time
  status = SetUsersConfigFirstTimeConfigured();
  switch(status) {
    case EFI_SUCCESS:
      break;
    case EFI_NOT_FOUND:
      return NO_CONFIG_KEY;
    default:
      return ERROR_OUT_OF_MEMORY;
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief UsersConfig config with INI dictionary */
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

  status = SetUsersConfigFromDictionary(iniParserProtocol, dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief UsersConfig config with config INI file */
/*! Read UsersConfig config from INI file and save to the variable. Use this function
    to config UsersConfig directly without using GlobalConfigDxe */
/*! \param[in] *filePath Path to the config file */
/*! \return Code of operation. See CONFIG_ERROR_T enum for details */
//------------------------------------------------------------------------------
CONFIG_ERROR_T
SetUsersConfigFromINIFile (
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

  status = SetUsersConfigFromDictionary(iniParserProtocol, dict);

  iniParserProtocol->DeleteIniDictionary(dict);

  return status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
StoreUserConfigToDict (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;
  Status = iniParserProtocol->SetBoolean(dict, UsersConfigSectionName,
                                LoadUsersFromLDAPKey, IsLoadUsersFromLdap());
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a dictionary with the user config */
//------------------------------------------------------------------------------
STATIC
CONFIG_ERROR_T
DumpUserConfigToDictionary (
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;
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

  Status = StoreUserConfigToDict(iniParserProtocol, dict);
  if (EFI_ERROR(Status))
    return CANT_SAVE_CONFIG_TO_DICTIONARY;

  return SUCCESS_TO_SET_CONFIG;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
EFI_STATUS
InitializeUsersConfig (
  VOID
  )
{
  EFI_STATUS	Status;
  GLOBAL_CONFIG_PROTOCOL *pGlobalConfigProtocol = NULL;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  //
  // Set UsersConfig flags from INI file
  // Don't check a result - if error, the config stays empty
  if(IsNeedToUsersConfigFirstTime() == TRUE) {
    CHAR8 Fname[255];
    AsciiSPrint(Fname, sizeof(Fname), "fv:%g", PcdGetPtr(PcdUsersConfigFile));
    LOG((EFI_D_ERROR, "PcdUsersConfigFile: %a \n", Fname));
    SetUsersConfigFromINIFile(Fname);
  }

  Status = gBS->LocateProtocol (
           &gGlobalConfigProtocolGuid,
           NULL,
           (VOID **) &pGlobalConfigProtocol
           );
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d: Status = 0x%x\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Status = pGlobalConfigProtocol->AddConfig(UsersConfigSectionName,
    SetConfigFromDictionary, DumpUserConfigToDictionary);

  LOG((EFI_D_ERROR, "%a.%d:  Status = 0x%x\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

