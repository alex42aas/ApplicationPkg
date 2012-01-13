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
#include <Library/UefiRuntimeServicesTableLib.h>

extern EFI_GUID gUsersConfigVarGuid;

STATIC USER_CONFIG_DATA currentUserConfig = {USER_CONFIG_VERSION, 0};

//------------------------------------------------------------------------------
/*! \brief Read Users config from variable */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
ReadUsersConfig (
  USER_CONFIG_DATA *usersConfig
)
{
  EFI_STATUS Status     = EFI_SUCCESS;
  UINTN      Size       = 0;

  if (NULL == usersConfig) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gRT->GetVariable(
                  USR_CONFIG_VAR_NAME,
                  &gUsersConfigVarGuid,
                  NULL,
                  &Size,
                  NULL
                  );
  DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  if (Size != sizeof(*usersConfig)) {
    return EFI_ABORTED;
  }

  Status = gRT->GetVariable(
                  USR_CONFIG_VAR_NAME,
                  &gUsersConfigVarGuid,
                  NULL,
                  &Size,
                  usersConfig
                  );
  DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
  
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Write Users config to variable */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
WriteUsersConfig (
  IN USER_CONFIG_DATA *usersConfig
)
{
  EFI_STATUS Status;

  if (NULL == usersConfig) {
    return EFI_INVALID_PARAMETER;
  }
  
  Status = gRT->SetVariable(
    USR_CONFIG_VAR_NAME, 
    &gUsersConfigVarGuid, 
    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS, 
    sizeof(*usersConfig), 
    usersConfig);
  DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set a setting UsersFromLdap */
/*! param[in] isLoadFromLdap TRUE if load users from LDAP, FALSE otherwise */
//------------------------------------------------------------------------------
EFI_STATUS
SetIsLoadUsersFromLdapFlag (
  BOOLEAN isLoadFromLdap
)
{
  USER_CONFIG_DATA userConfig = {USER_CONFIG_VERSION, 0};

  EFI_STATUS Status = EFI_SUCCESS;

  Status = ReadUsersConfig(&userConfig);
  DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  if (FALSE == isLoadFromLdap) {
    userConfig.flags &= ~((UINTN)(USERS_LIST_FROM_LDAP));
  } else {
    userConfig.flags |= USERS_LIST_FROM_LDAP;
  }

  Status = WriteUsersConfig(&userConfig);
  DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a UsersFromLdap flag */
/*! \retval TRUE If users list has to be get from ldap server
    \retval FALSE If no need to get users from ldap server */
//------------------------------------------------------------------------------
BOOLEAN
IsLoadUsersFromLdap (
  VOID
)
{
  USER_CONFIG_DATA userConfig = {USER_CONFIG_VERSION, 0};

  EFI_STATUS Status         = EFI_SUCCESS;
  BOOLEAN    isLoadFromLdap = FALSE;

  Status = ReadUsersConfig(&userConfig);
  if (!EFI_ERROR(Status)) {
    isLoadFromLdap = (BOOLEAN)(userConfig.flags & USERS_LIST_FROM_LDAP);
  }
  return isLoadFromLdap;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set Users Config already configured flag */
//------------------------------------------------------------------------------
EFI_STATUS
SetUsersConfigFirstTimeConfigured (
  VOID
)
{
  USER_CONFIG_DATA userConfig = {USER_CONFIG_VERSION, 0};

  EFI_STATUS Status = EFI_SUCCESS;

  Status = ReadUsersConfig(&userConfig);
  DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  userConfig.flags |= USERS_SETUP_FLAG_STATUS;
  Status = WriteUsersConfig(&userConfig);
  DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}
//-----------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check if config has been configured at least one time */
/*! \return TRUE if UsersConfig hasn't never been configured from INI file, 
            FALSE otherwise */
//------------------------------------------------------------------------------
BOOLEAN
IsNeedToUsersConfigFirstTime (
  VOID
)
{
  USER_CONFIG_DATA userConfig = {USER_CONFIG_VERSION, 0};
  EFI_STATUS Status;

  Status = ReadUsersConfig(&userConfig);
  if (EFI_ERROR(Status))
    return TRUE;

  if (userConfig.flags & USERS_SETUP_FLAG_STATUS)
    return FALSE;
  else
    return TRUE;
}
//------------------------------------------------------------------------------
