/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <LdapCommon.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/CommonUtils.h>
#include <Library/BIOSLib/CertificatesControl.h>

#include <Protocol/LdapAuthDxe.h>
#include <Protocol/LdapConfigOp.h>

#include <stdlib.h>

#include "LdapAuthDxeInternal.h"

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

static
EFI_STATUS
MakeAuthUserTokenInfo (
  IN  ldapAttributeList_t       *certificateList,
  IN  CHAR8                     *userName,
  IN  CHAR8                     *userDN,
  IN  USER_AUTH_PERMISSION      permissions,
  OUT LDAP_AUTH_TOKEN_USER_INFO *userInfo
);

static
LDAP_USER_AUTH_DB*
GetUsersFromUnionGroups (
  IN ldapAttributeList_t *unionGroupDNs,
  OUT UINTN *retval
);

static
LDAP_USER_AUTH_DB*
GetUsersFromSecureGroups (
  IN ldapAttributeList_t *SecureGroupDNs,
  OUT UINTN *retval
);

static
LDAP_USER_AUTH_DB*
GetUsersByDnList (
  IN ldapAttributeList_t *listOfUserDNs,
  IN USER_AUTH_PERMISSION permission,
  OUT UINTN *retval
);

static
EFI_STATUS
DeepCopyLdapAuthTokenInfo (
  IN LDAP_AUTH_TOKEN_USER_INFO *source,
  OUT LDAP_AUTH_TOKEN_USER_INFO *destination
);


//------------------------------------------------------------------------------
/*! \brief Is LdapAuthTokenInfo empty */
/*! LdapAuthTokenInfo is empy if one of data fields is NULL */
//------------------------------------------------------------------------------
BOOLEAN
isLdapAuthTokenInfoEmpty (
  LDAP_AUTH_TOKEN_USER_INFO *info
)
{
  if (info == NULL)
    return TRUE;

  if (info->certData == NULL || info->certDataLen == 0 || 
      info->userDN == NULL || info->userName == NULL)
    return TRUE;

  return FALSE;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief */
/*! LDAP_AUTH_TOKEN_USER_INFOs are the same if userDNs and permissions are the same */
/*! \retval 0 Objects are the same */
//------------------------------------------------------------------------------
CHAR8
CompareLdapAuthTokenInfo (
  IN LDAP_AUTH_TOKEN_USER_INFO *info_1,
  IN LDAP_AUTH_TOKEN_USER_INFO *info_2
)
{
  if (info_1 == NULL || info_2 == NULL)
    return -1;

  LOG((EFI_D_ERROR, "%a.%d: info_1: %a, perm: %d\n", 
    __FUNCTION__, __LINE__, info_1->userDN, info_1->permission));
  LOG((EFI_D_ERROR, "%a.%d: info_2: %a, perm: %d\n", 
    __FUNCTION__, __LINE__, info_2->userDN, info_2->permission));

  if (AsciiStrCmp(info_1->userDN, info_2->userDN) == 0) {

    if (info_1->permission == info_2->permission)
      return 0;

    switch(info_1->permission) {
      case ALLOW_TO_LOGIN_ADMIN_FULL_REMOTE:
        return 1;
      case ALLOW_TO_LOGIN_ADMIN_FULL:
        if (info_2->permission == ALLOW_TO_LOGIN_ADMIN_FULL_REMOTE)
          return -1;
        else
          return 1;
      case ALLOW_TO_LOGIN_ADMIN_AUDIT_REMOTE:
        if (info_2->permission == ALLOW_TO_LOGIN_ADMIN_FULL_REMOTE ||
            info_2->permission == ALLOW_TO_LOGIN_ADMIN_FULL)
          return -1;
        else
          return 1;
      case ALLOW_TO_LOGIN_ADMIN_AUDIT:
        if (info_2->permission == ALLOW_TO_LOGIN_ADMIN_FULL_REMOTE ||
            info_2->permission == ALLOW_TO_LOGIN_ADMIN_FULL ||
            info_2->permission == ALLOW_TO_LOGIN_ADMIN_AUDIT_REMOTE)
          return -1;
        else
          return 1;
      case ALLOW_TO_LOGIN_USER_REMOTE:
        if (info_2->permission == ALLOW_TO_LOGIN_ADMIN_FULL_REMOTE ||
            info_2->permission == ALLOW_TO_LOGIN_ADMIN_FULL ||
            info_2->permission == ALLOW_TO_LOGIN_ADMIN_AUDIT_REMOTE ||
            info_2->permission == ALLOW_TO_LOGIN_ADMIN_AUDIT)
          return -1;
        else
          return 1;
      case ALLOW_TO_LOGIN_USER:
        if (info_2->permission == ALLOW_TO_LOGIN_ADMIN_FULL_REMOTE ||
            info_2->permission == ALLOW_TO_LOGIN_ADMIN_FULL ||
            info_2->permission == ALLOW_TO_LOGIN_ADMIN_AUDIT_REMOTE ||
            info_2->permission == ALLOW_TO_LOGIN_ADMIN_AUDIT ||
            info_2->permission == ALLOW_TO_LOGIN_USER_REMOTE)
          return -1;
        else
          return 1;
      case ALLOW_TO_LOGIN_GUEST:
        if (info_2->permission == ALLOW_TO_LOGIN_ADMIN_FULL_REMOTE ||
            info_2->permission == ALLOW_TO_LOGIN_ADMIN_FULL ||
            info_2->permission == ALLOW_TO_LOGIN_ADMIN_AUDIT_REMOTE ||
            info_2->permission == ALLOW_TO_LOGIN_ADMIN_AUDIT ||
            info_2->permission == ALLOW_TO_LOGIN_USER)
          return -1;
        else
          return 1;
      default:
        break;
    }
  } else {
    return 2;
  }

  return 2;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Insert LdapAuthTokenInfo */
/*! This method doesn't change size of DB. */
//------------------------------------------------------------------------------
EFI_STATUS
InsertLdapAuthTokenInfo (
  IN LDAP_USER_AUTH_DB *ldapAuthDB,
  IN LDAP_AUTH_TOKEN_USER_INFO *infoToInsert
)
{
  UINTN count = 0;
  CHAR8 cmpResult = 0;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if(infoToInsert == NULL)
    return EFI_INVALID_PARAMETER;

  for(count = 0; count < ldapAuthDB->userCount; count++) {
    if(isLdapAuthTokenInfoEmpty(&ldapAuthDB->ldapAuthUserList[count]) == TRUE) {
      DeepCopyLdapAuthTokenInfo(infoToInsert, &ldapAuthDB->ldapAuthUserList[count]);
      LOG((EFI_D_ERROR, "%a.%d: Insert info\n", __FUNCTION__, __LINE__));
      return EFI_SUCCESS;
    }
    cmpResult = CompareLdapAuthTokenInfo(infoToInsert, &ldapAuthDB->ldapAuthUserList[count]);
    if(1 == cmpResult) {
      DeepCopyLdapAuthTokenInfo(infoToInsert, &ldapAuthDB->ldapAuthUserList[count]);
      LOG((EFI_D_ERROR, "%a.%d: Overwrite info\n", __FUNCTION__, __LINE__));
      return EFI_SUCCESS;
    } else if (-1 == cmpResult || 0 == cmpResult) {
      break;
    }
  }

  LOG((EFI_D_ERROR, "%a.%d: No need to insert\n", __FUNCTION__, __LINE__));

  return EFI_ABORTED;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Deep copy of LdapAuthTokenInfo */
/*! Copy all data objects, not only pointers */
//------------------------------------------------------------------------------
EFI_STATUS
DeepCopyLdapAuthTokenInfo (
  IN LDAP_AUTH_TOKEN_USER_INFO *source,
  OUT LDAP_AUTH_TOKEN_USER_INFO *destination
)
{
  if (destination == NULL || source == NULL)
    return EFI_INVALID_PARAMETER;

  if (source->userDN != NULL) {
    destination->userDN = AllocateCopyPool(AsciiStrSize(source->userDN), source->userDN);
  }
  if (source->userName != NULL) {
    destination->userName = AllocateCopyPool(AsciiStrSize(source->userName), source->userName);
  }
  if (source->certData != NULL ) {
    destination->certData = AllocateCopyPool(source->certDataLen, source->certData);
    destination->certDataLen = source->certDataLen;
  }
  destination->permission = source->permission;

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Deep copy userDB to other userDB */
/*! Copy all data objects, not only pointers */
//------------------------------------------------------------------------------
EFI_STATUS
DeepCopyAuthDB (
  IN LDAP_USER_AUTH_DB *source,
  OUT LDAP_USER_AUTH_DB *destination
)
{
  UINTN infoCount = 0;

  if (NULL == destination || source == NULL)
    return EFI_INVALID_PARAMETER;
  if (0 == source->userCount || NULL == source->ldapAuthUserList ||
    NULL == destination->ldapAuthUserList)
    return EFI_INVALID_PARAMETER;

  for(infoCount = 0; infoCount < source->userCount; infoCount++) {
    if (&destination->ldapAuthUserList[infoCount] != NULL) {
      DeepCopyLdapAuthTokenInfo(&source->ldapAuthUserList[infoCount], 
        &destination->ldapAuthUserList[infoCount]);
    } else {
      return EFI_ABORTED;
    }
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Append userDB to the other userDB */
/*! Destination userDB will be enlarge if it necessary */
//------------------------------------------------------------------------------
EFI_STATUS
AppendUserAuthDB (
  LDAP_USER_AUTH_DB *destination,
  LDAP_USER_AUTH_DB *source
)
{
  UINTN totalCount = 0, count = 0;

  LDAP_USER_AUTH_DB temp;
  LDAP_AUTH_TOKEN_USER_INFO *startOfSource;

  LOG((EFI_D_ERROR, "%a.%d \n", __FUNCTION__, __LINE__));

  if (NULL == destination || NULL == source) {
    LOG((EFI_D_ERROR, "%a.%d Error \n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (0 == source->userCount || NULL == source->ldapAuthUserList) {
    LOG((EFI_D_ERROR, "%a.%d Error \n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  if (NULL == destination->ldapAuthUserList) {
    // Just copy source to destination
    destination->ldapAuthUserList = AllocateZeroPool(source->userCount*sizeof(LDAP_AUTH_TOKEN_USER_INFO));
    if (destination->ldapAuthUserList == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    if (EFI_ERROR(DeepCopyAuthDB(source, destination))) {
      FreePool(destination->ldapAuthUserList);
      LOG((EFI_D_ERROR, "%a.%d Error \n", __FUNCTION__, __LINE__));
      return EFI_ABORTED;
    }
    destination->userCount = source->userCount;
  }else {
    // Need to append source to destination
    temp.userCount = destination->userCount + source->userCount;

    temp.ldapAuthUserList = AllocateZeroPool(temp.userCount*sizeof(LDAP_AUTH_TOKEN_USER_INFO));
    if (temp.ldapAuthUserList == NULL)
      return EFI_OUT_OF_RESOURCES;

    // Copy destination to temp
    DeepCopyAuthDB(destination, &temp);
    totalCount += destination->userCount;

    startOfSource = source->ldapAuthUserList;

    for (count = 0; count < source->userCount; count++) {
      if (InsertLdapAuthTokenInfo(&temp, startOfSource) == EFI_SUCCESS)
        totalCount++;
      startOfSource++;
    }

    FreeTokenUserDBInternal(destination);

    destination->ldapAuthUserList = temp.ldapAuthUserList;
    destination->userCount = totalCount;
  }

  LOG((EFI_D_ERROR, "%a.%d totalCount: %d\n", __FUNCTION__, __LINE__, destination->userCount));

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Get users from Workstation groups */
/*! \param[in] *pcGroupDNs A list of workstation's groups
    \param[out] *retval Status of operation */
//------------------------------------------------------------------------------
LDAP_USER_AUTH_DB*
GetUsersFromWorkstationGroups (
  IN ldapAttributeList_t *pcGroupDNs,
  OUT UINTN *retval
)
{
  UINTN pcGroupCount   = 0;                // Count of workstation's groups

  ldapAttributeList_t unionGroupList = {0, NULL};
  LDAP_USER_AUTH_DB   *totalAuthDB   = NULL;

  CHAR8                   *memberOf[]        = { MEMBER_OF_ATTR, NULL };
  ldapAttributeList_t     *attrsList[] = {NULL, NULL};
  ldapAttributePair       attrPair = {NULL, NULL, NULL};
  
  attrsList[0] = &unionGroupList;
  attrPair.attrs = memberOf;
  attrPair.pAttrList = attrsList;

  totalAuthDB = AllocateZeroPool(sizeof(LDAP_USER_AUTH_DB));
  if (totalAuthDB == NULL) {
    *retval = LDAP_OUT_OF_MEMORY;
    goto _exit;
  }

  // For each workstation's group get all union groups
  for(pcGroupCount = 0; pcGroupCount < pcGroupDNs->numberOfItems; pcGroupCount++) {
    LDAP_USER_AUTH_DB    *userAuthDB;

    LOG((EFI_D_ERROR, "Get for workstation group: %a \n", 
      pcGroupDNs->attributeValueList[pcGroupCount].data));

    if (unionGroupList.attributeValueList != NULL)
      FlushAttributeList(&unionGroupList);
    // get a list of union groups
    *retval = GetAttributeListForEntry(pcGroupDNs->attributeValueList[pcGroupCount].data, TRUE, 
                                       NULL, &attrPair);
    if (LDAP_SEARCH_SUCCESS != *retval)
      continue;

    userAuthDB = GetUsersFromUnionGroups(&unionGroupList, retval);
    if (userAuthDB != NULL) {
      AppendUserAuthDB(totalAuthDB, userAuthDB);
      FreeTokenUserDB(userAuthDB);
    }
  }

_exit:
  
  if (unionGroupList.attributeValueList != NULL)
    FlushAttributeList(&unionGroupList);

  LOG((EFI_D_ERROR, "%a.%d: retval: %d, \n", __FUNCTION__, __LINE__, *retval));

  return totalAuthDB;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get all users for union group list */
/*! \param[in] *unionGroupDNs A list of union's DNs
    \param[out] *retval Status of operation */
//------------------------------------------------------------------------------
LDAP_USER_AUTH_DB*
GetUsersFromUnionGroups (
  IN ldapAttributeList_t *unionGroupDNs,
  OUT UINTN *retval
)
{
  UINTN unionCount  = 0;                // Count of union groups, which connect PC group and user group
  CHAR8 *member[]   = { MEMBER_ATTR, NULL };

  ldapAttributeList_t secGroupList = {0, NULL};
  LDAP_USER_AUTH_DB   *totalAuthDB = NULL;

  ldapAttributeList_t     *attrsList[] = {NULL, NULL};
  ldapAttributePair       attrPair = {NULL, NULL, NULL};
  
  attrsList[0] = &secGroupList;
  attrPair.attrs = member;
  attrPair.pAttrList = attrsList;

  totalAuthDB = AllocateZeroPool(sizeof(LDAP_USER_AUTH_DB));
  if (NULL == totalAuthDB) {
    *retval = LDAP_OUT_OF_MEMORY;
    goto _exit;
  }

  for(unionCount = 0; unionCount < unionGroupDNs->numberOfItems; unionCount++) {
    LDAP_USER_AUTH_DB    *userAuthDB;

    LOG((EFI_D_ERROR, "Get for union group: %a \n",
      unionGroupDNs->attributeValueList[unionCount].data));

    if (secGroupList.attributeValueList != NULL)
      FlushAttributeList(&secGroupList);

    *retval = GetAttributeListForEntry(unionGroupDNs->attributeValueList[unionCount].data, TRUE,
                                       NULL, &attrPair);
    if (LDAP_SEARCH_SUCCESS != *retval)
      continue;

    userAuthDB = GetUsersFromSecureGroups(&secGroupList, retval);
    if (userAuthDB != NULL) {
      AppendUserAuthDB(totalAuthDB, userAuthDB);
      FreeTokenUserDB(userAuthDB);
    }
  }

_exit:
  
  if (secGroupList.attributeValueList != NULL)
    FlushAttributeList(&secGroupList);

  LOG((EFI_D_ERROR, "%a.%d: retval: %d, \n", __FUNCTION__, __LINE__, *retval));

  return totalAuthDB;
}
{
  UINTN secGroupCount  = 0; 
  CHAR8 *secMember[]   = { MEMBER_ATTR, ACCESS_LEVEL_ATTR, NULL};
  LDAP_FILTER_PAIR FilterSecGrp[2] = {{OBJ_CLASS_ATTR, SECURE_GRP_CLASS}, {NULL, NULL}};

  ldapAttributeList_t usersOfSecureList  = {0, NULL};
  ldapAttributeList_t accessLevelList    = {0, NULL};
  LDAP_USER_AUTH_DB   *totalAuthDB       = NULL;

  ldapAttributeList_t     *attrsList[] = {NULL, NULL, NULL};
  ldapAttributePair       attrPair = {NULL, NULL, NULL};
  
  attrsList[0] = &usersOfSecureList;
  attrsList[1] = &accessLevelList;
  attrPair.attrs = secMember;
  attrPair.pAttrList = attrsList;

  totalAuthDB = AllocateZeroPool(sizeof(LDAP_USER_AUTH_DB));
  if (NULL == totalAuthDB) {
    *retval = LDAP_OUT_OF_MEMORY;
    goto _exit;
  }
  
  for(secGroupCount = 0; secGroupCount < atellSecureGroupDNs->numberOfItems; secGroupCount++) {
    USER_AUTH_PERMISSION permission;
    LDAP_USER_AUTH_DB    *userAuthDB;

    if (usersOfSecureList.attributeValueList != NULL)
      FlushAttributeList(&usersOfSecureList);
    if (accessLevelList.attributeValueList != NULL)
      FlushAttributeList(&accessLevelList);
    *retval = GetAttributeListForEntry(atellSecureGroupDNs->attributeValueList[secGroupCount].data, TRUE,
                                       FilterSecGrp, &attrPair);
    if (LDAP_SEARCH_SUCCESS != *retval)
      continue;
    if (accessLevelList.numberOfItems == 0) {
      continue;
    }

    permission = atoi(accessLevelList.attributeValueList->data);

    userAuthDB = GetUsersByDnList(&usersOfSecureList, permission, retval);
    if (userAuthDB != NULL) {
      AppendUserAuthDB(totalAuthDB, userAuthDB);
      FreeTokenUserDB(userAuthDB);
    }
      
  }

_exit:
  
  if (usersOfSecureList.attributeValueList != NULL)
    FlushAttributeList(&usersOfSecureList);
  if (accessLevelList.attributeValueList != NULL)
    FlushAttributeList(&accessLevelList);

  LOG((EFI_D_ERROR, "%a.%d: retval: %d, \n", __FUNCTION__, __LINE__, *retval));

  return totalAuthDB;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a list of users by user DN list */
/*! \param[in] *listOfUserDNs A list of User's DNs to get
    ]param[in] permission User permission to set to userInfo
    \param[out] *retval Status of operation */
/*! \return A list of users with parameters */
//------------------------------------------------------------------------------
LDAP_USER_AUTH_DB*
GetUsersByDnList (
  IN ldapAttributeList_t *listOfUserDNs,
  IN USER_AUTH_PERMISSION permission,
  OUT UINTN *retval
)
{
  UINTN userCount      = 0;
  CHAR8 *userAttrs[]   = { USER_CERT_ATTR, SAM_ACCOUNT_ATTR, NULL };

  LDAP_AUTH_TOKEN_USER_INFO *AuthUserList = NULL;
  LDAP_USER_AUTH_DB         *ldapAuthDB   = NULL;

  ldapAttributeList_t     *attrsList[] = {NULL, NULL, NULL};
  ldapAttributePair       attrPair = {NULL, NULL, NULL};

  ldapAttributeList_t certificateList    = {0, NULL};
  ldapAttributeList_t sAMAccountNameList = {0, NULL};
  
  attrsList[0] = &certificateList;
  attrsList[1] = &sAMAccountNameList;
  attrPair.attrs = userAttrs;
  attrPair.pAttrList = attrsList;

  if (listOfUserDNs == NULL) {
    *retval = LDAP_INVALID_PARAMETER;
    return NULL;
  }
  if (listOfUserDNs->numberOfItems < 1 || listOfUserDNs->attributeValueList == NULL) {
    *retval = LDAP_INVALID_PARAMETER;
    return NULL;
  }
  
  ldapAuthDB = AllocateZeroPool(sizeof(LDAP_USER_AUTH_DB));
  if (ldapAuthDB == NULL) {
    *retval = LDAP_OUT_OF_MEMORY;
    return NULL;
  }

  ldapAuthDB->ldapAuthUserList = AllocateZeroPool(
    sizeof(LDAP_AUTH_TOKEN_USER_INFO)*listOfUserDNs->numberOfItems);
  if (ldapAuthDB->ldapAuthUserList == NULL) {
    *retval = LDAP_OUT_OF_MEMORY;
    goto _exit;
  }

  AuthUserList = ldapAuthDB->ldapAuthUserList;

  // Get some user info for each user has been found for given workstation and make user info
  for(userCount = 0; userCount < listOfUserDNs->numberOfItems; userCount++) {

    if (certificateList.attributeValueList != NULL)
      FlushAttributeList(&certificateList);
    if (sAMAccountNameList.attributeValueList != NULL)
      FlushAttributeList(&sAMAccountNameList);

     LOG((EFI_D_ERROR, "Get for userDN: %a \n", listOfUserDNs->attributeValueList[userCount].data));

    // Get certificate and sAMAccountName for user has been found
    *retval = GetAttributeListForEntry(listOfUserDNs->attributeValueList[userCount].data, TRUE, 
                                       NULL, &attrPair);
    if (LDAP_SEARCH_SUCCESS != *retval)
      continue;

    if (certificateList.numberOfItems != 1) {
      LogLdapAuthMessage(EFI_D_ERROR, "Skip user %a, number of certificates %d\n",
        listOfUserDNs->attributeValueList[userCount].data, certificateList.numberOfItems);
      continue;
    }

    if (sAMAccountNameList.numberOfItems != 1) {
      LogLdapAuthMessage(EFI_D_ERROR, "Skip user %a, Error with sAMAccountName\n",
        listOfUserDNs->attributeValueList[userCount].data);
      continue;
    }

    if (MakeAuthUserTokenInfo(&certificateList,
                              sAMAccountNameList.attributeValueList->data,
                              listOfUserDNs->attributeValueList[userCount].data,
                              permission,
                              AuthUserList) != EFI_SUCCESS)
      continue;

    ldapAuthDB->userCount++;
    AuthUserList++;
  }

_exit:
  if (certificateList.attributeValueList != NULL)
    FlushAttributeList(&certificateList);
  if (sAMAccountNameList.attributeValueList != NULL)
    FlushAttributeList(&sAMAccountNameList);

  LOG((EFI_D_ERROR, "%a.%d: retval: %d, \n", __FUNCTION__, __LINE__, *retval));

  return ldapAuthDB;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Make auth user info */
/*! \param[in] certificateList A list of user certificates. Has to contain only one
    \param[in] userDN DN of the user
    \param[in] permissions User login permissions
    \param[out] userInfo Info for auth user info list */
//------------------------------------------------------------------------------
static
EFI_STATUS
MakeAuthUserTokenInfo (
  IN  ldapAttributeList_t       *certificateList,
  IN  CHAR8                     *userName,
  IN  CHAR8                     *userDN,
  IN  USER_AUTH_PERMISSION      permissions,
  OUT LDAP_AUTH_TOKEN_USER_INFO *userInfo
)
{
  EFI_STATUS Status = EFI_ABORTED;

  if (certificateList == NULL || userDN == NULL || userInfo == NULL || userName == NULL)
    return EFI_INVALID_PARAMETER;

  if (certificateList->numberOfItems != 1)
    return EFI_INVALID_PARAMETER;

  LOG((EFI_D_ERROR, "%a.%d userDN: %a \n", __FUNCTION__, __LINE__, userDN));
  LOG((EFI_D_ERROR, "%a.%d userName: %a \n", __FUNCTION__, __LINE__, userName));
  LOG((EFI_D_ERROR, "%a.%d permissions: %d \n", __FUNCTION__, __LINE__, permissions));

  userInfo->userDN = AllocateCopyPool(AsciiStrSize(userDN), userDN);
  if (userInfo->userDN == NULL)
    return EFI_OUT_OF_RESOURCES;

  userInfo->certData = AllocateCopyPool(certificateList->attributeValueList->dataLen,
    certificateList->attributeValueList->data);
  if (userInfo->certData == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto _exit;
  }

  userInfo->userName = AllocateCopyPool(AsciiStrSize(userName), userName);
  if (userInfo->userName == NULL)
    return EFI_OUT_OF_RESOURCES;

  userInfo->certDataLen = certificateList->attributeValueList->dataLen;
  userInfo->permission = permissions;

  Status = EFI_SUCCESS;

_exit:
  if (Status != EFI_SUCCESS) {
    if (userInfo->userDN != NULL)
      FreePool(userInfo->userDN);
    if (userInfo->certData!= NULL)
      FreePool(userInfo->certData);
      userInfo->certDataLen = 0;
  }

  LOG((EFI_D_ERROR, "%a.%d Status: %d \n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get admins for specified worstation */
/*! You have to free received list of users in the end */
/*! \param[in] pcGuid GUID of a workstation
    \param[out] *retval Status of operation */
/*! \return A list of ldap token admins */
//------------------------------------------------------------------------------
LDAP_USER_AUTH_DB*
GetTokenAdminsListWithPCguid (
  IN EFI_GUID *pcGuid,
  OUT UINTN   *retval
)
{
  CHAR8 pcGuidStr[64]  = {0x00};
  LDAP_FILTER_PAIR FilterPcGuid[2] = {{BIOS_GUID_ATTR, NULL}, {NULL, NULL}};

  ldapAttributeList_t pcGroupsList = {0, NULL};
  LDAP_USER_AUTH_DB *ldapAuthDB    = NULL;

  CHAR8 *pcBaseData = NULL;
  LDAP_CONFIG_OP* LdapConfig = &gLdapAuthInternalData.LdapAuhtPtotocol.LdapConfigOp;

  CHAR8                   *memberOf[]        = { MEMBER_OF_ATTR, NULL };
  ldapAttributeList_t     *attrsList[] = {NULL, NULL};
  ldapAttributePair       attrPair = {NULL, NULL, NULL};
  
  attrsList[0] = &pcGroupsList;
  attrPair.attrs = memberOf;
  attrPair.pAttrList = attrsList;

  AsciiSPrint (pcGuidStr, sizeof(pcGuidStr), "%g", pcGuid);

  LOG((EFI_D_ERROR, "%a.%d: pcGuid: %a\n", __FUNCTION__, __LINE__, pcGuidStr));

  if (LdapConfig->ReadLdapConfig() != EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d: Error: Can't read ldap config!\n", 
      __FUNCTION__, __LINE__));
    return NULL;
  }

  if (LdapConfig->GetSizeOfLdapPCBase() && LdapConfig->GetLdapPCBase() != NULL) {
    pcBaseData = AllocateZeroPool((LdapConfig->GetSizeOfLdapPCBase())/2);
    if (NULL == pcBaseData) {
      return NULL;
    }
    UnicodeStrToAsciiStr(LdapConfig->GetLdapPCBase(), pcBaseData);
  }
  LOG((EFI_D_ERROR, "%a.%d pcBaseData = \"%a\"\n", __FUNCTION__, __LINE__, pcBaseData));

  // Get all groups which contains our workstation
  FilterPcGuid[0].Value = pcGuidStr;
  *retval = GetAttributeListForEntry(pcBaseData, FALSE, FilterPcGuid, &attrPair);
  if (LDAP_SEARCH_SUCCESS != *retval) {
    goto _exit;
  }

  ldapAuthDB = GetUsersFromWorkstationGroups(&pcGroupsList, retval);
  if (ldapAuthDB == NULL)
    goto _exit;

  LOG((EFI_D_ERROR, "Num users has been found %d \n", ldapAuthDB->userCount));

  if (ldapAuthDB->userCount > 0)
    *retval = LDAP_SEARCH_SUCCESS;
  else
    *retval = LDAP_SEARCH_ERROR;

_exit:

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pcGroupsList.attributeValueList != NULL)
    FlushAttributeList(&pcGroupsList);

  if (pcBaseData != NULL)
    FreePool(pcBaseData);

  LOG((EFI_D_ERROR, "%a.%d: retval: %d\n", __FUNCTION__, __LINE__, *retval));

  return ldapAuthDB;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a list of token users for specified workstation */
/*! You have to free received list of users in the end */
/*! \param[in] pcGuid GUID of a workstation
    \param[out] *retval Status of operation */
/*! \return A list of ldap token users */
//------------------------------------------------------------------------------
LDAP_USER_AUTH_DB*
GetTokenUserListWithPCguid (
  IN EFI_GUID *pcGuid,
  OUT UINTN   *retval
)
{
  CHAR8 pcGuidStr[64]  = {0x00};
  LDAP_FILTER_PAIR FilterPcGuid[2] = {{BIOS_GUID_ATTR, NULL}, {NULL, NULL}};
  CHAR8 *attrs[]       = { MEMBER_ATTR, NULL };

  ldapAttributeList_t usersList   = {0, NULL};
  LDAP_USER_AUTH_DB   *userAuthDB = NULL;

  CHAR8 *pcBaseData = NULL;
  LDAP_CONFIG_OP* LdapConfig = &gLdapAuthInternalData.LdapAuhtPtotocol.LdapConfigOp;

  ldapAttributeList_t     *attrsList[] = {NULL, NULL};
  ldapAttributePair       attrPair = {NULL, NULL, NULL};
  
  attrsList[0] = &usersList;
  attrPair.attrs = attrs;
  attrPair.pAttrList = attrsList;

  AsciiSPrint (pcGuidStr, sizeof(pcGuidStr), "%g", pcGuid);

  LOG((EFI_D_ERROR, "%a.%d: pcGuid: %a\n", __FUNCTION__, __LINE__, pcGuidStr));

  if (LdapConfig->ReadLdapConfig() != EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d: Error: Can't read ldap config!\n", 
      __FUNCTION__, __LINE__));
    return NULL;
  }

  if (LdapConfig->GetSizeOfLdapPCBase() && LdapConfig->GetLdapPCBase() != NULL) {
    pcBaseData = AllocateZeroPool((LdapConfig->GetSizeOfLdapPCBase())/2);
    if (NULL == pcBaseData) {
      return NULL;
    }
    UnicodeStrToAsciiStr(LdapConfig->GetLdapPCBase(), pcBaseData);
  }
  LOG((EFI_D_ERROR, "%a.%d pcBaseData = \"%a\"\n", __FUNCTION__, __LINE__, pcBaseData));

  FilterPcGuid[0].Value = pcGuidStr;
  *retval = GetAttributeListForEntry(pcBaseData, FALSE, FilterPcGuid, &attrPair);
  if (LDAP_SEARCH_SUCCESS != *retval)
    return NULL;

  userAuthDB = GetUsersByDnList(&usersList,
                 ALLOW_TO_LOGIN_USER, retval);
  if (userAuthDB == NULL)
    goto _exit;

  LOG((EFI_D_ERROR, "Num users has been found %d \n", userAuthDB->userCount));

  if (userAuthDB->userCount > 0)
    *retval = LDAP_SEARCH_SUCCESS;
  else
    *retval = LDAP_SEARCH_ERROR;

_exit:

  if (usersList.attributeValueList != NULL)
    FlushAttributeList(&usersList);

  if (pcBaseData != NULL)
    FreePool(pcBaseData);

  LOG((EFI_D_ERROR, "%a.%d: retval: %d\n", __FUNCTION__, __LINE__, *retval));

  return userAuthDB;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get all users and admins for specified workstation */
/*! You have to call FreeTokenUserDB() to delete this object */
/*! 2) Get all users for our workstation */
/*! \param[in] pcGuid System GUID of the workstation
    \param[out] *retval Status of operation */
/*! \return LDAP_USER_AUTH_DB object */
//------------------------------------------------------------------------------
LDAP_USER_AUTH_DB*
GetTokenUserDBWithPCguid (
  IN EFI_GUID *pcGuid,
  OUT UINTN   *retval
)
{
  LDAP_USER_AUTH_DB *totalAuthDB = NULL, *userAuthDB = NULL;

  totalAuthDB = GetTokenAdminsListWithPCguid(pcGuid, retval);
  userAuthDB = GetTokenUserListWithPCguid(pcGuid, retval);

  if (totalAuthDB == NULL) {
    if (userAuthDB == NULL)
      return NULL;
    else {
      *retval = LDAP_SEARCH_SUCCESS;
      return userAuthDB;
    }
  } else {
    if (userAuthDB == NULL) {
      *retval = LDAP_SEARCH_SUCCESS;
      return totalAuthDB;
    }
    else {
      AppendUserAuthDB(totalAuthDB, userAuthDB);
      FreeTokenUserDB(userAuthDB);
      *retval = LDAP_SEARCH_SUCCESS;
      return totalAuthDB;
    }
  }
}
//------------------------------------------------------------------------------

