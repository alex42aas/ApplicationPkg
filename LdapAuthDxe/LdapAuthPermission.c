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
#include <LdapCommon.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/FsUtils.h>
#include <Library/CommonUtils.h>

#include <Protocol/LdapAuthDxe.h>
#include <Protocol/LdapConfigOp.h>

#include <stdlib.h>

#include "LdapAuthDxeInternal.h"

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

//------------------------------------------------------------------------------
/*! \brief Search permissions */
//------------------------------------------------------------------------------
STATIC
UINTN
SearchMatchedGroupAndPermissions (
  IN ldapAttributeList_t pcGroupList,
  IN ldapAttributeList_t userGroupList,
  IN USER_AUTH_PERMISSION *permission
)
{
  UINTN i, j, permBits, retval = LDAP_SEARCH_ERROR;
  BOOLEAN isFound = FALSE;
  attributeValue_t *pGroupPcAttrList;
  attributeValue_t *pUserGroupAttrList, *startOfList;
  LDAP_FILTER_PAIR FilterThree[4] = {{NULL, NULL}, {NULL, NULL}, {NULL, NULL}, {NULL, NULL}};

  CHAR8 *attrs[] = { ACCESS_LEVEL_ATTR, NULL };
  ldapAttributeList_t *attrsList[] = {NULL, NULL};
  ldapAttributePair attrPair = {NULL, NULL, NULL};
  ldapAttributeList_t groupAttributesList = {0, NULL};

  CHAR8 *attrsClass[] = { OBJ_CLASS_ATTR, NULL };
  ldapAttributeList_t *attrsClassList[] = {NULL, NULL};
  ldapAttributePair attrClassPair = {NULL, NULL, NULL};

  *permission = NOT_ALLOW_TO_LOGIN;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pcGroupList.attributeValueList == NULL || pcGroupList.numberOfItems == 0 ||
      userGroupList.attributeValueList == NULL || userGroupList.numberOfItems == 0)
    return CANT_MAKE_REQUEST;

  pGroupPcAttrList = pcGroupList.attributeValueList;
  pUserGroupAttrList = userGroupList.attributeValueList;

  startOfList = pUserGroupAttrList;

  for(i = 0; i < pcGroupList.numberOfItems; i++) {
    if (pGroupPcAttrList->data == NULL || pGroupPcAttrList->dataLen == 0) {
      pGroupPcAttrList++;
      continue;
    }

    pUserGroupAttrList = startOfList;
    for(j = 0; j < userGroupList.numberOfItems; j++) {
      if (pUserGroupAttrList->data == NULL || pUserGroupAttrList->dataLen == 0) {
        pUserGroupAttrList++;
        continue;
      }
      FilterThree[0].Attribute = MEMBER_ATTR;
      FilterThree[0].Value = pGroupPcAttrList->data;
      FilterThree[1].Attribute = MEMBER_ATTR;
      FilterThree[1].Value = pUserGroupAttrList->data;
      FilterThree[2].Attribute = OBJ_CLASS_ATTR;
      FilterThree[2].Value = GRP_CLASS;
      attrClassPair.attrs = attrsClass;
      attrClassPair.pAttrList = attrsClassList;
      retval = GetAttributeListForEntry(NULL, FALSE,
               FilterThree, &attrClassPair);
      if  (retval != LDAP_SEARCH_SUCCESS) {
        pUserGroupAttrList++;
        continue;
      } else {
        isFound = TRUE;
        break;
      }
    }

    if (isFound == TRUE)
      break;

    pGroupPcAttrList++;
  }

  if (TRUE == isFound) {
    attrsList[0] = &groupAttributesList;
    attrPair.attrs = attrs;
    attrPair.pAttrList = attrsList;
  
    retval = GetAttributeListForEntry(pUserGroupAttrList->data, TRUE,
               NULL, &attrPair);

    if (groupAttributesList.numberOfItems != 1 || groupAttributesList.attributeValueList == NULL)
      *permission = NOT_ALLOW_TO_LOGIN;
    else {
      permBits = atoi(groupAttributesList.attributeValueList->data);
      *permission = permBits;
    }
  }
  LOG((EFI_D_ERROR, "%a.%d permission: %d\n", __FUNCTION__, __LINE__, *permission));

  if (groupAttributesList.attributeValueList != NULL)
    FlushAttributeList(&groupAttributesList);

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get from ldap server an user permission for the given work station */
/*! \param[in] *userDN A DN of the user 
    \param[in] *pcGuid A system GUID a workstation
    \param[out] *retval Status of an operation */
//------------------------------------------------------------------------------
USER_AUTH_PERMISSION
GetPermWithUserDNandPCguid (
  IN CHAR8    *userDN,
  IN EFI_GUID *pcGuid,
  OUT UINTN   *retval
)
{
  CHAR8 pcGuidStr[64]  = {0x00};
  LDAP_FILTER_PAIR FilterOne[2] = {{NULL, NULL}, {NULL, NULL}};
  BOOLEAN isLoginAllow = FALSE; 

  CHAR8 *pcDn = NULL;

  CHAR8 *pcBaseData = NULL;
  LDAP_CONFIG_OP* LdapConfig = &gLdapAuthInternalData.LdapAuhtPtotocol.LdapConfigOp;

  CHAR8 *userAttrs1[]   = { MEMBER_OF_ATTR, NULL };
  ldapAttributeList_t *memberOfAttrList1[] = {NULL, NULL};
  ldapAttributePair memberOfAttrPair1 = {NULL, NULL, NULL};
  ldapAttributeList_t usersGroupList = {0, NULL};

  CHAR8 *userAttrs2[]   = { MEMBER_OF_ATTR, NULL };
  ldapAttributeList_t *memberOfAttrList2[] = {NULL, NULL};
  ldapAttributePair memberOfAttrPair2 = {NULL, NULL, NULL};
  ldapAttributeList_t pcGroupList = {0, NULL};

  CHAR8 *attrs[]       = { MEMBER_ATTR, NULL };
  ldapAttributeList_t *memberAttrList[] = {NULL, NULL};
  ldapAttributePair memberAttrPair = {NULL, NULL, NULL};
  ldapAttributeList_t usersOfPcList = {0, NULL};

  USER_AUTH_PERMISSION permissions  = NOT_ALLOW_TO_LOGIN;

  if (userDN == NULL || retval == NULL) {
    *retval = CANT_MAKE_REQUEST;
    return NOT_ALLOW_TO_LOGIN;
  }

  AsciiSPrint (pcGuidStr, sizeof(pcGuidStr), "%g", pcGuid);

  LOG((EFI_D_ERROR, "userDN: %a, pcGuid: %a\n", userDN, pcGuidStr));

  if (LdapConfig->ReadLdapConfig() != EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d: Error: Can't read ldap config!\n", 
      __FUNCTION__, __LINE__));
    *retval = CANT_MAKE_REQUEST;
    return NOT_ALLOW_TO_LOGIN;
  }

  if (LdapConfig->GetSizeOfLdapPCBase() && LdapConfig->GetLdapPCBase() != NULL) {
    pcBaseData = AllocateZeroPool((LdapConfig->GetSizeOfLdapPCBase())/2);
    if (NULL == pcBaseData) {
      *retval = CANT_MAKE_REQUEST;
      return NOT_ALLOW_TO_LOGIN;
    }
    UnicodeStrToAsciiStr(LdapConfig->GetLdapPCBase(), pcBaseData);
  }
  LOG((EFI_D_ERROR, "%a.%d pcBaseData = \"%a\"\n", __FUNCTION__, __LINE__, pcBaseData));

  memberAttrPair.entryDn = &pcDn;
  memberAttrList[0] = &usersOfPcList;
  memberAttrPair.attrs = attrs;
  memberAttrPair.pAttrList = memberAttrList;

  // Get a member attribute of a group with pcGuid
  FilterOne[0].Attribute = BIOS_GUID_ATTR;
  FilterOne[0].Value = pcGuidStr;
  *retval = GetAttributeListForEntry(pcBaseData, FALSE, FilterOne, &memberAttrPair);
  if (LDAP_SEARCH_SUCCESS == *retval) {
    if ( NULL == pcDn ) {
      LogLdapAuthMessage(EFI_D_ERROR, "Can't find the PC with GUID: %g", pcGuid);
      *retval = LDAP_SEARCH_ERROR;
      goto _exit;
    }
    // Search given user as a member for this workstation
    if (IsAttributeValueInList(&usersOfPcList, userDN, AsciiStrLen(userDN)) == TRUE)
      isLoginAllow = TRUE; // At least can login as an user
  } else {
    // Couldn't find workstation, something wrong
    if (*retval == LDAP_TOO_MANY_ENTRIES) {
      LogLdapAuthMessage(EFI_D_ERROR, "Several PCs with GUID: %g", pcGuid);
    }
    goto _exit;
  }
  LOG((EFI_D_ERROR, "%a.%d isLoginAllow = %d\n", __FUNCTION__, __LINE__, isLoginAllow));

  memberOfAttrList2[0] = &pcGroupList;
  memberOfAttrPair2.attrs = userAttrs2;
  memberOfAttrPair2.pAttrList = memberOfAttrList2;

  // Get a memberOf attribute for this workstation
  FilterOne[0].Attribute = OBJ_CLASS_ATTR;
  FilterOne[0].Value = SECURE_PC_CLASS;
  *retval = GetAttributeListForEntry(pcDn, TRUE, FilterOne, &memberOfAttrPair2);
  if (LDAP_SEARCH_SUCCESS != *retval)
    goto _exit;

  memberOfAttrList1[0] = &usersGroupList;
  memberOfAttrPair1.attrs = userAttrs1;
  memberOfAttrPair1.pAttrList = memberOfAttrList1;

  // Get a memberOf attribute of an user
  *retval = GetAttributeListForEntry(userDN, TRUE, NULL, &memberOfAttrPair1);
  if (LDAP_SEARCH_SUCCESS != *retval)
    goto _exit;

  // Search permissions for given workstation
  *retval = SearchMatchedGroupAndPermissions(pcGroupList, usersGroupList, &permissions);
  if (LDAP_SEARCH_SUCCESS != *retval)
    goto _exit;

_exit:
  if (*retval != LDAP_SEARCH_SUCCESS) {
    if (isLoginAllow == TRUE)
      permissions = ALLOW_TO_LOGIN_USER;
  }

  if (usersOfPcList.attributeValueList != NULL)
    FlushAttributeList(&usersOfPcList);
  if (usersGroupList.attributeValueList != NULL)
    FlushAttributeList(&usersGroupList);
  if (pcGroupList.attributeValueList != NULL)
    FlushAttributeList(&pcGroupList);

  if (pcBaseData != NULL)
    FreePool(pcBaseData);

  if (pcDn != NULL)
    FreePool(pcDn);

  return permissions;
}
//------------------------------------------------------------------------------

