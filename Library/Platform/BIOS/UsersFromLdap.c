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
#include <Library/UefiBootServicesTableLib.h>
#include <Library/Lib/CertificatesControl.h>
#include <Library/Lib/OpensslFunctions.h>
#include <Library/Lib/OpensslCnfFv.h>
#include <Library/Lib/History.h>
#include <Library/UserManagerLib.h>
#include <Protocol/LdapAuthDxe.h>
#include <openssl/engine.h>
#include "ProcessingErrors.h"

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

STATIC LDAP_AUTH_PROTOCOL *pLdapAuthProtocol;

extern
EFI_STATUS
CalcDataDigest (
  IN UINT8 *CertData,
  IN UINTN CertDataLen,
  IN UINT8 *FileData,
  IN UINTN FileDataLen,
  OUT UINT8 **SignBuf,
  OUT UINTN *SignLen
);

//------------------------------------------------------------------------------
/*! \brief Make an unicode string representation of a signature */
/*! \param[in] *certData Certificate binary to calculate signature
    \param[in] certDataSize Certificate binary size
    \param[out] **signatureStr Signature as an unicode string */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
MakeSignatureStr16 (
  IN CHAR8 *certData,
  IN UINTN certDataSize,
  OUT CHAR16 **signatureStr
)
{
  EFI_STATUS Status = EFI_ABORTED;

  CHAR8 *sigData = NULL, *sigDataStr8 = NULL;
  UINTN signDataLent = 0, digestStrLen8 = 0;

  if (certData == NULL || certDataSize == 0 || signatureStr == NULL)
    return EFI_INVALID_PARAMETER;

  Status = CalcDataDigest(ChainGetData()->Data,
                          ChainGetData()->DataLen,
                          certData,
                          certDataSize,
                          &sigData,
                          &signDataLent
                          );
  if (Status != EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

  digestStrLen8 = (signDataLent << 1) + sizeof(CHAR8);

  sigDataStr8 = AllocateZeroPool(digestStrLen8);
  if (sigDataStr8 == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto _exit;
  }

  if (GetCalcDataDigest_MdType() == NID_id_GostR3411_94) {
    ByteBufToStringRev(sigData, signDataLent, sigDataStr8, digestStrLen8);
  } else {
    ByteBufToString(sigData, signDataLent, sigDataStr8, digestStrLen8);
  }

  *signatureStr = AllocateZeroPool(digestStrLen8*sizeof(CHAR16));
  if (*signatureStr == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto _exit;
  }

  AsciiStrToUnicodeStr(sigDataStr8, *signatureStr);

_exit:
  if (Status != EFI_SUCCESS)
    FreePool(*signatureStr);

  if (sigData != NULL)
    FreePool(sigData);
  if (sigDataStr8 != NULL)
    FreePool(sigDataStr8);

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Flush lokal token data */
//------------------------------------------------------------------------------
VOID
FlushTokenUserData (
  IN USER_TOKEN_DATA *localUserData
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (localUserData == NULL)
    return;

  if (localUserData->commonName != NULL)
    FreePool(localUserData->commonName);
  if (localUserData->digest != NULL)
    FreePool(localUserData->digest);
  if (localUserData->mail != NULL)
    FreePool(localUserData->mail);
  if (localUserData->subject != NULL)
    FreePool(localUserData->subject);
  if (localUserData->uid != NULL)
    FreePool(localUserData->uid);
  if (localUserData->userName != NULL)
    FreePool(localUserData->userName);

  FreePool(localUserData);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Make token user data from ldap auth token user data */
/*! \param[in] *ldapTokenUserInfo User info has been got from LDAP server
    \param[out] **localUserData Local token user data */
//------------------------------------------------------------------------------
EFI_STATUS
MakeTokenUserData (
  IN LDAP_AUTH_TOKEN_USER_INFO *ldapTokenUserInfo,
  OUT USER_TOKEN_DATA **localUserData
)
{
  CHAR16 *sigDataStr16 = NULL;
  EFI_STATUS Status = EFI_ABORTED;

  if (ldapTokenUserInfo == NULL || localUserData == NULL)
    return EFI_INVALID_PARAMETER;

  LOG((EFI_D_ERROR, "%a.%d: userDN %a\n", __FUNCTION__, __LINE__, ldapTokenUserInfo->userDN));

  *localUserData = AllocateZeroPool(sizeof(USER_TOKEN_DATA));
  if (*localUserData == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto _exit;
  }

  Status = MakeSignatureStr16(ldapTokenUserInfo->certData, ldapTokenUserInfo->certDataLen, &sigDataStr16);
  if (Status != EFI_SUCCESS || sigDataStr16 == NULL) {
    LogBiosMessage(EFI_D_ERROR, "UsersFromLdap",
      "Can't make signature for user %a. Skip user.", ldapTokenUserInfo->userName);
    goto  _exit;
  }
  (*localUserData)->digest = sigDataStr16;
  (*localUserData)->permission = ldapTokenUserInfo->permission;

  (*localUserData)->userName = AllocateZeroPool(AsciiStrSize(ldapTokenUserInfo->userName)*sizeof(CHAR16));
  if ((*localUserData)->userName == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto _exit;
  }

  ConvertUtf8StrToUnicodeStr((*localUserData)->userName, ldapTokenUserInfo->userName,
    AsciiStrLen(ldapTokenUserInfo->userName));

_exit:
  if (Status != EFI_SUCCESS) {
    FlushTokenUserData(*localUserData);
  } else {
    LOG((EFI_D_ERROR, "%a.%d digest: %s\n", __FUNCTION__, __LINE__, (*localUserData)->digest));
    LOG((EFI_D_ERROR, "%a.%d: permission %d\n", __FUNCTION__, __LINE__, (*localUserData)->permission));
    LOG((EFI_D_ERROR, "%a.%d: userName %s\n", __FUNCTION__, __LINE__, (*localUserData)->userName));

    LogBiosMessage(EFI_D_ERROR, "UsersFromLdap", "Find user %s", ldapTokenUserInfo->userName);
  }

  return Status;
}
//------------------------------------------------------------------------------


EFI_STATUS
CleanUpLocalUsersDataBase (
  LDAP_USER_AUTH_DB *pLdapDb  
  )
{
  UINTN LocalCnt, Idx, userCount;
  USER_INFO *pUsrInfo;
  EFI_STATUS Status;
  BOOLEAN bPresentSame, bPresent;

  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pLdapDb == NULL || pLdapDb->userCount == 0) {
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  LocalCnt = GetUsersCount ();
  if (LocalCnt != pLdapDb->userCount) {
    // clean up data base
    if (!HistoryOutswapped()) {
      return EFI_ABORTED;
    }
    UsersStorageInitEmpty ();
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }
  
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  for (Idx = 0; Idx < LocalCnt; Idx++) {
    LDAP_AUTH_TOKEN_USER_INFO *beginOfUserList = pLdapDb->ldapAuthUserList;
    Status = UserFindRecordByNum (Idx);
    if (EFI_ERROR(Status)) {
      LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      continue;
    }
    pUsrInfo = UserGetLastFoundedInfo ();
    if (NULL == pUsrInfo) {
      LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      continue;
    }
    if (pUsrInfo->AuthType == AUTH_TYPE_LOG_PASS) {      
      if (!HistoryOutswapped()) {
        return EFI_ABORTED;
      }
      UsersStorageInitEmpty ();
      LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_SUCCESS;
    }

      
    LOG ((EFI_D_ERROR, "%a.%d ldapAuthDB->userCount=%d\n", 
      __FUNCTION__, __LINE__, pLdapDb->userCount));

    for(userCount = 0; userCount < pLdapDb->userCount; userCount++) {
      if (beginOfUserList != NULL) {
        USER_TOKEN_DATA *tokenUserData = NULL;
        // Make local token user data to save
        Status = MakeTokenUserData(beginOfUserList, &tokenUserData);
        if (Status != EFI_SUCCESS) {
          LOG((EFI_D_ERROR, "%a.%d: Error, but try another user\n",
            __FUNCTION__, __LINE__));
          beginOfUserList++;
          continue;
        }
        // Add token local user
        //Status = AddTokenUser(tokenUserData);
        bPresentSame = bPresent = FALSE;
        Status = IsTokenUserDataPresentAndSame (
                    tokenUserData,
                    &bPresentSame,
                    &bPresent
                    );
        if (EFI_ERROR(Status) || !bPresentSame) {
          if (!HistoryOutswapped()) {
            return EFI_ABORTED;
          }
          UsersStorageInitEmpty ();
          LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
          return EFI_SUCCESS;
        }

        beginOfUserList++;
      }
    }
    
  }

  return EFI_SUCCESS;
}

VOID
DumpUsers (
  VOID
  )
{
  UINTN LocalCnt, Idx;
  USER_INFO *pUsrInfo;
  EFI_STATUS Status;

  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  LocalCnt = GetUsersCount ();
    
  LOG ((EFI_D_ERROR, "%a.%d LocalCnt=%d\n", __FUNCTION__, __LINE__, LocalCnt));
  for (Idx = 0; Idx < LocalCnt; Idx++) {
    Status = UserFindRecordByNum (Idx);
    if (EFI_ERROR(Status)) {
      LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      continue;
    }
    pUsrInfo = UserGetLastFoundedInfo ();
    if (NULL == pUsrInfo) {
      LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      continue;
    }
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));


    LOG ((EFI_D_ERROR, " AuthType=%02X UserName=%s UserId=%02X Flags=%02X\n",
      pUsrInfo->AuthType,
      pUsrInfo->UserName,
      pUsrInfo->UserId,
      pUsrInfo->Flags));
  }
}

EFI_STATUS
MarkActualUsersDb (
  IN UINT8 *MarkedId,
  IN UINTN MarkedNum
  )
{
  UINTN LocalCnt, Idx, M, UpdatedCnt, TotalLen, RecordSize;
  USER_INFO *pUsrInfo;
  EFI_STATUS Status;
  BOOLEAN bFound;
  UINT8 *DataPtr;
  STATIC USERS_STORAGE UsrStrorage;
  BOOLEAN bMarkAllUsers = FALSE;

  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (MarkedId == NULL && MarkedNum != 0) {
    return EFI_INVALID_PARAMETER;
  }
  if (MarkedNum == 0) {
    //return EFI_SUCCESS;
    bMarkAllUsers = TRUE;
  }

  for (M = 0; M < MarkedNum; M++) {
    LOG ((EFI_D_ERROR, "MarkedId[%d]=%02X\n", M, MarkedId[M]));
  }

  DumpUsers ();

  LocalCnt = GetUsersCount ();
    
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  UpdatedCnt = 0;
#if 1
  (VOID)Idx;
  Status = UsersStorageGetData(&UsrStrorage);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }

  TotalLen = UsrStrorage.DataLen;
  DataPtr = UsrStrorage.Data;
  
  while (TotalLen) {
    pUsrInfo = (USER_INFO*)DataPtr;
    RecordSize = sizeof(USER_INFO) - 1;

    RecordSize += pUsrInfo->ExtDataLen;

    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, 
        "%a.%d: Attention!!! Users storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }

    LOG ((EFI_D_ERROR, "%a.%d\n", 
      __FUNCTION__, __LINE__));
    LOG ((EFI_D_ERROR, " AuthType=%02X UserName=%s UserId=%02X Flags=%02X\n",
      pUsrInfo->AuthType,
      pUsrInfo->UserName,
      pUsrInfo->UserId,
      pUsrInfo->Flags));
    
    bFound = FALSE;
    if (bMarkAllUsers) {
      
    } else {
      for (M = 0; M < MarkedNum; M++) {
        if (pUsrInfo->UserId == MarkedId[M]) {
          bFound = TRUE;
          break;
        }
      }
    }

    if (bFound) {
      if (pUsrInfo->Flags & USER_HIDDEN_FLAG) {
        pUsrInfo->Flags &= ~USER_HIDDEN_FLAG;
        UpdatedCnt++;
      }
    } else {
      if (pUsrInfo->Flags & USER_HIDDEN_FLAG) {
        
      } else {
        pUsrInfo->Flags |= USER_HIDDEN_FLAG;
        UpdatedCnt++;
      }
    }
          
    LOG ((EFI_D_ERROR, " AuthType=%02X UserName=%s UserId=%02X Flags=%02X\n", 
      pUsrInfo->AuthType,
      pUsrInfo->UserName,
      pUsrInfo->UserId,
      pUsrInfo->Flags));
    
    TotalLen -= RecordSize;
    DataPtr += RecordSize;
  }
  
  
#else
  for (Idx = 0; Idx < LocalCnt; Idx++) {
    Status = UserFindRecordByNum (Idx);
    if (EFI_ERROR(Status)) {
      LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      continue;
    }
    pUsrInfo = UserGetLastFoundedInfo ();
    if (NULL == pUsrInfo) {
      LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      continue;
    }
    LOG ((EFI_D_ERROR, "%a.%d\n", 
      __FUNCTION__, __LINE__));
    LOG ((EFI_D_ERROR, " AuthType=%02X UserName=%s UserId=%02X Flags=%02X\n",
      pUsrInfo->AuthType,
      pUsrInfo->UserName,
      pUsrInfo->UserId,
      pUsrInfo->Flags));
    
    bFound = FALSE;
    for (M = 0; M < MarkedNum; M++) {
      if (pUsrInfo->UserId == MarkedId[M]) {
        bFound = TRUE;
        break;
      }
    }
    if (bFound) {
      if (pUsrInfo->Flags & USER_HIDDEN_FLAG) {
        pUsrInfo->Flags &= ~USER_HIDDEN_FLAG;
        UpdatedCnt++;
      }
    } else {
      if (pUsrInfo->Flags & USER_HIDDEN_FLAG) {
        
      } else {
        pUsrInfo->Flags |= USER_HIDDEN_FLAG;
        UpdatedCnt++;
      }
    }
          
    LOG ((EFI_D_ERROR, " AuthType=%02X UserName=%s UserId=%02X Flags=%02X\n", 
      pUsrInfo->AuthType,
      pUsrInfo->UserName,
      pUsrInfo->UserId,
      pUsrInfo->Flags));    
  }
#endif  

  LOG ((EFI_D_ERROR, "%a.%d UpdatedCnt=%d\n", 
    __FUNCTION__, __LINE__, UpdatedCnt));
  if (UpdatedCnt) {
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    Status = UsersStorageUpdate ();
  } else {
    Status = EFI_SUCCESS;
  }

  DumpUsers ();
  LOG ((EFI_D_ERROR, "%a.%d Status=%r\n", 
    __FUNCTION__, __LINE__, Status));
  return Status;
}

STATIC
EFI_STATUS
LogLoadUsersFromLDAP (
  IN UINTN chkStatus
  )
{
  UINT16 Evt = HEVENT_UPD_USRS_LOCAL_INT_ERR;
  UINT8 Sev = SEVERITY_LVL_ERROR;
  UINT8 Flags = 0;

  EFI_STATUS Status;
  MULTIBOOT_PROTOCOL *gMultiboot;

  if (chkStatus != LDAP_SEARCH_SUCCESS) {
    Status = gBS->LocateProtocol (
                &ProtocolGuid, 
                NULL, 
                (VOID **) &gMultiboot
                );
    if (!EFI_ERROR(Status)) {
      if (gMultiboot && gMultiboot->GetCurrentHiiHandle != NULL)
        LogBiosMessage(EFI_D_ERROR, "UsersFromLdap", "Can't get users. %s ",
          GetLdapErrorStr(gMultiboot->GetCurrentHiiHandle(), chkStatus));
    }
  }

  switch (chkStatus) {  
  case CANT_CONNECT_TO_LDAP:
  case CANT_PROC_LDAP_OPT:
  case CANT_INIT_LDAP_SESSION:
  case CANT_MAKE_REQUEST:
    Evt = HEVENT_UPD_USRS_LOCAL_CONNECT_ERR;
    break;
    
  case LDAP_AUTH_PASS:
  case LDAP_AUTH_FAIL:
  case LDAP_ROOT_ERR_CREDENTIALS:
  case LDAP_SERVER_DENY:
    Evt = HEVENT_UPD_USRS_LOCAL_AUTH_ERR;
    break;
    
  case LDAP_SEARCH_ERROR:
  case LDAP_SEARCH_SUCCESS:
    Evt = HEVENT_UPD_USRS_LOCAL_SUCCESS;
    Sev = SEVERITY_LVL_INFO;
    Flags = HISTORY_RECORD_FLAG_RESULT_OK;
    break;

  case LDAP_OUT_OF_MEMORY:    
  case LDAP_INTERNAL_ERROR:  
  case LDAP_TOO_MANY_ENTRIES:
  case LDAP_TLS_CACERTFILE_EMPTY:
  case LDAP_TLS_CACERTFILE_FAIL:
  case LDAP_ERROR_TO_START_TLS:
  case LDAP_ERROR_TO_GET_PERMIT:
  case LDAP_CANT_GET_SYSTEM_GUID:
  case LDAP_INVALID_PARAMETER:
    Evt = HEVENT_UPD_USRS_LOCAL_INT_ERR;
    break;

  default:
    Evt = HEVENT_UPD_USRS_LOCAL_INT_ERR;
  }

  return HistoryAddRecord(
    Evt,
    USER_UNKNOWN_ID,
    Sev,
    Flags
    );
}

STATIC
CHAR16 *
GetNameOfPermission (
  UINT8 Perm
  )
{
  switch (Perm) {
  case USER_ACCESS_AUDIT:
    return L"Auditor";
    
  case USER_ACCESS_REMOTE_AUDIT:
    return L"Auditor+Remote";
    break;
    
  case USER_ACCESS_FULL_CTRL:
    return L"FullCtrl";
    
  case USER_ACCESS_REMOTE_FULL_CTRL:
    return L"FullCtrl+Remote";
    
  
  case USER_ACCESS_REMOTE_START_OS:
    return L"+Remote";
    
  case USER_ACCESS_START_OS:
  default:
    return L"";
  }
}

//------------------------------------------------------------------------------
/*! \brief Get a list of users from the LDAP server and save to the storage */
//------------------------------------------------------------------------------
EFI_STATUS
GetUsersFromLdapAndSave (
  VOID
)
{
  LDAP_USER_AUTH_DB *ldapAuthDB = NULL;

  UINTN      userCount = 0;
  UINTN      chkStatus = LDAP_SEARCH_ERROR;
  EFI_STATUS Status    = EFI_ABORTED;
  UINT8 *MarkedId = NULL;

  Status = gBS->LocateProtocol (
                  &gLdapAuthDxeProtocolGuid,
                  NULL,
                  (VOID **) &pLdapAuthProtocol
                  );
  if (Status != EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
    return EFI_ABORTED;
  }

  if (pLdapAuthProtocol->LdapConfigOp.GetLdapAuthUsageStatus() != USE_LDAP_AUTH) {
    LogBiosMessage(EFI_D_ERROR, "UsersFromLdap", "LDAP auth usage is turned off. Can't get users from LDAP ");
    return EFI_ABORTED;
  }

  if (pLdapAuthProtocol->LdapConfigOp.IsUseTLS() == TRUE) {
    //-------------------------------------------------------
    // Check an using of a TLS and try to get OpenSSL.cnf from fv and load it
    //-------------------------------------------------------
    tlsConfig_t config = MakeTlsConfig(ChainGetData()->Data, ChainGetData()->DataLen);
    Status = pLdapAuthProtocol->LdapConfigOp.SetOpensslConfig(config);
    if (Status != EFI_SUCCESS) {
       LOG((EFI_D_ERROR, "%a.%d: Can't set OpenSSL.cnf. Will be used default settings\n", __FUNCTION__, __LINE__));
    }
  }

  HistoryAddRecord (
    HEVENT_UPD_USRS_LOCAL_DB_START,
    USER_UNKNOWN_ID,
    SEVERITY_LVL_INFO,
    HISTORY_RECORD_FLAG_RESULT_OK
    );

  // Download a list of users
  ldapAuthDB = pLdapAuthProtocol->GetTokenUserDBFromLdapServer(&chkStatus);
  LOG ((EFI_D_ERROR, "%a.%d chkStatus=%X\n", __FUNCTION__, __LINE__, chkStatus));
  pLdapAuthProtocol->CleanLdapConnection();

  LogLoadUsersFromLDAP (chkStatus);
  
  if (chkStatus == LDAP_SEARCH_SUCCESS) {
    if (ldapAuthDB != NULL && ldapAuthDB->userCount > 0) {

      LDAP_AUTH_TOKEN_USER_INFO *beginOfUserList = ldapAuthDB->ldapAuthUserList;
      LOG ((EFI_D_ERROR, "%a.%d ldapAuthDB->userCount=%d\n", 
        __FUNCTION__, __LINE__, ldapAuthDB->userCount));

      HistoryAddRecord(
          HEVENT_USERS_FROM_LDAP_NON_EMPTY,
          USER_UNKNOWN_ID,
          SEVERITY_LVL_DEBUG,
          HISTORY_RECORD_FLAG_RESULT_OK
          );
      
      MarkedId = AllocatePool (ldapAuthDB->userCount * sizeof(*MarkedId));
      if (MarkedId == NULL) {
        return EFI_OUT_OF_RESOURCES;
      }

      for(userCount = 0; userCount < ldapAuthDB->userCount; userCount++) {
        if (beginOfUserList != NULL) {
          USER_TOKEN_DATA *tokenUserData = NULL;
          MarkedId[userCount] = USER_UNKNOWN_ID;
          HistoryAddRecord(
            HEVENT_USERS_FROM_LDAP_PREPARE,
            USER_UNKNOWN_ID,
            SEVERITY_LVL_DEBUG,
            HISTORY_RECORD_FLAG_RESULT_OK
            );
          // Make local token user data to save
          LOG ((EFI_D_ERROR, ">> Rx usr from LDAP: name = %a\n",
            beginOfUserList->userName));
          Status = MakeTokenUserData(beginOfUserList, &tokenUserData);
          if (Status != EFI_SUCCESS) {
            LOG((EFI_D_ERROR, "%a.%d: Error, but try another user\n",
              __FUNCTION__, __LINE__));
            beginOfUserList++;
            continue;
          }
          LOG ((EFI_D_ERROR, ">> try to add usr from LDAP: [%s] [%s]\n",
            tokenUserData->userName, tokenUserData->digest));
          // Add token local user
          Status = AddTokenUser(tokenUserData);
          LOG ((EFI_D_ERROR, "%a.%d Status=%r\n", 
            __FUNCTION__, __LINE__, Status));
          UserFindRecordByNameWithThisAuth(AUTH_TYPE_TOKEN, 
            tokenUserData->userName);
          if (!EFI_ERROR (Status)) {
            USER_INFO *pUsrInfo;
            pUsrInfo = UserGetLastFoundedInfo();
            if (pUsrInfo) {
              UINT8 AccessType;
              MarkedId[userCount] = pUsrInfo->UserId;
              LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
              LOG ((EFI_D_ERROR, " UserId=%02X UserName=%s\n", 
                pUsrInfo->UserId, pUsrInfo->UserName));

              AccessType = USER_ACCESS_START_OS;
              GetUserAccessInfo (
                pUsrInfo->UserId, 
                &AccessType
                );
              
              LOG ((EFI_D_ERROR, ">> saved usr from LDAP: [%s] %s %s\n",
                pUsrInfo->UserName,
                (pUsrInfo->Flags & USER_ADMIN_FLAG) ? L"ADMIN" : L"USER",
                GetNameOfPermission (AccessType)
                ));
              HistoryAddRecord(
                HEVENT_USERS_FROM_LDAP_ADD_TO_DB,
                USER_UNKNOWN_ID,
                SEVERITY_LVL_DEBUG,
                HISTORY_RECORD_FLAG_RESULT_OK
                );
            } else {
              HistoryAddRecord(
                HEVENT_USERS_FROM_LDAP_ADD_TO_DB,
                USER_UNKNOWN_ID,
                SEVERITY_LVL_DEBUG,
                0
                );
            }
          }
          if (tokenUserData != NULL) {
            FlushTokenUserData(tokenUserData);
          }
          beginOfUserList++;
        }
      }
    }
    MarkActualUsersDb (MarkedId, ldapAuthDB == NULL ? 0 : ldapAuthDB->userCount);
  } else if (chkStatus == LDAP_SEARCH_ERROR) {
    MarkActualUsersDb (NULL, 0);
  }

  LOG((EFI_D_ERROR, "%a.%d: Status: %d\n", __FUNCTION__, __LINE__, Status));

  if (ldapAuthDB != NULL) {
    pLdapAuthProtocol->FreeTokenUserDB(ldapAuthDB);
  }
  if (MarkedId != NULL) {
    FreePool (MarkedId);
  }   

  return Status;  
}
//------------------------------------------------------------------------------

