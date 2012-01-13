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
#include <Library/BaseMemoryLib.h>
#include <Library/Lib/CertificatesControl.h>
#include <Library/Lib/OpensslFunctions.h>
#include <Library/RevokeChkConfigLib/RevokeChkConfig.h>

#include "CDPInternal.h"

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)  DEBUG(MSG)
#endif

//------------------------------------------------------------------------------
/*! \brief Save CRLs from CDP to the Local Stack */
/*! chainData is used to check CRL issuer. We want to save only CRL for CAs from our
    CaChain. */
/*! \param[in] *cdpUrl8 CDP Url 
    \param[in] *chainData A pointer to CaChain binary
    \param[in] *chainDataLen Binary length */
/*! \retval CDP_REFRESH_SUCCESSFUL CRLs have been saved to the Local Stack 
    \retval CDP_NO_NEED_TO_REFRESH CRLs haven't been saved. No need
    \retval CDP_ERROR_TO_SAVE_NEW_CRL Error to save CRLs to the Local Stack */
//------------------------------------------------------------------------------
STATIC
CDP_STATUS
SearchAndSaveCRLsToLocalStack (
  CHAR8 *cdpUrl8,
  UINT8 *chainData,
  UINTN chainDataLen
)
{
  UINT8  *crlData  = NULL;
  UINTN  crlDataLen, crlCount, crlNum = 0;

  OSSL_STATUS osslStatus = OSSL_INVALID_PARAM;
  CDP_STATUS Status      = CDP_NO_NEED_TO_REFRESH;

  LOG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));

  Status = SearchCrlWithCDP(cdpUrl8, &crlNum);
  if (CDP_SEARCH_SUCCESS == Status) {
    if (crlNum > 0) {
      for(crlCount = 0; crlCount < crlNum; crlCount++) {
        GetCRLByNum(crlCount, &crlData, &crlDataLen);
        if (crlData != NULL) {
          if (CheckCRLWithCA(crlData, crlDataLen, chainData, chainDataLen) == OSSL_VERIFY_SUCCESS) {
            osslStatus = AddCRLtoLocalStack(crlData, crlDataLen);
            if (osslStatus != OSSL_VERIFY_SUCCESS) {
              LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
              Status = CDP_ERROR_TO_SAVE_NEW_CRL;
              break;
            }
          }
        }
      }
    }
  }

  if (OSSL_NO_NEED_TO_SAVE_CRLS == osslStatus)
    Status = CDP_NO_NEED_TO_REFRESH;
  else if (OSSL_VERIFY_SUCCESS == osslStatus)
    Status = CDP_REFRESH_SUCCESSFUL;

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get CRL from CDP URL, check and refresh CRL Local Stack */
/*! If CDP Cashe is off we dont refresh CAChain Storage, result CRLs are in the
    LocalCRLStack */
/*! \return Status of operation */
//------------------------------------------------------------------------------
STATIC
CDP_STATUS
GetCRLbyCDPSetting (
  VOID
)
{
  CHAR16 *cdpUrl16 = NULL;
  CHAR8  *cdpUrl8  = NULL;

  UINT8  *chainData = NULL;
  UINTN  chainDataLen = 0;

  CDP_STATUS  Status     = CDP_NO_NEED_TO_REFRESH;

  LOG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));

  if (IsChainEmpty() == TRUE) {
    return CDP_CANT_GET_CA_CHAIN;
  } else {
    chainData = ChainGetData()->Data;
    chainDataLen = ChainGetData()->DataLen;
  }

  cdpUrl16 = GetLocalCdpUrl();
  if (cdpUrl16 == NULL) {
    Status = CDP_URL_IS_EMPTY;
    goto _exit;
  }
  cdpUrl8 = AllocateZeroPool(StrLen(cdpUrl16)*sizeof(CHAR8) + sizeof(CHAR8));
  if (cdpUrl8 == NULL) {
    Status = CDP_OUT_OF_MEMORY;
    goto _exit;
  }
  UnicodeStrToAsciiStr(cdpUrl16, cdpUrl8);

  Status = SearchAndSaveCRLsToLocalStack(cdpUrl8, chainData, chainDataLen);

  if (cdpUrl8 != NULL)
    FreePool(cdpUrl8);
  FreeReceivedCRLs();

_exit:
  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  SetCDPLastError(Status);

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get CRL with CDP from certificate, check and refresh CRL Local Stack */
/*! Check CaChain and load CRL by CDP extension for the each certificate in
    the chain. Also get CRL for certificate from the binary passed through. */
/*! \param[in] *Data Certificate binary with CDP extension
    \param[in] DataLen Binary length */
//------------------------------------------------------------------------------
STATIC
CDP_STATUS
GetCRLByCertExtension (
  IN OPTIONAL UINT8 *Data,
  IN OPTIONAL UINTN DataLen
)
{
  CDP_STATUS Status      = CDP_NO_NEED_TO_REFRESH;
  LIST_ENTRY cdpListHead;
  LIST_ENTRY *Link, *PrevLink;
  UINT8 *chainData = NULL;
  UINTN chainDataLen = 0, cdpCount = 0;
  CDP_URL_ENTRY *cdpUrlEntry;
  BOOLEAN atLeastOne = FALSE;

  LOG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));

  if (IsChainEmpty() == TRUE) {
    return CDP_CANT_GET_CA_CHAIN;
  } else {
    chainData = ChainGetData()->Data;
    chainDataLen = ChainGetData()->DataLen;
  }

  InitializeListHead(&cdpListHead);

  // Get CDP URLs from the user certificate and CA chain
  if (Data  != NULL && DataLen != 0)
    cdpCount = GetCDPListFromCertBinary(Data, DataLen, &cdpListHead);

  cdpCount += GetCDPListFromCaChainBinary(chainData, chainDataLen, &cdpListHead);
  if (cdpCount <= 0)
    return CDP_CANT_GET_CDP_FROM_CERT;

  for(Link = GetFirstNode(&cdpListHead); !IsNull(&cdpListHead, Link);) {
    cdpUrlEntry = (CDP_URL_ENTRY*)Link;
    if (cdpUrlEntry->cdpUri == NULL) {
      // Something wrong
      continue;
    }
    Status = SearchAndSaveCRLsToLocalStack(cdpUrlEntry->cdpUri, chainData, chainDataLen);
    if (Status == CDP_REFRESH_SUCCESSFUL)
      atLeastOne = TRUE;

    Link = GetNextNode(&cdpListHead, Link);
  }

  for(Link = GetFirstNode(&cdpListHead); !IsNull(&cdpListHead, Link);) {
    PrevLink = Link;
    cdpUrlEntry = (CDP_URL_ENTRY*)Link;
    Link = GetNextNode (&cdpListHead, Link);    
    RemoveEntryList (PrevLink);
    FreePool(cdpUrlEntry);
  }

  LOG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));

  // Need to inform - need to refresh CaChain, CRLs are new
  if (atLeastOne == TRUE)
    Status = CDP_REFRESH_SUCCESSFUL;

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get CRLs and refresh local CRL stack if needed */
/*! Try to read CDP URL from setting and from CDP extension in the user certificate
    and certificates from CaChain. Download CRLs. Access to CaChain is performed
    directly. */
/*! If returns CDP_REFRESH_SUCCESSFUL, caller has to reload CaChain in the certificate
    storage */
/*! \param[in] *Data User certificate binary data 
    \param[in] DataLen A length of the binary */
//------------------------------------------------------------------------------
CDP_STATUS
RefreshLocalCRL (
  IN OPTIONAL UINT8 *Data,
  IN OPTIONAL UINTN DataLen
)
{
  CDP_STATUS Status;
  BOOLEAN needToRefresh = FALSE;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (GetCDPfromCertUsageFlag() == USE) {
    Status = GetCRLByCertExtension(Data, DataLen);
    if (CDP_REFRESH_SUCCESSFUL == Status)
      needToRefresh = TRUE;
  }

  Status = GetCRLbyCDPSetting();

  if (needToRefresh == TRUE) {
    LOG((EFI_D_ERROR, "At least one attempt has been successful\n"));
    Status = CDP_REFRESH_SUCCESSFUL;
  }

  // Check is LocalStack keeps new CRLs and save these CRLs to the CaChain in the flash
  if (Status == CDP_REFRESH_SUCCESSFUL) {
    if (GetCDPCasheUsageFlag() == USE)
      if (CheckAndSaveStackToChainStorage(ChainGetData()->Data, ChainGetData()->DataLen) != OSSL_VERIFY_SUCCESS)
        Status = CDP_NO_NEED_TO_REFRESH;
  }

  return Status;
}
//------------------------------------------------------------------------------

