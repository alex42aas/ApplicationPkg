/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef REVOKE_CHECK_CONFIG_INTERNAL_H_
#define REVOKE_CHECK_CONFIG_INTERNAL_H_

#define USE_LOCAL_CDP_OFFSET      1  //!< Shift to one position (bit)
#define USE_CERT_CDP_OFFSET       2  //!< Shift to two positions (bit)
#define USE_CA_CDP_OFFSET         3   //!< Shift to three positions (bit)
#define USE_CRL_OFFSET            4  //!< Shift to four positions (bit)
#define USE_CRL_ALL_OFFSET        5  //!< Shift to five positions (bit)
#define USE_CDP_CASHE_OFFSET      6  //!< Shift to six positions (bit)
#define USE_OCSP_RSP_VER_OFFSET   7  //!< Shift to seven positions (bit)
#define USE_TLS_PEER_CRL_OFFSET   8  //!< Shift to eight positions (bit)
#define USE_TLS_ALL_CRL_OFFSET    9  //!< Shift to nine positions (bit)
#define USE_CDP_FROM_CERT_OFFSET 10  //!< Shift to ten positions (bit)

#define OCSP_USAGE_MASK       0x0001      //!< A mask to get the first bit of an usage flag variable
#define LOCAL_CDP_USAGE_MASK  0x0002      //!< A mask to get the second bit of an usage flag variable
#define CERT_CDP_USAGE_MASK   0x0004      //!< A mask to get the third bit of an usage flag variable
#define CA_CDP_USAGE_MASK     0x0008      //!< A mask to get the fourth bit of an usage flag variable
#define CRL_USAGE_MASK        0x0010      //!< A mask to get the fifth bit of an usage flag variable
#define CRL_ALL_USAGE_MASK    0x0020      //!< A mask to get the sixth bit of an usage flag variable
#define CDP_CASHE_ENABLE_MASK 0x0040      //!< A mask to get the seventh bit of an usage flag variable
#define OCSP_RSP_VERIFY_MASK  0x0080      //!< A mask to get the eighth bit of an usage flag variable
#define TLS_PEER_CRL_MASK     0x0100      //!< A mask to get the ninth bit of an usage flag variable
#define TLS_ALL_CRL_MASK      0x0200      //!< A mask to get the tenth bit of an usage flag variable
#define CDP_FROM_CERT_MASK    0x0400      //!< A mask to get the eleventh bit of an usage flag variable

/** \name A config of Revokation Check */
typedef struct REVOKE_CHECK_CONFIG_T {
  UINT16   usageFlag;               //!< OCSP/CDP/CRL/CDP_Cashe/TLS_CRL usage flag
  UINTN    urlOcspLen;              //!< Length in bytes of an OCSP url string
  CHAR16   *pOcspUrl[1];            //!< OCSP url string
  UINTN    urlCdpLen;               //!< Length in bytes of a CDP url string
  CHAR16   *pCdpUrl[1];             //!< CDP url string
} REVOKE_CHECK_CONFIG;

extern EFI_GUID gIniParserDxeProtocolGuid;

#endif // REVOKE_CHECK_CONFIG_INTERNAL_H_
