/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef REVOKE_CHECK_CONFIG_H_
#define REVOKE_CHECK_CONFIG_H_

#include <Uefi/UefiBaseType.h>
#include <Protocol/GlobalConfigType.h>

#define REVOKE_CHECK_CONFIG_VAR_NAME L"RevokeChkConfig" //!< Name of gRT variable for the Revoke Check config

#define NOT_USE_REVOKE_CHECK   0  //!< Don't use revocation check

#define NOT_USE     0x00  //!< Don't use setting
#define USE         0x01  //!< Use setting

#define DONT_CHECK_CRL  0x00
#define ALL_CRL_CHECK   0x01
#define CRL_CHECK       0x02

EFI_STATUS
ReadRevokeChkConfig (
  VOID
  );

UINT16
GetOcspUsageFlag(
  VOID
);

CHAR16*
GetOcspUrl(
  VOID
);

UINTN
GetOcspUrlLenght(
  VOID
);

UINT16
GetLocalCdpUsageFlag(
  VOID
);

CHAR16*
GetLocalCdpUrl(
  VOID
);

UINTN
GetLocalCdpUrlLenght(
  VOID
);

UINT16
GetCrlCheckMode(
  VOID
);

UINT16
GetTLSCrlCheckMode( 
  VOID
);

UINT16
GetCDPCasheUsageFlag( 
  VOID
);

UINT16
GetOCSPResponceVerifyUsageFlag(
  VOID
);

UINT16
GetCDPfromCertUsageFlag(
  VOID
);

EFI_STATUS
SetOcspUsageFlag(
  IN UINT16 usageStatus
);

EFI_STATUS
SetOcspUrl(
  IN CHAR16* utlStr
);

EFI_STATUS
SetLocalCdpUsageFlag(
  IN UINT16 usageStatus
);

EFI_STATUS
SetLocalCdpUrl(
  IN CHAR16* utlStr
);

EFI_STATUS
SetCrlCheckMode(
  IN UINT16 crlMode
);

EFI_STATUS
SetCDPCasheUsageFlag(
  IN UINT16 usageFlag
);

EFI_STATUS
SetOCSPResponceVerifyUsageFlag(
  IN UINT16 usageFlag
);

EFI_STATUS
SetTLSCrlCheckMode(
  IN UINT16 crlMode
);

EFI_STATUS
SetCDPfromCertUsageFlag(
  IN UINT16 usageFlag
);

EFI_STATUS
SaveRevokeChkConfig(
  VOID
);

VOID
DeleteRevokeChkConfig(
  VOID
);

CONFIG_ERROR_T
SetConfigFromINIFile (
  CHAR8 *filePath
);

CONFIG_ERROR_T
SetConfigFromData (
  UINT8 *configData,
  UINTN dataLen
);

VOID
ResetReadRevokeChkConfig (
  VOID
  );

#endif // OCSP_CONFIG_H_