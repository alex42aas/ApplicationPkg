/** @file
  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#ifndef __COMPARISON__DATA__HELPER__H
#define __COMPARISON__DATA__HELPER__H


#include <CommonDefs.h>
#include <Library/Messages.h>


#define MAX_COMPARISON_NUM                5

#define MAX_CN_LEN                        255
#define MAX_SUBJECT_LEN                   255
#define MAX_MAIL_LEN                      255
#define MAX_DIGEST_LEN                    64
#define MAX_UID_LEN                       255

#define CT_BIT_CN                         (1 << CT_FLAG_CN)
#define CT_BIT_SUBJECT                    (1 << CT_FLAG_SUBJECT)
#define CT_BIT_MAIL                       (1 << CT_FLAG_MAIL)
#define CT_BIT_DIGEST                     (1 << CT_FLAG_DIGEST)
#define CT_BIT_UID                        (1 << CT_FLAG_UID)


enum {CT_FLAG_CN, CT_FLAG_SUBJECT, CT_FLAG_MAIL, CT_FLAG_DIGEST, CT_FLAG_UID};

EFI_STATUS
GetComparisonDataType16(
  IN CHAR16 *Str,
  IN UINT8 *Type
  );

CHAR8 *
GetComparisonDataName(
  IN UINT8 Type
  );

CHAR16 *
GetComparisonDataName16(
  IN UINT8 Type
  );


#endif /* #ifndef __COMPARISON__DATA__HELPER__H */
