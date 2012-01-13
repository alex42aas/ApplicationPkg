/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef CERT_VIEWER_H_
#define CERT_VIEWER_H_

typedef enum {
  P7B_CHAIN,
  CRL_OBJ,
  CERT_OBJ
} OBJECT_T;

EFI_STATUS
ProcessCertViewer (
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *config,
  IN OBJECT_T type,
  IN CHAR8 *objectData,
  IN UINTN objectDataLen
);

#endif // CERT_VIEWER_H_
