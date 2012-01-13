/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef TOKEN_VIEWER_H_
#define TOKEN_VIEWER_H_

EFI_STATUS
ProcessTokenViewer (
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *config,
  OUT UINT8 *selectedId,
  OUT UINTN *lengthOfId
);

#endif // TOKEN_VIEWER_H_
