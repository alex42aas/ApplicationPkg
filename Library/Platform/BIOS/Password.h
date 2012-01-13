/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __PASSWORD__H
#define __PASSWORD__H

#include <Base.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>



EFI_STATUS
GenPassword (
  IN UINTN PassLen,
  IN OUT CHAR8 *Password
  );

#endif /* #ifndef __PASSWORD__H */
