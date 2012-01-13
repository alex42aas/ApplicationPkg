/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "Password.h"

CHAR8 PassSymbols[] = {
  "AaBbCcDdEeFfGgHh0Ii1Gg2Kk3Ll4Mm5Nn6Oo7Pp8Qq9RrSsTtUuVvWwXxYyZz"
  };


#define RAND_MAX  0x7fffffff

STATIC UINTN Next = 1;

/** Compute a pseudo-random number.
  *
  * Compute x = (7^5 * x) mod (2^31 - 1)
  * without overflowing 31 bits:
  *      (2^31 - 1) = 127773 * (7^5) + 2836
  * From "Random number generators: good ones are hard to find",
  * Park and Miller, Communications of the ACM, vol. 31, no. 10,
  * October 1988, p. 1195.
**/
INTN
Rand (
  VOID
  )
{
  INTN hi, lo, x;

  /* Can't be initialized with 0, so use another value. */
  if (Next == 0)
    Next = 123459876;
  hi = Next / 127773;
  lo = Next % 127773;
  x = 16807 * lo - 2836 * hi;
  if (x < 0)
    x += 0x7fffffff;
  return ((Next = x) % ((UINTN)RAND_MAX + 1));
}

VOID
Srand (
  UINTN Seed
  )
{
  Next = Seed;
}


EFI_STATUS
GenPassword (
  IN UINTN PassLen,
  IN OUT CHAR8 *Password
  )
{
  UINTN Idx, Idx2;

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (Password == NULL || PassLen == 0) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Srand ((UINTN)AsmReadTsc());
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  for (Idx = 0; Idx < PassLen; Idx++) {
    Idx2 = Rand () % (sizeof (PassSymbols) - 1);
    DEBUG ((EFI_D_ERROR, " 0x%02X %d \n", PassSymbols[Idx2], Idx2));
    Password[Idx] = PassSymbols[Idx2];
  }
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  return EFI_SUCCESS;
}


