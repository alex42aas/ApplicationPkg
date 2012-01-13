/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

/*
 */

#ifndef GOSTHASH_H
#define GOSTHASH_H


#include <Uefi/UefiBaseType.h>
#include "OpenSSLGostHash/gost_hash.h"

/* State structure */

typedef struct 
{
  UINT32 sum[8];
  UINT32 hash[8];
  UINT32 len[8];
  UINT8  partial[32];
  UINTN  partial_bytes;  
} GOST_HASH_CTX;
  
/* Compute some lookup-tables that are needed by all other functions. */
#if 0
EFI_STATUS
EFIAPI
GostHashInit (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );
#endif

EFI_STATUS
GostHashInit2(
  IN gost_hash_ctx *pctx
  );


/* Clear the state of the given context structure. */

VOID 
GostHashReset(
	GOST_HASH_CTX *Ctx
	);  

EFI_STATUS
GostHashReset2(
  IN gost_hash_ctx *ctx
  );


/* Mix in len bytes of data for the given buffer. */

VOID 
GostHashUpdate(
	GOST_HASH_CTX *ctx, 
	const UINT8 *buf, 
	UINTN len
	);

VOID 
GostHashUpdate2(
  IN OUT gost_hash_ctx *ctx, 
  IN const UINT8 *buf, 
  IN UINTN len
  );


/* Compute and save the 32-byte digest. */


#define GOST_DIGEST_SIZE 32 
typedef UINT8 GOST_DIGEST[GOST_DIGEST_SIZE];

VOID GostHashFinal(
    GOST_HASH_CTX *ctx, 
    GOST_DIGEST digest
    );

VOID 
GostHashFinal2(
  IN gost_hash_ctx *ctx,
  IN OUT GOST_DIGEST digest
  );

VOID
GostHashSelectParamSet (
  UINTN ParamSet
  );


#endif /* GOSTHASH_H */
