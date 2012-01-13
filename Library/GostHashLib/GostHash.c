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
 *  gosthash.c 
 *
 */

#include <Uefi.h>
#include <Library/GostHashLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>


STATIC gost_subst_block *subst_b = NULL; //&GostR3411_94_CryptoProParamSet;

#if 1
//#include <Library/CommonUtils.h>
VOID
DumpBytes(
  IN UINT8 *Bytes,
  IN UINTN Len
  );
#endif


#define memset(Buf, Val, Len) SetMem(Buf, Len, Val)
#define memcpy(Dst, Src, Len) CopyMem(Dst, Src, Len)

/* lookup tables : each of these has two rotated 4-bit S-Boxes */

UINT32 gost_sbox_1[256];
UINT32 gost_sbox_2[256];
UINT32 gost_sbox_3[256];
UINT32 gost_sbox_4[256];


EFI_STATUS
GostTestVectorCheck(
  CHAR8 *TestVectorString,
  UINT8 *Hash
  )
{

  GOST_HASH_CTX HashCtx;
  UINT8 OutBuf[GOST_DIGEST_SIZE];
      
  ZeroMem(OutBuf, sizeof(GOST_DIGEST));
  GostHashReset(&HashCtx);  
  GostHashUpdate(&HashCtx, TestVectorString, AsciiStrLen(TestVectorString));       
  GostHashFinal(&HashCtx, OutBuf);
  
  if (CompareMem(OutBuf, Hash, GOST_DIGEST_SIZE) == 0) {
    return EFI_SUCCESS;
  }
  return EFI_CRC_ERROR;
}


EFI_STATUS
GostTestVectorCheck2(
  IN gost_hash_ctx *pctx,
  IN CHAR8 *TestVectorString,
  IN UINT8 *Hash
  )
{
  UINT8 OutBuf[GOST_DIGEST_SIZE];
      
  ZeroMem(OutBuf, sizeof(GOST_DIGEST));
  GostHashReset2(pctx);
  GostHashUpdate2(pctx, TestVectorString, AsciiStrLen(TestVectorString));       
  GostHashFinal2(pctx, OutBuf);

  if (CompareMem(OutBuf, Hash, GOST_DIGEST_SIZE) == 0) {
    return EFI_SUCCESS;
  }
  return EFI_CRC_ERROR;
}


VOID
GostHashSelectParamSet (
  UINTN ParamSet
  )
{
  switch (ParamSet) {
  case 1:
    subst_b = &GostR3411_94_CryptoProParamSet;
    break;

  case 0:
  default:
    subst_b = NULL;
    break;
  }
}


EFI_STATUS
GostHashInit2(
  IN gost_hash_ctx *pctx
  )
{  
  UINT8 TestHash[] = {
    0xa0, 0xdd, 0x09, 0x4a, 0xc5, 0x2d, 0xd1, 0x1a,
    0x5d, 0x77, 0xd4, 0x73, 0x3f, 0x95, 0xd6, 0xda,
    0x4a, 0x03, 0x89, 0x38, 0xed, 0x19, 0x48, 0xa7,
    0xaf, 0x68, 0x14, 0x04, 0xdb, 0xd5, 0xdf, 0x7e
  };
  CHAR8 *TestString = "Each man's death diminishes me, For I am involved in mankind. Therefore, send not to know For whom the bell tolls, It tolls for thee.";
  int rv;

  /* before init check test vector */
  rv = init_gost_hash_ctx(pctx, NULL);
  if (!rv) {
    return EFI_CRC_ERROR;
  }
  if (GostTestVectorCheck2(pctx, TestString, TestHash) != EFI_SUCCESS) {
    return EFI_CRC_ERROR;
  }
  init_gost_hash_ctx(pctx, subst_b);
  return EFI_SUCCESS;
}

/*
 *  A macro that performs a full encryption round of GOST 28147-89.
 *  Temporary variable t assumed and variables r and l for left and right
 *  blocks
 */ 

#define GOST_ENCRYPT_ROUND(k1, k2) \
t = (k1) + r; \
l ^= gost_sbox_1[t & 0xff] ^ gost_sbox_2[(t >> 8) & 0xff] ^ \
gost_sbox_3[(t >> 16) & 0xff] ^ gost_sbox_4[t >> 24]; \
t = (k2) + l; \
r ^= gost_sbox_1[t & 0xff] ^ gost_sbox_2[(t >> 8) & 0xff] ^ \
gost_sbox_3[(t >> 16) & 0xff] ^ gost_sbox_4[t >> 24]; \

/* encrypt a block with the given key */

#define GOST_ENCRYPT(key) \
GOST_ENCRYPT_ROUND(key[0], key[1]) \
GOST_ENCRYPT_ROUND(key[2], key[3]) \
GOST_ENCRYPT_ROUND(key[4], key[5]) \
GOST_ENCRYPT_ROUND(key[6], key[7]) \
GOST_ENCRYPT_ROUND(key[0], key[1]) \
GOST_ENCRYPT_ROUND(key[2], key[3]) \
GOST_ENCRYPT_ROUND(key[4], key[5]) \
GOST_ENCRYPT_ROUND(key[6], key[7]) \
GOST_ENCRYPT_ROUND(key[0], key[1]) \
GOST_ENCRYPT_ROUND(key[2], key[3]) \
GOST_ENCRYPT_ROUND(key[4], key[5]) \
GOST_ENCRYPT_ROUND(key[6], key[7]) \
GOST_ENCRYPT_ROUND(key[7], key[6]) \
GOST_ENCRYPT_ROUND(key[5], key[4]) \
GOST_ENCRYPT_ROUND(key[3], key[2]) \
GOST_ENCRYPT_ROUND(key[1], key[0]) \
t = r; \
r = l; \
l = t;

/* 
 *  "chi" compression function. the result is stored over h
 */

VOID gosthash_compress(UINT32 *h, UINT32 *m)
{
  int i;
  UINT32 l, r, t, key[8], u[8], v[8], w[8], s[8];
  
  memcpy(u, h, sizeof(u));
  memcpy(v, m, sizeof(u));
  
  for (i = 0; i < 8; i += 2)
    {        
      w[0] = u[0] ^ v[0];	       /* w = u xor v */
      w[1] = u[1] ^ v[1];
      w[2] = u[2] ^ v[2];
      w[3] = u[3] ^ v[3];
      w[4] = u[4] ^ v[4];
      w[5] = u[5] ^ v[5];
      w[6] = u[6] ^ v[6];
      w[7] = u[7] ^ v[7];      
      
      /* P-Transformation */
      
      key[0] = (w[0]  & 0x000000ff) | ((w[2] & 0x000000ff) << 8) |
	((w[4] & 0x000000ff) << 16) | ((w[6] & 0x000000ff) << 24);
      key[1] = ((w[0] & 0x0000ff00) >> 8)  | (w[2]  & 0x0000ff00) |
	((w[4] & 0x0000ff00) << 8) | ((w[6] & 0x0000ff00) << 16);
      key[2] = ((w[0] & 0x00ff0000) >> 16) | ((w[2] & 0x00ff0000) >> 8) |
	(w[4] & 0x00ff0000) | ((w[6] & 0x00ff0000) << 8);
      key[3] = ((w[0] & 0xff000000) >> 24) | ((w[2] & 0xff000000) >> 16) |
	((w[4] & 0xff000000) >> 8) | (w[6] & 0xff000000);  
      key[4] = (w[1] & 0x000000ff) | ((w[3] & 0x000000ff) << 8) |
	((w[5] & 0x000000ff) << 16) | ((w[7] & 0x000000ff) << 24);
      key[5] = ((w[1] & 0x0000ff00) >> 8) | (w[3]  & 0x0000ff00) |
	((w[5] & 0x0000ff00) << 8) | ((w[7] & 0x0000ff00) << 16);
      key[6] = ((w[1] & 0x00ff0000) >> 16) | ((w[3] & 0x00ff0000) >> 8) |
	(w[5] & 0x00ff0000) | ((w[7] & 0x00ff0000) << 8);
      key[7] = ((w[1] & 0xff000000) >> 24) | ((w[3] & 0xff000000) >> 16) |
	((w[5] & 0xff000000) >> 8) | (w[7] & 0xff000000);  
            
      r = h[i];			       /* encriphering transformation */
      l = h[i + 1];      
      GOST_ENCRYPT(key);
      
      s[i] = r;
      s[i + 1] = l;
            
      if (i == 6)
	break;
      
      l = u[0] ^ u[2];		       /* U = A(U) */
      r = u[1] ^ u[3];
      u[0] = u[2];
      u[1] = u[3];
      u[2] = u[4];
      u[3] = u[5];
      u[4] = u[6];
      u[5] = u[7];
      u[6] = l;
      u[7] = r;
            
      if (i == 2)		       /* Constant C_3 */
	{
	  u[0] ^= 0xff00ff00; 
	  u[1] ^= 0xff00ff00; 
	  u[2] ^= 0x00ff00ff;
	  u[3] ^= 0x00ff00ff;
	  u[4] ^= 0x00ffff00;
	  u[5] ^= 0xff0000ff;
	  u[6] ^= 0x000000ff;
	  u[7] ^= 0xff00ffff;	    
	}
      
      l = v[0];			       /* V = A(A(V)) */
      r = v[2];
      v[0] = v[4];
      v[2] = v[6];
      v[4] = l ^ r;
      v[6] = v[0] ^ r;
      l = v[1];
      r = v[3];
      v[1] = v[5];
      v[3] = v[7];
      v[5] = l ^ r;
      v[7] = v[1] ^ r;
    }
  
  /* 12 rounds of the LFSR (computed from a product matrix) and xor in M */
  
  u[0] = m[0] ^ s[6];
  u[1] = m[1] ^ s[7];
  u[2] = m[2] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xffff) ^ 
    (s[1] & 0xffff) ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[6] ^ (s[6] << 16) ^
    (s[7] & 0xffff0000) ^ (s[7] >> 16);
  u[3] = m[3] ^ (s[0] & 0xffff) ^ (s[0] << 16) ^ (s[1] & 0xffff) ^ 
    (s[1] << 16) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16) ^
    (s[3] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ 
    (s[7] << 16) ^ (s[7] >> 16);
  u[4] = m[4] ^ 
    (s[0] & 0xffff0000) ^ (s[0] << 16) ^ (s[0] >> 16) ^ 
    (s[1] & 0xffff0000) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16) ^
    (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[6] << 16) ^ 
    (s[6] >> 16) ^(s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);
  u[5] = m[5] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xffff0000) ^
    (s[1] & 0xffff) ^ s[2] ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^
    (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^  (s[6] << 16) ^ 
    (s[6] >> 16) ^ (s[7] & 0xffff0000) ^ (s[7] << 16) ^ (s[7] >> 16);
  u[6] = m[6] ^ s[0] ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[3] ^ (s[3] >> 16) ^
    (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16) ^ s[6] ^ 
    (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] << 16);
  u[7] = m[7] ^ (s[0] & 0xffff0000) ^ (s[0] << 16) ^ (s[1] & 0xffff) ^ 
    (s[1] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ s[4] ^ (s[4] >> 16) ^
    (s[5] << 16) ^ (s[5] >> 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ 
    (s[7] << 16) ^ (s[7] >> 16);
      
  /* 16 * 1 round of the LFSR and xor in H */
  
  v[0] = h[0] ^ (u[1] << 16) ^ (u[0] >> 16);
  v[1] = h[1] ^ (u[2] << 16) ^ (u[1] >> 16);
  v[2] = h[2] ^ (u[3] << 16) ^ (u[2] >> 16);
  v[3] = h[3] ^ (u[4] << 16) ^ (u[3] >> 16);
  v[4] = h[4] ^ (u[5] << 16) ^ (u[4] >> 16);
  v[5] = h[5] ^ (u[6] << 16) ^ (u[5] >> 16);
  v[6] = h[6] ^ (u[7] << 16) ^ (u[6] >> 16);
  v[7] = h[7] ^ (u[0] & 0xffff0000) ^ (u[0] << 16) ^ (u[7] >> 16) ^
    (u[1] & 0xffff0000) ^ (u[1] << 16) ^ (u[6] << 16) ^ (u[7] & 0xffff0000);
  
  /* 61 rounds of LFSR, mixing up h (computed from a product matrix) */

  h[0] = (v[0] & 0xffff0000) ^ (v[0] << 16) ^ (v[0] >> 16) ^ (v[1] >> 16) ^ 
    (v[1] & 0xffff0000) ^ (v[2] << 16) ^ (v[3] >> 16) ^ (v[4] << 16) ^
    (v[5] >> 16) ^ v[5] ^ (v[6] >> 16) ^ (v[7] << 16) ^ (v[7] >> 16) ^ 
    (v[7] & 0xffff);
  h[1] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xffff0000) ^ (v[1] & 0xffff) ^ 
    v[2] ^ (v[2] >> 16) ^ (v[3] << 16) ^ (v[4] >> 16) ^ (v[5] << 16) ^ 
    (v[6] << 16) ^ v[6] ^ (v[7] & 0xffff0000) ^ (v[7] >> 16);
  h[2] = (v[0] & 0xffff) ^ (v[0] << 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^ 
    (v[1] & 0xffff0000) ^ (v[2] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^
    (v[5] >> 16) ^ v[6] ^ (v[6] >> 16) ^ (v[7] & 0xffff) ^ (v[7] << 16) ^
    (v[7] >> 16);
  h[3] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xffff0000) ^ 
    (v[1] & 0xffff0000) ^ (v[1] >> 16) ^ (v[2] << 16) ^ (v[2] >> 16) ^ v[2] ^ 
    (v[3] << 16) ^ (v[4] >> 16) ^ v[4] ^ (v[5] << 16) ^ (v[6] << 16) ^ 
    (v[7] & 0xffff) ^ (v[7] >> 16);
  h[4] = (v[0] >> 16) ^ (v[1] << 16) ^ v[1] ^ (v[2] >> 16) ^ v[2] ^ 
    (v[3] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ (v[5] >> 16) ^ 
    v[5] ^ (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16);
  h[5] = (v[0] << 16) ^ (v[0] & 0xffff0000) ^ (v[1] << 16) ^ (v[1] >> 16) ^ 
    (v[1] & 0xffff0000) ^ (v[2] << 16) ^ v[2] ^ (v[3] >> 16) ^ v[3] ^ 
    (v[4] << 16) ^ (v[4] >> 16) ^ v[4] ^ (v[5] << 16) ^ (v[6] << 16) ^
    (v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ (v[7] >> 16) ^ (v[7] & 0xffff0000);
  h[6] = v[0] ^ v[2] ^ (v[2] >> 16) ^ v[3] ^ (v[3] << 16) ^ v[4] ^ 
    (v[4] >> 16) ^ (v[5] << 16) ^ (v[5] >> 16) ^ v[5] ^ (v[6] << 16) ^ 
    (v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ v[7];
  h[7] = v[0] ^ (v[0] >> 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^ (v[2] << 16) ^
    (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ v[4] ^ (v[5] >> 16) ^ v[5] ^
    (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16) ^ v[7];
}

/* Clear the state of the given context structure. */

VOID GostHashReset(GOST_HASH_CTX *ctx)
{
  memset(ctx->sum, 0, 32);
  memset(ctx->hash, 0, 32);
  memset(ctx->len, 0, 32);
  memset(ctx->partial, 0, 32);
  ctx->partial_bytes = 0;  
}

EFI_STATUS
GostHashReset2(
  IN gost_hash_ctx *ctx
  )
{
  return start_hash(ctx) == 1 ? EFI_SUCCESS : EFI_ABORTED;
}


/* Mix in a 32-byte chunk ("stage 3") */

VOID gosthash_bytes(GOST_HASH_CTX *ctx, const UINT8 *buf, UINTN bits)
{
  int i, j;
  UINT32 a, b, c, m[8];
  
  /* convert bytes to a long words and compute the sum */
  
  j = 0;
  c = 0;
  for (i = 0; i < 8; i++)
    {
      a = ((UINT32) buf[j]) | 
	(((UINT32) buf[j + 1]) << 8) | 
	(((UINT32) buf[j + 2]) << 16) | 
	(((UINT32) buf[j + 3]) << 24);
      j += 4;
      m[i] = a;
      b = ctx->sum[i];
      c = a + c + ctx->sum[i];
      ctx->sum[i] = c;
      c = ((c < a) || (c < b)) ? 1 : 0;     
    }
    
  /* compress */
  
  gosthash_compress(ctx->hash, m);
  
  /* a 64-bit counter should be sufficient */
  
  ctx->len[0] += (UINT32) bits;
  if (ctx->len[0] < (UINT32) bits)
    ctx->len[1]++;  
}

/* Mix in len bytes of data for the given buffer. */

VOID GostHashUpdate(GOST_HASH_CTX *ctx, const UINT8 *buf, UINTN len)
{
  UINTN i, j;
  
  i = ctx->partial_bytes;
  j = 0;
  while (i < 32 && j < len)
    ctx->partial[i++] = buf[j++];
  
  if (i < 32)
    {
      ctx->partial_bytes = i;
      return;
    }  
  gosthash_bytes(ctx, ctx->partial, 256);
  
  while ((j + 32) < len)
    {
      gosthash_bytes(ctx, &buf[j], 256);
      j += 32;
    }
  
  i = 0;
  while (j < len)
    ctx->partial[i++] = buf[j++];
  ctx->partial_bytes = i;
}

VOID 
GostHashUpdate2(
  IN OUT gost_hash_ctx *ctx, 
  IN const UINT8 *buf, 
  IN UINTN len
  )
{
  hash_block(ctx, buf, len);
}



/* Compute and save the 32-byte digest. */

VOID GostHashFinal(GOST_HASH_CTX *ctx, GOST_DIGEST digest)
{
  int i, j;
  UINT32 a;
  
  /* adjust and mix in the last chunk */
  
  if (ctx->partial_bytes > 0)
    {
      memset(&ctx->partial[ctx->partial_bytes], 0, 32 - ctx->partial_bytes);
      gosthash_bytes(ctx, ctx->partial, ctx->partial_bytes << 3);      
    }
  
  /* mix in the length and the sum */
  
  gosthash_compress(ctx->hash, ctx->len);  
  gosthash_compress(ctx->hash, ctx->sum);  
  
  /* convert the output to bytes */
  
  j = 0;
  for (i = 0; i < 8; i++)
    {
      a = ctx->hash[i];
      digest[j] = (UINT8) a;
      digest[j + 1] = (UINT8) (a >> 8);
      digest[j + 2] = (UINT8) (a >> 16);
      digest[j + 3] = (UINT8) (a >> 24);	
      j += 4;
    }  
}

VOID 
GostHashFinal2(
  IN gost_hash_ctx *ctx,
  IN OUT GOST_DIGEST digest
  )
{
  finish_hash (ctx, digest);
  done_gost_hash_ctx (ctx);
}


