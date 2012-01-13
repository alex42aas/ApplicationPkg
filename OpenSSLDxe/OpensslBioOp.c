/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Protocol/OpensslBioOp.h>

#include "OpenSSLDxeInternal.h"

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

static SSL_OPENSSL_BIO_OP internalBioOperations;

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
BIO *
OPENSSL_BIO_new (
  BIO_METHOD *method
)
{
  BIO *bio;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  bio = BIO_new(method);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return bio;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int
OPENSSL_BIO_free (
  BIO *a
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = BIO_free(a);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_BIO_read(
  BIO *b, 
  void *data, 
  int len
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = BIO_read(b, data, len);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int	
OPENSSL_BIO_write(
  BIO *b, 
  const void *data, 
  int len
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = BIO_write(b, data, len);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
long
OPENSSL_BIO_ctrl(
  BIO *bp,
  int cmd,
  long larg,
  void *parg
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = BIO_ctrl(bp, cmd, larg, parg);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
long
OPENSSL_BIO_set_write_buf_size(
  BIO *b,
  long size
)
{
  long retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = BIO_set_write_buf_size(b, size);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
long
OPENSSL_BIO_make_bio_pair(
  BIO *b1,
  BIO *b2
)
{
  long retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = BIO_make_bio_pair(b1, b2);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
unsigned long 
OPENSSL_BIO_number_written(
  BIO *bio
)
{
  int retval;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  retval = BIO_number_written(bio);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
BIO *
OPENSSL_BIO_new_mem_buf (
  void *buf,
  int len
)
{
  BIO *bio;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  bio = BIO_new_mem_buf(buf, len);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return bio;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
BIO *
OPENSSL_BIO_new_file (
  const char *filename,
  const char *mode
)
{
  BIO *bio;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  bio = BIO_new_file(filename, mode);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return bio;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_BIO_clear_retry_flags (
  BIO *b
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  BIO_clear_retry_flags(b);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_BIO_set_retry_write (
  BIO *b
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  BIO_set_retry_write(b);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
void
OPENSSL_BIO_set_retry_read (
  BIO *b
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  BIO_set_retry_read(b);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
BIO_METHOD *
OPENSSL_BIO_s_mem(
  void
)
{
  BIO_METHOD *method;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  method = BIO_s_mem();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return method;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Initialize OpenSSL direct Bio operations structure */
//------------------------------------------------------------------------------
VOID*
InitBioDirectOp (
  IN VOID
)
{
  internalBioOperations.BIO_new                     = OPENSSL_BIO_new;
  internalBioOperations.BIO_free                    = OPENSSL_BIO_free;
  internalBioOperations.BIO_read                    = OPENSSL_BIO_read;
  internalBioOperations.BIO_write                   = OPENSSL_BIO_write;
  internalBioOperations.BIO_ctrl                    = OPENSSL_BIO_ctrl;
  internalBioOperations.BIO_set_write_buf_size_func = OPENSSL_BIO_set_write_buf_size;
  internalBioOperations.BIO_make_bio_pair_func      = OPENSSL_BIO_make_bio_pair;
  internalBioOperations.BIO_number_written          = OPENSSL_BIO_number_written;
  internalBioOperations.BIO_new_mem_buf             = OPENSSL_BIO_new_mem_buf;
  internalBioOperations.BIO_new_file                = OPENSSL_BIO_new_file;
  internalBioOperations.BIO_clear_retry_flags_func  = OPENSSL_BIO_clear_retry_flags;
  internalBioOperations.BIO_set_retry_write_func    = OPENSSL_BIO_set_retry_write;
  internalBioOperations.BIO_set_retry_read_func     = OPENSSL_BIO_set_retry_read;
  internalBioOperations.BIO_s_mem                   = OPENSSL_BIO_s_mem;

  return (VOID*)&internalBioOperations;
}
//------------------------------------------------------------------------------

