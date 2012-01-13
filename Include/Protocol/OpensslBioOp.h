/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

/** \file
 *  \brief OpenSSL BIO direct operations.
 *
 *  If you need a direct access to the OpenSSL library use these methods
 *
*/

#include <openssl/ssl.h>

typedef
BIO *
(EFIAPI *OPENSSL_BIO_NEW) (
  BIO_METHOD *method
);

typedef
int
(EFIAPI *OPENSSL_BIO_FREE) (
  BIO *a
);

typedef
int	
(EFIAPI *OPENSSL_BIO_READ) (
  BIO *b, 
  void *data, 
  int len
);

typedef
int	
(EFIAPI *OPENSSL_BIO_WRITE) (
  BIO *b, 
  const void *data, 
  int len
);

typedef
long
(EFIAPI *OPENSSL_BIO_CTRL) (
  BIO *bp,
  int cmd,
  long larg,
  void *parg
);

typedef
long
(EFIAPI *OPENSSL_BIO_SET_WRITE_BUF_SIZE) (
  BIO *b,
  long size
);

typedef
long
(EFIAPI *OPENSSL_BIO_MAKE_BIO_PAIR) (
  BIO *b1,
  BIO *b2
);

typedef
unsigned long 
(EFIAPI *OPENSSL_BIO_NUMBER_WRITTEN) (
  BIO *bio
);

typedef
BIO *
(EFIAPI *OPENSSL_BIO_NEW_MEM_BUF) (
  void *buf,
  int len
);

typedef
BIO *
(EFIAPI *OPENSSL_BIO_NEW_FILE) (
  const char *filename,
  const char *mode
);

typedef
void
(EFIAPI *OPENSSL_BIO_CLEAR_RETRY_FLAGS) (
  BIO *b
);

typedef
void
(EFIAPI *OPENSSL_BIO_SET_RETRY_WRITE) (
  BIO *b
);

typedef
void
(EFIAPI *OPENSSL_BIO_SET_RETRY_READ) (
  BIO *b
);

typedef
BIO_METHOD *
(EFIAPI *OPENSSL_BIO_S_MEM) (
  void
);

struct _SSL_OPENSSL_BIO_OP {
  OPENSSL_BIO_NEW               BIO_new;
  OPENSSL_BIO_FREE              BIO_free;
  OPENSSL_BIO_READ              BIO_read;
  OPENSSL_BIO_WRITE             BIO_write;
  OPENSSL_BIO_CTRL              BIO_ctrl;
  OPENSSL_BIO_SET_WRITE_BUF_SIZE BIO_set_write_buf_size_func;
  OPENSSL_BIO_MAKE_BIO_PAIR     BIO_make_bio_pair_func;
  OPENSSL_BIO_NUMBER_WRITTEN    BIO_number_written;
  OPENSSL_BIO_NEW_MEM_BUF       BIO_new_mem_buf;
  OPENSSL_BIO_NEW_FILE          BIO_new_file;
  OPENSSL_BIO_CLEAR_RETRY_FLAGS BIO_clear_retry_flags_func;
  OPENSSL_BIO_SET_RETRY_WRITE   BIO_set_retry_write_func;
  OPENSSL_BIO_SET_RETRY_READ    BIO_set_retry_read_func;
  OPENSSL_BIO_S_MEM             BIO_s_mem;
};

typedef struct _SSL_OPENSSL_BIO_OP SSL_OPENSSL_BIO_OP;

