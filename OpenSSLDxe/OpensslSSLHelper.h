/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef OPENSSL_SSL_HELPER_H_
#define OPENSSL_SSL_HELPER_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>

#include <Protocol/OpensslProtocol.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

#include "OpensslFunctions.h"

#define OPENSSL_NOT_CONNECTED        101    //client and server
#define OPENSSL_CONNECTING_TLS       102    //client and server
#define OPENSSL_CONNECTING_ERROR_TLS 103    //client and server
#define OPENSSL_CONNECTED_TLS        106    //client and server
#define OPENSSL_ERROR                107    //client and server
#define OPENSSL_CLOSED_BY_PEER       108    //client and server
#define OPENSSL_BIO_ERROR            109    //client and server

#define OPENSSL_CMD_READ             101
#define OPENSSL_CMD_WRITE            102

typedef struct _OPENSSL_HELPER_HANDLE{
  LIST_ENTRY          Link;

  UINTN               Type;

  //common data
  SSL_CTX*            Ctx;
  PKCS7*              CaCertsPkcs7;
  SSL*                Ssl;
  BOOLEAN             IsSslCalled;
  
  //server data
  //client data

  UINTN               ConnectionState;

  //BIO data
  BIO*                SslBio;
  VOID*               BioHandle;
  BIO_READ            BioRead;
  BIO_WRITE           BioWrite;
} OPENSSL_HELPER_HANDLE;

/**
  Create SSL handle
  
  @param  SslHandle               A pointer to the location of newly created Ssl handle
  @param  SslSettings             A pointer to the structure with OpenSSL certificates and private keys
  
  @retval EFI_INVALID_PARAMETER   Function got invalid pointer in parameters
  @retval EFI_OUT_OF_RESOURCES    Cannot allocate memory for internal structures
  @retval EFI_LOAD_ERROR          OpenSSL initiliazing error
  @retval EFI_ABORTED             Error occured, handle not created
  @retval EFI_SUCCESS             Handle succesfully created
**/
EFI_STATUS
EFIAPI
ThisSslCreate(
  IN OPENSSL_PROTOCOL *This,
  OUT EFI_HANDLE *SslHandle,
  IN OPENSSL_SETTINGS *SslSettings
  );

/**
  Start Ssl server/client and try to accept incoming connection/connect to remote server
  
  @param  SslHandle               SSL handle
 
  @retval EFI_INVALID_PARAMETER   Function got invalid parameters
  @retval EFI_LOAD_ERROR          OpenSSL initiliazing error
  @retval EFI_DEVICE_ERROR        OpenSSL connecting error
  @retval EFI_ABORTED             Error occured
  @retval EFI_NOT_READY           Server/client started but yet no connection. Retry SslStart() call
  @retval EFI_SUCCESS             Server/client started and succesfully connected
**/
EFI_STATUS
EFIAPI
ThisSslStart(
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle
  );

/**
  Return num of bytes buffered in OpenSSL internal buffers
  
  @param  SslHandle               SSL handle
  @param  NumOfPendingBytes       Num of bytes available to immediate reading
  
  @retval EFI_INVALID_PARAMETER   Function got invalid handle or pointer in parameters
  @retval EFI_SUCCESS             Some of data successfully readed
**/
EFI_STATUS
EFIAPI
ThisSslPending(
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle,
  OUT UINTN *NumOfPendingBytes
  );

/**
  Try to read data
  
  @param  SslHandle               SSL handle
  @param  Buf                     A pointer to the buffer for read in
  @param  BufSize                 Number of data try to read
  @param  ExchangedLen            Length of really readed data
  
  @retval EFI_INVALID_PARAMETER   Function got invalid handle, command or pointer in parameters
  @retval EFI_NOT_STARTED         Not connected
  @retval EFI_DEVICE_ERROR        OpenSSL data exchanging error
  @retval EFI_ABORTED             Error occured
  @retval EFI_SUCCESS             Some of data successfully readed
**/
EFI_STATUS
EFIAPI
ThisSslRead(
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle,
  IN VOID *Buf,
  IN UINTN BufSize,
  OUT UINTN *ReadedLen
  );

/**
  Try to send data
  
  @param  SslHandle               SSL handle
  @param  Buf                     A pointer to the buffer for send out
  @param  BufSize                 Number of data try to send
  @param  ExchangedLen            Length of really sended data
  
  @retval EFI_INVALID_PARAMETER   Function got invalid handle, command or pointer in parameters
  @retval EFI_NOT_STARTED         Not connected
  @retval EFI_DEVICE_ERROR        OpenSSL data exchanging error
  @retval EFI_ABORTED             Error occured
  @retval EFI_SUCCESS             Some of data successfully sended
**/
EFI_STATUS
EFIAPI
ThisSslWrite(
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle,
  IN CONST VOID *Buf,
  IN UINTN BufSize,
  OUT UINTN *WritedLen
  );

/**
  Destroy SSL handle. If in connected state disconnect.
  
  @param  SslHandle               SSL handle
  @param  MakeFullShutdown        If TRUE - don't finish destroy until peer answer on 'close notify' or error occurs
                                  If FALSE - just send 'close notify', immediately free memory and exit
  
  @retval EFI_INVALID_PARAMETER   Function got invalid handle in parameters
  @retval EFI_NOT_READY           If MakeFullShutdown==TRUE:  peer answer on 'close notify' not yet received,
                                                              handle NOT destroyed, retry call to SslDestroy()
                                  If MakeFullShutdown==FALSE: peer answer on 'close notify' not yet received,
                                                              handle successfully destroyed
  @retval EFI_DEVICE_ERROR        OpenSSL data exchanging error while sendind/reading 'close notify',
                                  handle successfully destroyed
  @retval EFI_SUCCESS             Handle successfully destroyed
**/
EFI_STATUS
EFIAPI
ThisSslDestroy(
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle,
  IN BOOLEAN MakeFullShutdown
  );

#endif /*OPENSSL_SSL_HELPER_H_*/
