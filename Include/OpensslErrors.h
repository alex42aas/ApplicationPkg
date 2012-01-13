/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef OPENSSL_ERRORS_H_
#define OPENSSL_ERRORS_H_

typedef enum {
              OSSL_VERIFY_SUCCESS,                           // 0
              OSSL_INVALID_SIGNATURE,                        // 1
              OSSL_CERT_REVOKED,                             // 2
              OSSL_UNKNOWN_CERT_FORMAT,                      // 3
              OSSL_UNKNOWN_CRL_FORMAT,                       // 4
              OSSL_UNKNOWN_KEY_FORMAT,                       // 5
              OSSL_UNKNOWN_PKCS7_FORMAT,                     // 6
              OSSL_CANT_GET_PKEY_FROM_CERT,                  // 7
              OSSL_MEMORY_ERROR,                             // 8
              OSSL_INVALID_PARAM,                            // 9
              OSSL_INVALID_CRL_SIGNATURE,                    // 10
              OSSL_ERROR_TO_LOAD_CRL,                        // 11
              OSSL_ERROR_TO_LOAD_ISSUER_CERT,                // 12
              OSSL_ERROR_TO_LOAD_ISSUER_CERT_LOCALLY,        // 13
              OSSL_INIT_ERROR,                               // 14
              OSSL_VERIFY_ERROR,                             // 15
              OSSL_SUCCESS_CONVERT_TO_ASN,                   // 16
              OSSL_SUCCESS_CONVERT_TO_PEM,                   // 17
              OSSL_PKCS7_NOT_SIGNED,                         // 18
              OSSL_CANT_GET_TRUSTED_CERTS,                   // 19
              OSSL_CERT_NOT_YET_VALID,                       // 20
              OSSL_CERT_HAS_EXPIRED,                         // 21
              OSSL_CRL_NOT_YET_VALID,                        // 22
              OSSL_CRL_HAS_EXPIRED,                          // 23
              OSSL_UNSUPPORTED_DIGEST_ALGORITM,              // 24
              OSSL_OCSP_ERROR_MAKE_REQUEST,                  // 25
              OSSL_OCSP_URL_ERROR,                           // 26
              OSSL_OCSP_URL_EMPTY,                           // 27
              OSSL_OCSP_RESPONSE_VERIFICATION,               // 28
              OSSL_OCSP_RESPONDER_QUERY_FAILED,              // 29
              OSSL_OCSP_CERT_UNKNOWN,                        // 30
              OSSL_ERROR_IN_CRL_LAST_UPDATE_FIELD,           // 31
              OSSL_ERROR_TO_SAVE_CRL_TO_LOCAL_STACK,         // 32
              OSSL_ERROR_TO_SAVE_BIO,                        // 33
              OSSL_ERROR_TO_SAVE_CRL_TO_CA_CHAIN,            // 34
              OSSL_NO_NEED_TO_SAVE_CRLS,                     // 35
              OSSL_ERR_UNABLE_TO_GET_CRL,                    // 36
              OSSL_ERR_UNABLE_TO_GET_CERT_CDP_EXT,           // 37
              OSSL_ERR_PROTOCOL_NOT_FOUND_INTERNAL,          // 38
              OSSL_ERR_CANT_GET_SUBJECT_NAME,                // 39
              OSSL_ERR_CANT_GET_NOT_BEFORE_DATE,             // 40
              OSSL_ERR_CANT_GET_NOT_AFTER_DATE,              // 41
              OSSL_ERR_CANT_GET_ISSUER_NAME,                 // 42
              OSSL_NO_ERROR,                                 // 43
              OSSL_ERR_CANT_GET_SERIAL,                      // 44
              OSSL_ERR_IN_CERT_NOT_BEFORE_FIELD,             // 45
              OSSL_ERR_IN_CERT_NOT_AFTER_FIELD,              // 46
              OSSL_ERR_IN_CRL_LAST_UPDATE_FIELD,             // 47
              OSSL_ERR_IN_CRL_NEXT_UPDATE_FIELD,             // 48
              OSSL_ERR_VERIFY_WITH_USER_PKEY,                // 49
			  OSSL_ERR_RUTOKEN_SUPPORT_ERR					 // 50	
              }
  OSSL_STATUS;

#endif // OPENSSL_ERRORS_H_