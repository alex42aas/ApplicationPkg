/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "RemoteCfgTlsDxe.h"

#if 1
#define LOG(MSG)
#else
//be very verbose
#define LOG(MSG) DEBUG(MSG)
#endif

STATIC REMOTE_CFG_TLS_PRIVATE_DATA gPrivateData;

REMOTE_CFG_TLS_WORK_DATA gRCTDataInitTemplate = {
  ST_RESTARTING3,//State
  EFI_ALREADY_STARTED,//Status
  FALSE,//IsWorked
  NULL,//CallbackRun
  NULL,//CallbackRunIdle
  FALSE,//ResetRate
  NULL,//StopAttempt
  0,//Attempts
  NULL,//Settings
  {0,0,0,{0,0,0,0},NULL,0,NULL,0,NULL,0},//TcpSettings

  NULL,//ServerIp
  0, //ServerIpNum
  0, //ServerIpCur
  FALSE, //ServerIpTryNext
  
  NULL,//RCPkt
  NULL,//RCPktHandle
  NULL,//Tcp
  NULL,//TcpConn  
  NULL,//Dns

  NULL,//InChunk
  INITIALIZE_LIST_HEAD_VARIABLE(gRCTDataInitTemplate.OutQueue),//OutQueue
  NULL//TmpChunk
};
REMOTE_CFG_TLS_WORK_DATA* gRCTData = NULL;
EFI_STATUS gRCTStatus = EFI_NOT_STARTED;

STATIC
EFI_STATUS
ProcessingRxPackets (
  IN REMOTE_CFG_PKT_PROTOCOL *RCPkt,
  IN EFI_HANDLE RCPktHandle,
  IN UINT8 *PktData,
  IN UINTN PktDataLen
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  STATIC HISTORY_HANDLER_PROTOCOL *gHistoryHandlerProtocol;
  STATIC MULTIBOOT_PROTOCOL *gMultiboot;
  STATIC BOOLEAN bMultibootStarted;
  
  if (RCPkt == NULL || PktData == NULL || PktDataLen == 0) {
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  if (gHistoryHandlerProtocol == NULL) {
    Status = gBS->LocateProtocol (
                &gHistoryHandlerProtocolGuid, 
                NULL, 
                (VOID **) &gHistoryHandlerProtocol
                );
    LOG ((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  }

  if (gMultiboot == NULL) {
    Status = gBS->LocateProtocol (
                &gMultibootProtocolGuid, 
                NULL, 
                (VOID **) &gMultiboot
                );
    LOG ((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
  }

  if (!RCPkt->ProtocolStarted (RCPkt, RCPktHandle)) {
    Status = RCPkt->SendAns (
              RCPkt,
              RCPktHandle,
              PktData[RCFG_PKT_ADDR_OFFS], // Addr
              PktData[RCFG_PKT_OPCODE_OFFS] | RCFG_OPCODE_ANS_FLAG, //Func
              SC_PROTOCOL_NOT_INIT,
              0,
              NULL,
              CRC_TYPE_LAST_RECEIVED
              );
    return EFI_NOT_READY;
  }

  if (gMultiboot && gMultiboot->ProcessingRemoteCtrlPkt) {
    bMultibootStarted = TRUE;
  }

  if (!bMultibootStarted) {
    return EFI_NOT_READY;
  }

  switch (PktData[RCFG_PKT_OPCODE_OFFS]) {
  case FUNC_HISTORY_SET_UNLOADED_FLAG:
    {
      UINT32 DataLen, AmountRec;
      UINT8 Sc = SC_FUNC_ERR;

      DataLen = ReadUnaligned32((UINT32*)&PktData[RCFG_PKT_LEN_OFFS]);
      if (DataLen < 8 || (DataLen & 0x3)) {
        Sc = SC_WRONG_DATA_LEN;
      } else {
        AmountRec = ReadUnaligned32((UINT32*)&PktData[RCFG_PKT_DATA_OFFS]);
        if ((AmountRec + 1) * sizeof(UINT32) != DataLen) {
          Sc = SC_WRONG_DATA_LEN;
        } else {
          if (gHistoryHandlerProtocol) {
            Status = gHistoryHandlerProtocol->MarkAsUnloaded (
                      gHistoryHandlerProtocol, 
                      AmountRec,
                      (UINT32*)&PktData[RCFG_PKT_DATA_OFFS + sizeof(UINT32)]
                      );
            if (!EFI_ERROR(Status)) {
              Sc = SC_SUCCESS;
            }
          }
        }
      }

      Status = RCPkt->SendAns (
            RCPkt,
            RCPktHandle,
            PktData[RCFG_PKT_ADDR_OFFS],
            PktData[RCFG_PKT_OPCODE_OFFS] | RCFG_OPCODE_ANS_FLAG,
            Sc,
            0,
            NULL,
            CRC_TYPE_LAST_RECEIVED);
      LOG ((EFI_D_ERROR, "%a.%d Status=%r\n", 
        __FUNCTION__, __LINE__, Status));
    }
    break;

  case FUNC_HISTORY_GET_CSV:
  case FUNC_HISTORY_UNLOAD:
    {
      CHAR16 *Csv16Str = NULL;
      UINT8 Sc = SC_FUNC_ERR;

      LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      if (PktData[RCFG_PKT_DATA_OFFS] == 0x01) {
        if (gHistoryHandlerProtocol) {
          if (PktData[RCFG_PKT_OPCODE_OFFS] == FUNC_HISTORY_GET_CSV) {
            Status = gHistoryHandlerProtocol->GetCsv16 (
                      gHistoryHandlerProtocol, 
                      &Csv16Str
                      );
          } else {
            Status = gHistoryHandlerProtocol->UnloadCsv16 (
                      gHistoryHandlerProtocol, 
                      &Csv16Str
                      );
          }
        } else {
          Status = EFI_UNSUPPORTED;
          Sc = SC_OPCODE_UNSUPPORTED;
        }
      } else {
        Status = EFI_UNSUPPORTED;
        Sc = SC_OPCODE_UNSUPPORTED;
      }

      LOG ((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
      if (EFI_ERROR(Status)) {
        Status = RCPkt->SendAns (
            RCPkt,
            RCPktHandle,
            PktData[RCFG_PKT_ADDR_OFFS],
            PktData[RCFG_PKT_OPCODE_OFFS] | RCFG_OPCODE_ANS_FLAG,
            Sc,
            0,
            NULL,
            CRC_TYPE_LAST_RECEIVED);
      } else {
        Status = RCPkt->SendAns (
            RCPkt,
            RCPktHandle,
            PktData[RCFG_PKT_ADDR_OFFS],
            PktData[RCFG_PKT_OPCODE_OFFS] | RCFG_OPCODE_ANS_FLAG,
            SC_SUCCESS,
            Csv16Str ? StrLen (Csv16Str) * 2 : 0,
            (UINT8*)Csv16Str,
            CRC_TYPE_LAST_RECEIVED);
      }
      if (Csv16Str) {
        FreePool (Csv16Str);
      }
      LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    }
    break;

  case FUNC_GET_BIOS_INFO:
    {
      struct tMainFvInfo TmpMainFvInfo;
      BiosInfoRecord *pBiosInfo;
      CHAR16 UnicodeStr[1024];
      UINT8 Sc = SC_FUNC_ERR;
      EFI_GUID SysGuid = {0};
      if (-1 != FindMainFv(MAIN_FV_GUID_STR, &TmpMainFvInfo)) {
        pBiosInfo = (BiosInfoRecord*)FindBiosInfoRecord(&TmpMainFvInfo);
        Status = GetSystemGuidFromVolume (&SysGuid);
        if (NULL != pBiosInfo) {
          UnicodeSPrint(UnicodeStr, sizeof(UnicodeStr), L"%a\n%a\n%g\n%g",
            pBiosInfo->BiosBuildStr,
            pBiosInfo->BiosVerStr,
            pBiosInfo->PlatformGuid,
            &SysGuid);
          Sc = SC_SUCCESS;
        }
      } 
      Status = RCPkt->SendAns (
                  RCPkt,
                  RCPktHandle,
                  PktData[RCFG_PKT_ADDR_OFFS],
                  PktData[RCFG_PKT_OPCODE_OFFS] | RCFG_OPCODE_ANS_FLAG,
                  Sc,
                  Sc == SC_SUCCESS ? 
                    StrLen (UnicodeStr) * sizeof(*UnicodeStr) : 0,
                  Sc == SC_SUCCESS ? (UINT8*)UnicodeStr : NULL,
                  CRC_TYPE_LAST_RECEIVED
                  );
  
    }
    break;

  case FUNC_GET_XML_CONFIG:
    if (gMultiboot && gMultiboot->ProcessingRemoteCtrlPkt != NULL) {
      UINT8 *XmlData;
      UINTN XmlDataLen = 0;
      
      XmlData = gMultiboot->GetXmlConfigData(&XmlDataLen);
      if (XmlData && XmlDataLen > 0) {
        Status = RCPkt->SendAns (
                  RCPkt,
                  RCPktHandle,
                  PktData[RCFG_PKT_ADDR_OFFS],
                  PktData[RCFG_PKT_OPCODE_OFFS] | RCFG_OPCODE_ANS_FLAG,
                  SC_SUCCESS,
                  XmlDataLen,
                  XmlData,
                  CRC_TYPE_LAST_RECEIVED
                  );
      } else {
        Status = RCPkt->SendAns (
              RCPkt,
              RCPktHandle,
              PktData[RCFG_PKT_ADDR_OFFS], // Addr
              PktData[RCFG_PKT_OPCODE_OFFS] | RCFG_OPCODE_ANS_FLAG, //Func
              SC_CANT_GET_XML_CFG,
              0,
              NULL,
              CRC_TYPE_LAST_RECEIVED
              );      
      }
    } else {
      Status = RCPkt->SendAns (
              RCPkt,
              RCPktHandle,
              PktData[RCFG_PKT_ADDR_OFFS], // Addr
              PktData[RCFG_PKT_OPCODE_OFFS] | RCFG_OPCODE_ANS_FLAG, //Func
              SC_CANT_LOCATE_MDZ_PROTO,
              0,
              NULL,
              CRC_TYPE_LAST_RECEIVED
              );
    }
    break;

  default:
    if (gMultiboot && gMultiboot->ProcessingRemoteCtrlPkt != NULL) {
      Status = gMultiboot->ProcessingRemoteCtrlPkt (
              gMultiboot,
              PktData,
              PktDataLen,
              RCPkt,
              RCPktHandle
              );
    } else {
      Status = RCPkt->SendAns (
              RCPkt,
              RCPktHandle,
              PktData[RCFG_PKT_ADDR_OFFS], // Addr
              PktData[RCFG_PKT_OPCODE_OFFS] | RCFG_OPCODE_ANS_FLAG, //Func
              SC_PERMISSION_DENIED,
              0,
              NULL,
              CRC_TYPE_LAST_RECEIVED
              );
    }
    break;
  }
  return EFI_SUCCESS;
}


/**
  Remote Config Protocol working callback
**/
VOID
EFIAPI 
RemoteCfgTlsCallback(
  IN EFI_EVENT Event,
  IN VOID *Context
  ) 
{
  EFI_STATUS Status;
  UINTN Result, CurTimeout;
  REMOTE_CFG_TLS_WORK_DATA* RCTData = NULL;
  BOOLEAN RetryReadOrWrite;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (Context == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d Context = 0x%X\n", __FUNCTION__, __LINE__, Context));
    return;
  }
  RCTData = (REMOTE_CFG_TLS_WORK_DATA*)Context;

  switch (RCTData->State) {
  case ST_CONNECTING:
    LOG ((EFI_D_INFO, "%a.%d State = ST_CONNECTING\n", __FUNCTION__, __LINE__));
    Status = RCTData->Tcp->Start(RCTData->Tcp, RCTData->TcpConn, NULL);
    if (Status == EFI_SUCCESS) {//connected
      DEBUG ((EFI_D_ERROR, "%a.%d Tcp->Start(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      RCTData->IsWorked = TRUE;//resets timeout
      RCTData->Status = EFI_SUCCESS;
      RCTData->State = ST_EXCHANGING;//goto exchange state
      RCTData->Attempts = RCTData->Settings->Attempts;
      goto _EXIT_SWITCH;
    } else if (Status == EFI_NOT_READY) {//connect in progress
      LOG ((EFI_D_INFO, "%a.%d Tcp->Start(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      RCTData->IsWorked = FALSE;
      RCTData->Status = EFI_NOT_READY;
      RCTData->State = ST_CONNECTING;//stay on connecting
      goto _EXIT_SWITCH;
    } else if (Status == EFI_DEVICE_ERROR) {//connect failed
      DEBUG ((EFI_D_ERROR, "%a.%d Tcp->Start(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      RCTData->IsWorked = FALSE;
      RCTData->Status = EFI_DEVICE_ERROR;
      RCTData->State = ST_RESTARTING;//restart
      RCTData->ServerIpTryNext = TRUE;//try next server
      goto _EXIT_SWITCH;
    } else {//socket error
      DEBUG ((EFI_D_ERROR, "%a.%d Tcp->Start(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      RCTData->IsWorked = FALSE;
      RCTData->Status = EFI_LOAD_ERROR;
      RCTData->State = ST_STOPPED;//halt
      goto _EXIT_SWITCH;
    }

  case ST_EXCHANGING:
    LOG ((EFI_D_INFO, "%a.%d State = ST_EXCHANGING\n", __FUNCTION__, __LINE__));
    RCTData->IsWorked = FALSE;//assume - no worked
    do {
      RetryReadOrWrite = FALSE;
      //read input
      //always reinit - input without "true" queue
#if 0
      ZeroMem(RCTData->InChunk, sizeof(REMOTE_CFG_TLS_DATA_CHUNK));
      InitializeListHead(&RCTData->InChunk->Link);
#else
      RCTData->InChunk->Exchanged = 0;
      RCTData->InChunk->Size = 0;
#endif

      Status = RCTData->Tcp->Read(RCTData->Tcp,
                                  RCTData->TcpConn,
                                  &RCTData->InChunk->Data[RCTData->InChunk->Size],
                                  (REMOTE_CFG_TLS_CHUNK_SIZE - RCTData->InChunk->Size),
                                  &Result);
      if (Status == EFI_SUCCESS) {
        LOG ((EFI_D_INFO, "%a.%d Tcp->Read(): Status = %r\n", __FUNCTION__, __LINE__, Status));
        LOG ((EFI_D_INFO, "%a.%d Tcp->Read(): Result = %d\n", __FUNCTION__, __LINE__, Result));
        if (Result > 0) {
          if (Result == (REMOTE_CFG_TLS_CHUNK_SIZE - RCTData->InChunk->Size)) {
            LOG ((EFI_D_INFO, "%a.%d RETRY READ\n", __FUNCTION__, __LINE__));
            RetryReadOrWrite = TRUE;
          }
          RCTData->InChunk->Size += Result;
          RCTData->IsWorked = TRUE;//resets timeout
        }
      } else if (Status == EFI_DEVICE_ERROR) {
        DEBUG ((EFI_D_ERROR, "%a.%d Tcp->Read(): Status = %r\n", __FUNCTION__, __LINE__, Status));
        RCTData->IsWorked = FALSE;
        RCTData->Status = EFI_DEVICE_ERROR;
        RCTData->State = ST_RESTARTING;//restart
        goto _EXIT_SWITCH;
      } else {
        DEBUG ((EFI_D_ERROR, "%a.%d Tcp->Read(): Status = %r\n", __FUNCTION__, __LINE__, Status));
        RCTData->IsWorked = FALSE;
        RCTData->Status = EFI_ABORTED;
        RCTData->State = ST_STOPPED;
        goto _EXIT_SWITCH;
      }

      //TODO: handle input data with RemoteCfgPkt protocol
      //input data placed in RCTData->InChunk->Data[0..(RCTData->InChunk->Size-1)]
      //input data size - RCTData->InChunk->Size
      if (RCTData->InChunk->Size > 0) {
        BOOLEAN bNewPktRx = FALSE;
        UINT8 *NewPkt = NULL;
        UINTN NewPktLen = 0;
        LOG ((EFI_D_ERROR, "%a.%d RCTData->InChunk->Size = %d\n", __FUNCTION__, __LINE__, RCTData->InChunk->Size));
#if 0        
        DumpBytes (RCTData->InChunk->Data, RCTData->InChunk->Size);
#endif
        Status = RCTData->RCPkt->ProcessingRxPackets (
                              RCTData->RCPkt,
                              RCTData->RCPktHandle,
                              RCTData->InChunk->Data,
                              RCTData->InChunk->Size,
                              &bNewPktRx, 
                              &NewPkt, 
                              &NewPktLen
                              );
        if (!EFI_ERROR(Status) && bNewPktRx && NewPkt != NULL) {
          LOG ((EFI_D_ERROR, "%a.%d *bNewPktRx=%X! *NewPktLen=%d\n", 
            __FUNCTION__, __LINE__, bNewPktRx, NewPktLen));
#if 0          
          DumpBytes (NewPkt, NewPktLen);
#endif
          ProcessingRxPackets (
                  RCTData->RCPkt, 
                  RCTData->RCPktHandle, 
                  NewPkt, 
                  NewPktLen
                  );
          FreePool (NewPkt);
        }
      }
      //Status = RCTData->RCPkt->ProcessingRxPackets(RCTData->RCPkt,...);
      //if (EFI_ERROR(Status)) {
      //  DEBUG ((EFI_D_ERROR, "%a.%d RCPkt->ProcessingRxPackets(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      //  RCTData->IsWorked = FALSE;
      //  RCTData->Status = EFI_PROTOCOL_ERROR;
      //  RCTData->State = ST_RESTARTING;//restart
      //  break;
      //}
    } while (RetryReadOrWrite);

    do {
      REMOTE_CFG_TLS_DATA_CHUNK* NewOutChunk;
      REMOTE_CFG_TLS_DATA_CHUNK* CurOutChunk;
      REMOTE_CFG_TLS_DATA_CHUNK* NextOutChunk;

      RetryReadOrWrite = FALSE;
      if (RCTData->TmpChunk != NULL) {//if exist chunk from previous iteration use it
        NewOutChunk = RCTData->TmpChunk;
      } else {//or allocate new
        NewOutChunk = AllocatePool(sizeof(REMOTE_CFG_TLS_DATA_CHUNK));
        if (NewOutChunk == NULL) {
          DEBUG ((EFI_D_ERROR, "%a.%d AllocatePool(): NewOutChunk = 0x%X\n", __FUNCTION__, __LINE__, NewOutChunk));
          RCTData->IsWorked = FALSE;
          RCTData->Status = EFI_OUT_OF_RESOURCES;
          RCTData->State = ST_STOPPED;//halt
          goto _EXIT_SWITCH;
        }
#if 0
        ZeroMem(NewOutChunk, sizeof(REMOTE_CFG_TLS_DATA_CHUNK));
#else
        NewOutChunk->Exchanged = 0;
        NewOutChunk->Size = 0;
#endif
        InsertTailList(&RCTData->OutQueue, &NewOutChunk->Link);//save newly allocated out chunk at the END of list
      }
      //LOG ((EFI_D_INFO, "%a.%d RCTData->TmpChunk = 0x%X\n", __FUNCTION__, __LINE__, RCTData->TmpChunk));
      //LOG ((EFI_D_INFO, "%a.%d NewOutChunk = 0x%X\n", __FUNCTION__, __LINE__, NewOutChunk));

      //TODO: get output data with RemoteCfgPkt protocol
      //ADD(!) output data size to NewOutChunk->Size
      //place output data here NewOutChunk->Data[NewOutChunk->Size..(REMOTE_CFG_TLS_CHUNK_SIZE-1)]
      //max output data length - (REMOTE_CFG_TLS_CHUNK_SIZE - NewOutChunk->Size)
#if 1
      {
        UINTN TxLen;
        TxLen = (REMOTE_CFG_TLS_CHUNK_SIZE - NewOutChunk->Size);
        Status = RCTData->RCPkt->Tx (
          RCTData->RCPkt,
          RCTData->RCPktHandle,
          &NewOutChunk->Data[NewOutChunk->Size],
          &TxLen
          );
        if (EFI_ERROR(Status)) {
          LOG ((EFI_D_ERROR, "%a.%d Status=%r\n", __FUNCTION__, __LINE__, Status));
        } else {
          NewOutChunk->Size += TxLen;
        }
      }
#endif
      //Status = RCTData->RCPkt->Tx(RCTData->RCPkt,...);
      //if (EFI_ERROR(Status)) {
      //  DEBUG ((EFI_D_ERROR, "%a.%d RCPkt->Tx(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      //  RCTData->IsWorked = FALSE;
      //  RCTData->Status = EFI_PROTOCOL_ERROR;
      //  RCTData->State = ST_RESTARTING;//restart
      //  break;
      //}

      if (NewOutChunk->Size == REMOTE_CFG_TLS_CHUNK_SIZE) {//chunk is full
        RCTData->TmpChunk = NULL;//next iteration allocate new
      } else {//or use this chunk on the next iteration
        RCTData->TmpChunk = NewOutChunk;//TmpChunk now points to last chunk
      }
      //LOG ((EFI_D_INFO, "%a.%d RCTData->TmpChunk = 0x%X\n", __FUNCTION__, __LINE__, RCTData->TmpChunk));
      //LOG ((EFI_D_INFO, "%a.%d NewOutChunk = 0x%X\n", __FUNCTION__, __LINE__, NewOutChunk));

      //get chunk for out from BEGIN of list
      CurOutChunk = (REMOTE_CFG_TLS_DATA_CHUNK *)GetFirstNode(&RCTData->OutQueue);
      if (IsNull(&RCTData->OutQueue, (LIST_ENTRY *)CurOutChunk)) {
        //must never get here - we always have chunk at this point(it size maybe zero)
        DEBUG ((EFI_D_ERROR, "%a.%d GetFirstNode(): CurOutChunk = 0x%X\n", __FUNCTION__, __LINE__, CurOutChunk));
        RCTData->IsWorked = FALSE;
        RCTData->Status = EFI_ABORTED;
        RCTData->State = ST_STOPPED;//halt
        goto _EXIT_SWITCH;
      }
      //LOG ((EFI_D_INFO, "%a.%d CurOutChunk = 0x%X\n", __FUNCTION__, __LINE__, CurOutChunk));

      if (CurOutChunk->Size > 0) {//BEGIN chunk has data
        if (CurOutChunk->Exchanged < CurOutChunk->Size) {//not all data sended
          LOG ((EFI_D_INFO, "%a.%d CurOutChunk->Exchanged = %d\n", __FUNCTION__, __LINE__, CurOutChunk->Exchanged));
          LOG ((EFI_D_INFO, "%a.%d CurOutChunk->Size = %d\n", __FUNCTION__, __LINE__, CurOutChunk->Size));
          Status = RCTData->Tcp->Write(RCTData->Tcp,
                                       RCTData->TcpConn,
                                       &CurOutChunk->Data[CurOutChunk->Exchanged],
                                       (CurOutChunk->Size - CurOutChunk->Exchanged),
                                       &Result);
          if (Status == EFI_SUCCESS) {
            LOG ((EFI_D_INFO, "%a.%d Tcp->Write(): Status = %r\n", __FUNCTION__, __LINE__, Status));
            LOG ((EFI_D_INFO, "%a.%d Tcp->Write(): Result = %d\n", __FUNCTION__, __LINE__, Result));
            if (Result > 0) {
              if (Result == (CurOutChunk->Size - CurOutChunk->Exchanged)) {
                LOG ((EFI_D_INFO, "%a.%d RETRY WRITE\n", __FUNCTION__, __LINE__));
                RetryReadOrWrite = TRUE;
              }
              CurOutChunk->Exchanged += Result;
              RCTData->IsWorked = TRUE;//resets timeout
            }
          } else if (Status == EFI_DEVICE_ERROR) {
            DEBUG ((EFI_D_ERROR, "%a.%d Tcp->Write(): Status = %r\n", __FUNCTION__, __LINE__, Status));
            RCTData->IsWorked = FALSE;
            RCTData->Status = EFI_DEVICE_ERROR;
            RCTData->State = ST_RESTARTING;//restart
            goto _EXIT_SWITCH;
          } else {
            DEBUG ((EFI_D_ERROR, "%a.%d Tcp->Write(): Status = %r\n", __FUNCTION__, __LINE__, Status));
            RCTData->IsWorked = FALSE;
            RCTData->Status = EFI_ABORTED;
            RCTData->State = ST_STOPPED;
            goto _EXIT_SWITCH;
          }
        }

        if (CurOutChunk->Exchanged < CurOutChunk->Size) {
          //not all BEGIN chunk sended
          LOG ((EFI_D_INFO, "%a.%d CurOutChunk->Exchanged = %d\n", __FUNCTION__, __LINE__, CurOutChunk->Exchanged));
          LOG ((EFI_D_INFO, "%a.%d CurOutChunk->Size = %d\n", __FUNCTION__, __LINE__, CurOutChunk->Size));
        } else if (CurOutChunk->Exchanged == CurOutChunk->Size) {
          //BEGIN chunk fully sended
          NextOutChunk = (REMOTE_CFG_TLS_DATA_CHUNK *)GetNextNode(&RCTData->OutQueue, (LIST_ENTRY *)CurOutChunk);
          if (!IsNull(&RCTData->OutQueue, (LIST_ENTRY *)NextOutChunk)) {
            //BEGIN chunk fully sended and it's NOT only one chunk - delete it
            LOG ((EFI_D_INFO, "%a.%d CurOutChunk->Exchanged = %d\n", __FUNCTION__, __LINE__, CurOutChunk->Exchanged));
            LOG ((EFI_D_INFO, "%a.%d CurOutChunk->Size = %d\n", __FUNCTION__, __LINE__, CurOutChunk->Size));
            RemoveEntryList((LIST_ENTRY *)CurOutChunk);
            FreePool(CurOutChunk);
          } else {
            //BEGIN chunk fully sended and it's only one chunk - zero indexes and use it on next call
            LOG ((EFI_D_INFO, "%a.%d CurOutChunk->Exchanged = %d\n", __FUNCTION__, __LINE__, CurOutChunk->Exchanged));
            LOG ((EFI_D_INFO, "%a.%d CurOutChunk->Size = %d\n", __FUNCTION__, __LINE__, CurOutChunk->Size));
            CurOutChunk->Exchanged = 0;
            CurOutChunk->Size = 0;
            RCTData->TmpChunk = CurOutChunk;
          }
        } else if (CurOutChunk->Exchanged > CurOutChunk->Size) {
          //must never get here
          DEBUG ((EFI_D_ERROR, "%a.%d CurOutChunk->Exchanged = %d\n", __FUNCTION__, __LINE__, CurOutChunk->Exchanged));
          DEBUG ((EFI_D_ERROR, "%a.%d CurOutChunk->Size = %d\n", __FUNCTION__, __LINE__, CurOutChunk->Size));
          RCTData->IsWorked = FALSE;
          RCTData->Status = EFI_ABORTED;
          RCTData->State = ST_STOPPED;//halt
          goto _EXIT_SWITCH;
        }
      } else {//BEGIN chunk has NOT data
        NextOutChunk = (REMOTE_CFG_TLS_DATA_CHUNK *)GetNextNode(&RCTData->OutQueue, (LIST_ENTRY *)CurOutChunk);
        if (!IsNull(&RCTData->OutQueue, (LIST_ENTRY *)NextOutChunk)) {
          //if BEGIN chunk has NOT data and it's NOT only one chunk - delete it
          LOG ((EFI_D_INFO, "%a.%d CurOutChunk->Exchanged = %d\n", __FUNCTION__, __LINE__, CurOutChunk->Exchanged));
          LOG ((EFI_D_INFO, "%a.%d CurOutChunk->Size = %d\n", __FUNCTION__, __LINE__, CurOutChunk->Size));
          RemoveEntryList((LIST_ENTRY *)CurOutChunk);
          FreePool(CurOutChunk);
        } else {
          //if BEGIN chunk has NOT data and it's only one chunk - use it on next call(indexes already zero)
          LOG ((EFI_D_INFO, "%a.%d CurOutChunk->Exchanged = %d\n", __FUNCTION__, __LINE__, CurOutChunk->Exchanged));
          LOG ((EFI_D_INFO, "%a.%d CurOutChunk->Size = %d\n", __FUNCTION__, __LINE__, CurOutChunk->Size));
          RCTData->TmpChunk = CurOutChunk;
        }
      }
      //TODO: if it was chunk deletion get next chunk from begin and send it
    } while (RetryReadOrWrite);
    
    RCTData->Status = EFI_SUCCESS;
    RCTData->State = ST_EXCHANGING;
    goto _EXIT_SWITCH;

  case ST_STOPPED:
    DEBUG ((EFI_D_ERROR, "%a.%d State = ST_STOPPED\n", __FUNCTION__, __LINE__));
    RCTData->IsWorked = FALSE;
    RCTData->State = ST_STOPPED;
    //don't change RCTData->Status - to save last error code
    DEBUG ((EFI_D_ERROR, "%a.%d RCTData->Status == %r\n", __FUNCTION__, __LINE__, RCTData->Status));
    gBS->SetTimer(RCTData->CallbackRun, TimerCancel, 0);//Stop callback
    gBS->CheckEvent(RCTData->CallbackRun);//reset event if it happens 
    gBS->CloseEvent(RCTData->CallbackRunIdle);
    RCTData->CallbackRunIdle = NULL;
    gBS->SetTimer(RCTData->StopAttempt, TimerCancel, 0);
    gBS->CheckEvent(RCTData->StopAttempt);//reset event if it happens 
    goto _EXIT_SWITCH;

  case ST_RESTARTING:
    DEBUG ((EFI_D_ERROR, "%a.%d State = ST_RESTARTING\n", __FUNCTION__, __LINE__));

    //free out data
    {
      LIST_ENTRY *OutChunk, *NextOutChunk;
      RCTData->TmpChunk = NULL;
      OutChunk = GetFirstNode(&RCTData->OutQueue);
      while (!IsNull(&RCTData->OutQueue, OutChunk)) {
        NextOutChunk = RemoveEntryList(OutChunk);
        if (IsNull(&RCTData->OutQueue, NextOutChunk)) {
          //OutChunk is last chunk - zero indexes and save it for reusing on next iteration
          RCTData->TmpChunk = (REMOTE_CFG_TLS_DATA_CHUNK *)OutChunk;
#if 0
          ZeroMem(RCTData->TmpChunk, sizeof(REMOTE_CFG_TLS_DATA_CHUNK));
#else
          RCTData->TmpChunk->Exchanged = 0;
          RCTData->TmpChunk->Size = 0;
#endif
          InsertTailList(&RCTData->OutQueue, OutChunk);//return chunk to list
          //now list have one chunk
          break;
        } else {
          //OutChunk is NOT last chunk - free it
          FreePool(OutChunk);
          OutChunk = NextOutChunk;
        }
      }
      //out queue has no chunks(TmpChunk == NULL) or has one chunk(TmpChunk != NULL)
    }

    //TODO: RemoteCfgPkt reset/reinit here
    RCTData->RCPkt->ResetState(RCTData->RCPkt, RCTData->RCPktHandle);
    
    RCTData->State = ST_RESTARTING2;
    //(!)no break here
  case ST_RESTARTING2:
    DEBUG ((EFI_D_ERROR, "%a.%d State = ST_RESTARTING2\n", __FUNCTION__, __LINE__));
    //destroy current TCP Helper instance
    if (RCTData->TcpConn != NULL) {
      Status = RCTData->Tcp->Destroy(RCTData->Tcp, 
                                     RCTData->TcpConn, 
                                     FALSE);
      DEBUG ((EFI_D_ERROR, "%a.%d Tcp->Destroy(): Status == %r\n", __FUNCTION__, __LINE__, Status));
      RCTData->TcpConn = NULL;
    }

    if (RCTData->Attempts != REMOTE_CFG_TLS_ATTEMPTS_INFINITE) {
      RCTData->Attempts--;
      if (RCTData->Attempts == 0) {//no more attempts
        DEBUG ((EFI_D_ERROR, "%a.%d RCTData->Attempts = %d\n", __FUNCTION__, __LINE__, RCTData->Attempts));
        RCTData->IsWorked = FALSE;
        RCTData->Status = EFI_NO_RESPONSE;
        RCTData->State = ST_STOPPED;//halt
        goto _EXIT_SWITCH;
      }
    } else {
      //infinite retries
      DEBUG ((EFI_D_ERROR, "%a.%d RCTData->Settings->Attempts = REMOTE_CFG_TLS_ATTEMPTS_INFINITE\n", __FUNCTION__, __LINE__));
    }

    RCTData->State = ST_RESTARTING3;
    //(!)no break here
  case ST_RESTARTING3:
    DEBUG ((EFI_D_ERROR, "%a.%d State = ST_RESTARTING3\n", __FUNCTION__, __LINE__));
#if 0
    ZeroMem(RCTData->InChunk, sizeof(REMOTE_CFG_TLS_DATA_CHUNK));
    InitializeListHead(&RCTData->InChunk->Link);
#else
    RCTData->InChunk->Exchanged = 0;
    RCTData->InChunk->Size = 0;
#endif
    if (RCTData->TmpChunk == NULL) {
      //if no chunk saved - init list head
      InitializeListHead(&RCTData->OutQueue);
    }

    DEBUG ((EFI_D_ERROR, "%a.%d RCTData->ServerIpTryNext = %d, ServerIp = 0x%X, ServerIpNum = %d\n", __FUNCTION__, __LINE__, RCTData->ServerIpTryNext, RCTData->ServerIp, RCTData->ServerIpNum));
    if ((RCTData->ServerIpNum == 0) ||
        ((RCTData->ServerIpTryNext) && ((RCTData->ServerIpCur+1) >= RCTData->ServerIpNum))) {

      if (RCTData->ServerIp != NULL) {
        FreePool (RCTData->ServerIp);
        RCTData->ServerIp = NULL;
        RCTData->ServerIpNum = 0;
      }

      gBS->SetTimer(RCTData->CallbackRun, TimerCancel, 0);
      gBS->CheckEvent(RCTData->CallbackRun);//reset event if it happens 
      gBS->CloseEvent(RCTData->CallbackRunIdle);
      RCTData->CallbackRunIdle = NULL;
      Status = RCTData->Dns->Resolve8(RCTData->Dns,
                              RCTData->Settings->ServerName,
                              &RCTData->ServerIp,
                              &RCTData->ServerIpNum);
      if (EFI_ERROR(Status) || RCTData->ServerIp == NULL || RCTData->ServerIpNum == 0) {
        DEBUG ((EFI_D_ERROR, "%a.%d Resolve(): Status = %r\n", __FUNCTION__, __LINE__, Status));
        DEBUG ((EFI_D_ERROR, "%a.%d Resolve(): ServerIp = 0x%X, ServerIpNum = %d\n", __FUNCTION__, __LINE__, RCTData->ServerIp, RCTData->ServerIpNum));
        Status = gBS->SetTimer(RCTData->CallbackRun,
                               TimerRelative,
                               REMOTE_CFG_TLS_CALLBACK_SLOWING * REMOTE_CFG_TLS_CALLBACK_RATE);
        if (EFI_ERROR(Status)) {
          DEBUG ((EFI_D_ERROR, "%a.%d SetTimer(): Status = %r\n", __FUNCTION__, __LINE__, Status));
          RCTData->Status = EFI_ABORTED;
          RCTData->State = ST_STOPPED;
          goto _EXIT_SWITCH;
        }
        RCTData->IsWorked = FALSE;
        RCTData->Status = EFI_NO_MAPPING;
        RCTData->State = ST_RESTARTING2;//restart
        goto _EXIT_SWITCH;
      }
      RCTData->ResetRate = TRUE;
      RCTData->ServerIpTryNext = FALSE;
      RCTData->ServerIpCur = 0;
      CopyMem(&RCTData->TcpSettings.ServerIp,
              &RCTData->ServerIp[RCTData->ServerIpCur],
              sizeof(EFI_IPv4_ADDRESS));
    }

    //try next server address
    if (RCTData->ServerIpTryNext) {
      RCTData->ServerIpTryNext = FALSE;
      RCTData->ServerIpCur++;
      ASSERT (RCTData->ServerIpCur < RCTData->ServerIpNum);
      CopyMem(&RCTData->TcpSettings.ServerIp,
              &RCTData->ServerIp[RCTData->ServerIpCur],
              sizeof(EFI_IPv4_ADDRESS));
    }

    //create new TcpHelper instance
    Status = RCTData->Tcp->Create(RCTData->Tcp, 
                                  &RCTData->TcpConn, 
                                  &RCTData->TcpSettings);
    if (EFI_ERROR(Status) || RCTData->TcpConn == NULL) {
      DEBUG ((EFI_D_ERROR, "%a.%d Tcp->Create(): Status == %r\n", __FUNCTION__, __LINE__, Status));
      RCTData->IsWorked = FALSE;
      RCTData->Status = EFI_LOAD_ERROR;
      RCTData->State = ST_STOPPED;//halt
      goto _EXIT_SWITCH;
    }

    RCTData->IsWorked = TRUE;//reinit timeout timer by setting to TRUE
    RCTData->Status = EFI_ALREADY_STARTED;
    RCTData->State = ST_CONNECTING;//goto to connecting
    goto _EXIT_SWITCH;

  default:
    DEBUG ((EFI_D_ERROR, "%a.%d State = %d\n", __FUNCTION__, __LINE__, RCTData->State));
    RCTData->IsWorked = FALSE;
    RCTData->Status = EFI_ABORTED;
    RCTData->State = ST_STOPPED;
    goto _EXIT_SWITCH;
  }
_EXIT_SWITCH:

  if (RCTData->State == ST_EXCHANGING) {
    CurTimeout = RCTData->Settings->TimeoutExchange;
  } else if (RCTData->State == ST_CONNECTING) {
    CurTimeout = RCTData->Settings->TimeoutConnect;
  } else {
    //other states didn't have timer
    CurTimeout = REMOTE_CFG_TLS_TIMEOUT_OFF;
  }
  if (CurTimeout != REMOTE_CFG_TLS_TIMEOUT_OFF) {
    //don't reset or check timer if current timeout is off
    if (RCTData->IsWorked) {
      //reset timeout
      LOG ((EFI_D_INFO, "%a.%d CurTimeout = %d\n", __FUNCTION__, __LINE__, CurTimeout));
      Status = gBS->SetTimer(RCTData->StopAttempt, 
                             TimerRelative, 
                             CurTimeout * REMOTE_CFG_TLS_TIMEOUT_1s);
      gBS->CheckEvent(RCTData->StopAttempt);//reset event if it happens 
      if (EFI_ERROR(Status)) {
        DEBUG ((EFI_D_ERROR, "%a.%d SetTimer(): Status = %r\n", __FUNCTION__, __LINE__, Status));
        RCTData->Status = EFI_ABORTED;
        RCTData->State = ST_STOPPED;
      }
    } else {
      //check for timeout exceeded
      Status = gBS->CheckEvent(RCTData->StopAttempt);//check and reset event if it happens 
      if (Status == EFI_SUCCESS) {
        //restart work
        DEBUG ((EFI_D_ERROR, "%a.%d CheckEvent(StopAttempt): Status = %r\n", __FUNCTION__, __LINE__, Status));
        if (RCTData->State == ST_CONNECTING) {
          RCTData->ServerIpTryNext = TRUE;//try next server
        }
        RCTData->Status = EFI_TIMEOUT;
        RCTData->State = ST_RESTARTING;
      } else if (Status == EFI_NOT_READY) {
        //continue work
        LOG ((EFI_D_INFO, "%a.%d CheckEvent(StopAttempt): Status = %r\n", __FUNCTION__, __LINE__, Status));
      } else {
        DEBUG ((EFI_D_ERROR, "%a.%d CheckEvent(StopAttempt): Status = %r\n", __FUNCTION__, __LINE__, Status));
        RCTData->Status = EFI_ABORTED;
        RCTData->State = ST_STOPPED;
      }
    }
  } else {
    //if timeout is off - quietly cancel it(or do nothing if timer not running)
    LOG ((EFI_D_INFO, "%a.%d CurTimeout = %d\n", __FUNCTION__, __LINE__, CurTimeout));
    gBS->SetTimer(RCTData->StopAttempt, TimerCancel, 0);
    gBS->CheckEvent(RCTData->StopAttempt);//reset event if it happens 
  }

  if (RCTData->ResetRate) {
    DEBUG ((EFI_D_ERROR, "%a.%d RCTData->ResetRate = %d\n", __FUNCTION__, __LINE__, RCTData->ResetRate));
    RCTData->ResetRate = FALSE;
    Status = gBS->SetTimer(RCTData->CallbackRun,
                           TimerPeriodic,
                           REMOTE_CFG_TLS_CALLBACK_RATE);
    if (EFI_ERROR(Status)) {
      DEBUG ((EFI_D_ERROR, "%a.%d SetTimer(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      RCTData->Status = EFI_ABORTED;
      RCTData->State = ST_STOPPED;
    }
    Status = gBS->CreateEvent(EVT_NOTIFY_IDLE,
                              REMOTE_CFG_TLS_CALLBACK_TPL,
                              RemoteCfgTlsCallback, 
                              RCTData,
                              &RCTData->CallbackRunIdle);
    if (EFI_ERROR(Status) || RCTData->CallbackRunIdle == NULL) {
      DEBUG ((EFI_D_ERROR, "%a.%d CreateEvent(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      DEBUG ((EFI_D_ERROR, "%a.%d CreateEvent(): RCTData->CallbackRunIdle = 0x%X\n", __FUNCTION__, __LINE__, RCTData->CallbackRunIdle));
      gBS->SetTimer(RCTData->CallbackRun, TimerCancel, 0);
      gBS->CheckEvent(RCTData->CallbackRun);//reset event if it happens 
      RCTData->Status = EFI_ABORTED;
      RCTData->State = ST_STOPPED;
    }
  }

  LOG ((EFI_D_INFO, "%a.%d Exit\n", __FUNCTION__, __LINE__));
  return;
}

/**
  Load settings and start Remote Config Protocol connection via TCP/TLS
  Before starting make nonevident Stop() if currently running service is in error state
  
  @param  param                   desc
  
  @retval EFI_INVALID_PARAMETER   Settings not found/incorrect settings
  @retval EFI_NOT_FOUND           Can't locate RemoteCfgPkt/TCP/DNS protocols/OpenSSL certificates/keys/etc
  @retval EFI_OUT_OF_RESOURCES    Cannot allocate memory for internal structures
  @retval EFI_UNSUPPORTED         Service disabled
  @retval EFI_LOAD_ERROR          RemoteCfgPkt/TCP protocol initiliazing error
  @retval EFI_NO_MAPPING          Can't DNS resolve server name/Incorrect server IP address
  @retval EFI_ABORTED             Error occured
  @retval EFI_ALREADY_STARTED     Service already started
  @retval EFI_SUCCESS             Succesfully started
**/
EFI_STATUS
EFIAPI
RemoteCfgTlsStart(
  IN REMOTE_CFG_TLS_PROTOCOL *This
  )
{
  EFI_STATUS Status;
  REMOTE_CFG_TLS_WORK_DATA* RCTData = NULL;
  REMOTE_CFG_TLS_SETTINGS* RCTSettings = NULL;
  BOOLEAN IsSettingsAlreadyReseted = FALSE;
  EFI_TPL OldTpl;

  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  OldTpl = gBS->RaiseTPL(REMOTE_CFG_TLS_CALLBACK_TPL);

  if (gRCTData != NULL) {//check for running
    Status = gRCTData->Status;
    DEBUG ((EFI_D_INFO, "%a.%d gRCTData = 0x%X\n", __FUNCTION__, __LINE__, gRCTData));
    DEBUG ((EFI_D_INFO, "%a.%d gRCTData->Status = %r\n", __FUNCTION__, __LINE__, Status));
    if (REMOTE_CFG_TLS_RUNNING_STATUS(Status)) {//already succefully runned
      gBS->RestoreTPL(OldTpl);
      return EFI_ALREADY_STARTED;//the one error return that miss _error_exit label
    } else {//stop failed service and continue starting new
      RemoteCfgTlsStop(This);
    }
  }
  gRCTData = NULL;
  gRCTStatus = EFI_NOT_STARTED;

  //load settings
  do {
    Status = RemoteCfgTlsGetSettings(This, &RCTSettings);
    if (Status == EFI_NOT_FOUND && !IsSettingsAlreadyReseted) {
      DEBUG ((EFI_D_ERROR, "%a.%d RemoteCfgTlsGetSettings(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      //try to reset settings from INI
      Status = RemoteCfgTlsResetSettingsFromINI(This);
      if ((Status == EFI_NOT_FOUND || Status == EFI_VOLUME_CORRUPTED) && !IsSettingsAlreadyReseted) {
        DEBUG ((EFI_D_ERROR, "%a.%d RemoteCfgTlsResetSettingsFromINI(): Status = %r\n", __FUNCTION__, __LINE__, Status));
        //ini not found or not valid - try to reset to hard coded settings
        Status = RemoteCfgTlsResetSettings(This);
        if (EFI_ERROR(Status)) {
          DEBUG ((EFI_D_ERROR, "%a.%d RemoteCfgTlsResetSettings(): Status = %r\n", __FUNCTION__, __LINE__, Status));
          gRCTStatus = EFI_INVALID_PARAMETER;
          goto _error_exit;
        } else {
          //all ok - settings reseted to hard coded values
          IsSettingsAlreadyReseted = TRUE;//try to reset only one time
          //try to load
          continue;
        }
      } else if (EFI_ERROR(Status)) {
        //can't write settings or etc
        DEBUG ((EFI_D_ERROR, "%a.%d RemoteCfgTlsResetSettingsFromINI(): Status = %r\n", __FUNCTION__, __LINE__, Status));
        gRCTStatus = EFI_INVALID_PARAMETER;
        goto _error_exit;
      } else {
        //all ok - settings reseted from ini
        IsSettingsAlreadyReseted = TRUE;//try to reset only one time
        //try to load
        continue;
      }
    } else if (EFI_ERROR(Status) || RCTSettings == NULL) {
      //settings invalid or etc
      DEBUG ((EFI_D_ERROR, "%a.%d RemoteCfgTlsGetSettings(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      DEBUG ((EFI_D_ERROR, "%a.%d RemoteCfgTlsGetSettings(): RCTSettings = 0x%X\n", __FUNCTION__, __LINE__, RCTSettings));
      gRCTStatus = EFI_INVALID_PARAMETER;
      goto _error_exit;
    } else {
      //all ok
      break;
    }
  } while (TRUE);
  if ((RCTSettings->Flags & REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED) == 0) {
    DEBUG ((EFI_D_ERROR, "%a.%d RCTSettings->Flags = 0x%X\n", __FUNCTION__, __LINE__, RCTSettings->Flags));
    gRCTStatus = EFI_UNSUPPORTED;
    goto _error_exit;
  }

  //init service inner data by template
  RCTData = AllocateCopyPool(sizeof(REMOTE_CFG_TLS_WORK_DATA), 
                             &gRCTDataInitTemplate);
  if (RCTData == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d AllocateCopyPool(): gRCTData = 0x%X\n", __FUNCTION__, __LINE__, RCTData));
    gRCTStatus = EFI_OUT_OF_RESOURCES;
    goto _error_exit;
  }
  RCTData->Settings = RCTSettings;
  RCTData->Attempts = RCTData->Settings->Attempts;

  //allocate buffer for input data
  RCTData->InChunk = AllocatePool(sizeof(REMOTE_CFG_TLS_DATA_CHUNK));
  if (RCTData->InChunk == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d AllocatePool(): InChunk = 0x%X\n", __FUNCTION__, __LINE__, RCTData->InChunk));
    gRCTStatus = EFI_OUT_OF_RESOURCES;
    goto _error_exit;
  }
#if 0
  ZeroMem(RCTData->InChunk, sizeof(REMOTE_CFG_TLS_DATA_CHUNK));
  InitializeListHead(&RCTData->InChunk->Link);
#else
  RCTData->InChunk->Exchanged = 0;
  RCTData->InChunk->Size = 0;
#endif
  //allocate buffer for output data
  InitializeListHead(&RCTData->OutQueue);

  //callback timer event
  Status = gBS->CreateEvent(EVT_TIMER | EVT_NOTIFY_SIGNAL,
                            REMOTE_CFG_TLS_CALLBACK_TPL,
                            RemoteCfgTlsCallback, 
                            RCTData,
                            &RCTData->CallbackRun);
  if (EFI_ERROR(Status) || RCTData->CallbackRun == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d CreateEvent(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    DEBUG ((EFI_D_ERROR, "%a.%d CreateEvent(): RCTData->CallbackRun = 0x%X\n", __FUNCTION__, __LINE__, RCTData->CallbackRun));
    gRCTStatus = EFI_OUT_OF_RESOURCES;
    goto _error_exit;
  }
  //connecting/exchanging attempt timeout timer
  Status = gBS->CreateEvent(EVT_TIMER,
                            0,
                            NULL,
                            NULL,
                            &RCTData->StopAttempt);
  if (EFI_ERROR(Status) || RCTData->StopAttempt == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d CreateEvent(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    DEBUG ((EFI_D_ERROR, "%a.%d CreateEvent(): RCTData->StopAttempt = 0x%X\n", __FUNCTION__, __LINE__, RCTData->StopAttempt));
    gRCTStatus = EFI_OUT_OF_RESOURCES;
    goto _error_exit;
  }

  //RemoteCfgPkt protocol
  Status = gBS->LocateProtocol(&gRemoteCfgPktProtocolGuid,
                               NULL,
                               (VOID **)&RCTData->RCPkt);
  if (EFI_ERROR(Status) || RCTData->RCPkt == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d LocateProtocol(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    DEBUG ((EFI_D_ERROR, "%a.%d LocateProtocol(): RCPkt = 0x%X\n", __FUNCTION__, __LINE__, RCTData->RCPkt));
    gRCTStatus = EFI_NOT_FOUND;
    goto _error_exit;
  }

  //TODO: init/reset RemoteCfgPkt here
  Status = RCTData->RCPkt->ProtocolOpen(RCTData->RCPkt, &RCTData->RCPktHandle);
  //On error - same handling as TCP->Create() - return EFI_LOAD_ERROR
  if (EFI_ERROR(Status) || RCTData->RCPktHandle == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d RemoteCfgPkt->ResetState(): Status == %r\n", __FUNCTION__, __LINE__, Status));
    DEBUG ((EFI_D_ERROR, "%a.%d RemoteCfgPkt->ResetState(): RCPktHandle == 0x%X\n", __FUNCTION__, __LINE__, RCTData->RCPktHandle));
    gRCTStatus = EFI_LOAD_ERROR;
    goto _error_exit;
  }
  RCTData->RCPkt->ResetState(RCTData->RCPkt, RCTData->RCPktHandle);

  //TcpHelper protocol
  Status = gBS->LocateProtocol(&gTcpHelperProtocolGuid,
                               NULL,
                               (VOID **)&RCTData->Tcp);
  if (EFI_ERROR(Status) || RCTData->Tcp == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d LocateProtocol(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    DEBUG ((EFI_D_ERROR, "%a.%d LocateProtocol(): Tcp = 0x%X\n", __FUNCTION__, __LINE__, RCTData->Tcp));
    gRCTStatus = EFI_NOT_FOUND;
    goto _error_exit;
  }

  //TcpHelper settings
  RCTData->TcpSettings.Type = TCP_CLIENT;
  if (RCTData->Settings->TlsVersion == REMOTE_CFG_USE_TLS_1_0) {
    RCTData->TcpSettings.Version = TCP_USE_TLS_1_0;
  } else if (RCTData->Settings->TlsVersion == REMOTE_CFG_USE_TLS_1_1) {
    RCTData->TcpSettings.Version = TCP_USE_TLS_1_1;
  } else if (RCTData->Settings->TlsVersion == REMOTE_CFG_USE_TLS_1_2) {
    RCTData->TcpSettings.Version = TCP_USE_TLS_1_2;
#ifdef REMOTE_CFG_USE_NO_CRYPTO
  } else if (RCTData->Settings->TlsVersion == REMOTE_CFG_USE_NO_CRYPTO) {
    RCTData->TcpSettings.Version = TCP_USE_NO_CRYPTO;
#endif
  } else {
    DEBUG ((EFI_D_ERROR, "%a.%d TlsVersion = %d\n", __FUNCTION__, __LINE__, RCTData->Settings->TlsVersion));
    gRCTStatus = EFI_INVALID_PARAMETER;
    goto _error_exit;
  }
  RCTData->TcpSettings.Port = RCTData->Settings->Port;
  Status = gBS->LocateProtocol(&gDnsResolverProtocolGuid,
                                NULL,
                                (VOID **)&RCTData->Dns);
  if (EFI_ERROR(Status) || RCTData->Dns == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d LocateProtocol(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    DEBUG ((EFI_D_ERROR, "%a.%d LocateProtocol(): Dns = 0x%X\n", __FUNCTION__, __LINE__, RCTData->Dns));
    gRCTStatus = EFI_NOT_FOUND;
    goto _error_exit;
  }

  //load certificate
  Status = LoadCertStorageDataInBuffer(TLS_CERT_STORAGE,
                                       &gClientCertStorageGuid,
                                       &RCTData->TcpSettings.CertAsn1Buf, 
                                       &RCTData->TcpSettings.CertAsn1BufLen);
  if (EFI_ERROR(Status) || RCTData->TcpSettings.CertAsn1BufLen == 0) {
    DEBUG ((EFI_D_ERROR, "%a.%d LoadCertStorageDataInBuffer(%s, %g): Status == %r, CertAsn1BufLen = %d\n", 
      __FUNCTION__, __LINE__, TLS_CERT_STORAGE, &gClientCertStorageGuid, Status, RCTData->TcpSettings.CertAsn1BufLen));
    gRCTStatus = EFI_NOT_FOUND;
    goto _error_exit;
  }
  //load private key
  Status = LoadCertStorageDataInBuffer(TLS_PKEY_STORAGE,
                                       &gClientPKeyStorageGuid,
                                       &RCTData->TcpSettings.PrivKeyAsn1Buf, 
                                       &RCTData->TcpSettings.PrivKeyAsn1BufLen);
  if (EFI_ERROR(Status) || RCTData->TcpSettings.PrivKeyAsn1BufLen == 0) {
    DEBUG ((EFI_D_ERROR, "%a.%d LoadCertStorageDataInBuffer(%s, %g): Status == %r, PrivKeyAsn1BufLen = %d\n", 
      __FUNCTION__, __LINE__, TLS_PKEY_STORAGE, &gClientPKeyStorageGuid, Status, RCTData->TcpSettings.PrivKeyAsn1BufLen));
    gRCTStatus = EFI_NOT_FOUND;
    goto _error_exit;
  }
  //load CA certificates list
  Status = LoadCertStorageDataInBuffer(TLS_CA_STORAGE,
                                       &gChainStorageGuid,
                                       &RCTData->TcpSettings.CaCertsP7bBuf, 
                                       &RCTData->TcpSettings.CaCertsP7bBufLen);
  if (EFI_ERROR(Status) || RCTData->TcpSettings.CaCertsP7bBufLen == 0) {
    DEBUG ((EFI_D_ERROR, "%a.%d LoadCertStorageDataInBuffer(%s, %g): Status == %r, CaCertsP7bBufLen = %d\n", 
      __FUNCTION__, __LINE__, TLS_CA_STORAGE, &gChainStorageGuid, Status, RCTData->TcpSettings.CaCertsP7bBufLen));
    gRCTStatus = EFI_NOT_FOUND;
    goto _error_exit;
  }

  //init timeout timer
  if (RCTData->Settings->TimeoutConnect != REMOTE_CFG_TLS_TIMEOUT_OFF) {
    DEBUG ((EFI_D_INFO, "%a.%d RCTData->Settings->TimeoutConnect = %d\n", __FUNCTION__, __LINE__, RCTData->Settings->TimeoutConnect));
    Status = gBS->SetTimer(RCTData->StopAttempt, 
                           TimerRelative, 
                           RCTData->Settings->TimeoutConnect*REMOTE_CFG_TLS_TIMEOUT_1s);
    if (EFI_ERROR(Status)) {
      DEBUG ((EFI_D_ERROR, "%a.%d SetTimer(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      gRCTStatus = EFI_ABORTED;
      goto _error_exit;
    }
  } else {
    DEBUG ((EFI_D_INFO, "%a.%d RCTData->Settings->TimeoutConnect = %d\n", __FUNCTION__, __LINE__, RCTData->Settings->TimeoutConnect));
  }
  //init callback timer
  Status = gBS->SetTimer(RCTData->CallbackRun, 
                         TimerPeriodic,
                         REMOTE_CFG_TLS_CALLBACK_RATE);
  if (EFI_ERROR(Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d SetTimer(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    gRCTStatus = EFI_ABORTED;
    goto _error_exit;
  }
  Status = gBS->CreateEvent(EVT_NOTIFY_IDLE,
                            REMOTE_CFG_TLS_CALLBACK_TPL,
                            RemoteCfgTlsCallback, 
                            RCTData,
                            &RCTData->CallbackRunIdle);
  if (EFI_ERROR(Status) || RCTData->CallbackRunIdle == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d CreateEvent(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    DEBUG ((EFI_D_ERROR, "%a.%d CreateEvent(): RCTData->CallbackRunIdle = 0x%X\n", __FUNCTION__, __LINE__, RCTData->CallbackRunIdle));
    gRCTStatus = EFI_OUT_OF_RESOURCES;
    goto _error_exit;
  }

  //save data
  gRCTData = RCTData;
  gRCTStatus = RCTData->Status;

#if 0
  //for LOGging - cancel timer and call directly
  gBS->SetTimer(RCTData->CallbackRun, TimerCancel, 0);
  do {
    RemoteCfgTlsCallback(gRCTData->CallbackRun, gRCTData);
  } while (gRCTData->State != ST_STOPPED);
#endif

//_success_exit:
  gBS->RestoreTPL(OldTpl);
  return EFI_SUCCESS;

_error_exit:
  if (RCTData != NULL) {
    if (RCTData->CallbackRunIdle != NULL) {
      gBS->CloseEvent(RCTData->CallbackRunIdle);
      RCTData->CallbackRunIdle = NULL;
    }
    if (RCTData->CallbackRun != NULL) {
      gBS->SetTimer(RCTData->CallbackRun, TimerCancel, 0);//Stop it first
      gBS->CloseEvent(RCTData->CallbackRun);
    }
    if (RCTData->StopAttempt != NULL) {
      gBS->SetTimer(RCTData->StopAttempt, TimerCancel, 0);
      gBS->CloseEvent(RCTData->StopAttempt);
    }

    if (RCTData->TcpSettings.CertAsn1Buf != NULL) {
      FreePool(RCTData->TcpSettings.CertAsn1Buf);
    }
    if (RCTData->TcpSettings.PrivKeyAsn1Buf != NULL) {
      FreePool(RCTData->TcpSettings.PrivKeyAsn1Buf);
    }
    if (RCTData->TcpSettings.CaCertsP7bBuf != NULL) {
      FreePool(RCTData->TcpSettings.CaCertsP7bBuf);
    }

    //TODO: RemoteCfgPkt destroy here
    if (RCTData->RCPktHandle != NULL && RCTData->RCPkt != NULL) {
      RCTData->RCPkt->ProtocolClose(RCTData->RCPkt, RCTData->RCPktHandle);
    }

    if (RCTData->InChunk != NULL) {
      FreePool(RCTData->InChunk);
    }
    if (RCTData != NULL) {
      FreePool(RCTData);
    }
  }
  if (RCTSettings != NULL) {
    FreePool(RCTSettings);
  }
  //gRCTStatus = EFI_ABORTED;//don't change gRCTStatus here
  gRCTData = NULL;
  gBS->RestoreTPL(OldTpl);
  return gRCTStatus;
}

/**
  Stop Remote Config Protocol connection
  
  @param  param                   desc
  
  @retval EFI_ABORTED             Error occured
  @retval EFI_SUCCESS             Succesfully started
**/
EFI_STATUS
EFIAPI
RemoteCfgTlsStop(
  IN REMOTE_CFG_TLS_PROTOCOL *This
  )
{
  EFI_STATUS Status;
  REMOTE_CFG_TLS_WORK_DATA* RCTData;
  EFI_TPL OldTpl;

  OldTpl = gBS->RaiseTPL(REMOTE_CFG_TLS_CALLBACK_TPL);

  RCTData = gRCTData;  
  DEBUG ((EFI_D_INFO, "%a.%d gRCTData = 0x%X\n", __FUNCTION__, __LINE__, RCTData));
  if (RCTData != NULL) {
    gRCTData = NULL;
    
    if (RCTData->CallbackRunIdle != NULL) {
      gBS->CloseEvent(RCTData->CallbackRunIdle);
      RCTData->CallbackRunIdle = NULL;
    }

    if (RCTData->CallbackRun != NULL) {
      gBS->SetTimer(RCTData->CallbackRun, TimerCancel, 0);//Stop it first
      gBS->CloseEvent(RCTData->CallbackRun);
    }
    
    gRCTStatus = RCTData->Status;
    
    if (RCTData->TcpConn != NULL && RCTData->Tcp != NULL) {
      //stop destroying instantly
      Status = RCTData->Tcp->Destroy(RCTData->Tcp, 
                                     RCTData->TcpConn, 
                                     FALSE);//fast destroy - free memory etc and exit
      DEBUG ((EFI_D_ERROR, "%a.%d Tcp->Destroy(): Status == %r\n", __FUNCTION__, __LINE__, Status));
    }
    if (RCTData->StopAttempt != NULL) {
      gBS->SetTimer(RCTData->StopAttempt, TimerCancel, 0);
      gBS->CloseEvent(RCTData->StopAttempt);
    }

    if (RCTData->TcpSettings.CertAsn1Buf != NULL) {
      FreePool(RCTData->TcpSettings.CertAsn1Buf);
    }
    if (RCTData->TcpSettings.PrivKeyAsn1Buf != NULL) {
      FreePool(RCTData->TcpSettings.PrivKeyAsn1Buf);
    }
    if (RCTData->TcpSettings.CaCertsP7bBuf != NULL) {
      FreePool(RCTData->TcpSettings.CaCertsP7bBuf);
    }

    if (RCTData->ServerIp != NULL) {
      FreePool(RCTData->ServerIp);
    }

    //TODO: RemoteCfgPkt destroy here
    if (RCTData->RCPktHandle != NULL && RCTData->RCPkt != NULL) {
      RCTData->RCPkt->ProtocolClose(RCTData->RCPkt, RCTData->RCPktHandle);
    }
    
    {
      LIST_ENTRY *OutChunk, *NextOutChunk;
      OutChunk = GetFirstNode(&RCTData->OutQueue);
      while (!IsNull(&RCTData->OutQueue, OutChunk)) {
        NextOutChunk = RemoveEntryList(OutChunk);
        FreePool(OutChunk);
        OutChunk = NextOutChunk;
      }
      if (RCTData->InChunk != NULL) {
        FreePool(RCTData->InChunk);
      }
    }
    if (RCTData->Settings != NULL) {
      FreePool(RCTData->Settings);
    }
    if (RCTData != NULL) {
      FreePool(RCTData);
    }
  }
  
  gBS->RestoreTPL(OldTpl);
  return EFI_SUCCESS;
}

/**
  Return current status of connection.
  Make nonevident Stop() if service is in error state
  
  @param  param                   desc
  
  Halt errors(service can't run):
  @retval EFI_INVALID_PARAMETER   Settings not found/incorrect settings
  @retval EFI_NOT_FOUND           Can't locate RemoteCfgPkt/TCP protocols/OpenSSL certificates/keys/etc
  @retval EFI_OUT_OF_RESOURCES    Cannot allocate memory/resources for internal structures
  @retval EFI_LOAD_ERROR          RemoteCfgPkt/TCP protocol initiliazing/destroying error
  @retval EFI_UNSUPPORTED         Service disabled
  @retval EFI_ABORTED             Error occured

  Retry attempt(service autorestart):
  @retval EFI_DEVICE_ERROR        TCP protocol error
  @retval EFI_PROTOCOL_ERROR      RemoteCfgPkt protocol error
  @retval EFI_TIMEOUT             Service restarted by timeout
  @retval EFI_NO_MAPPING          Can't DNS resolve server name/Incorrect server IP address

  End of attempts(service autostop):
  @retval EFI_NO_RESPONSE         Connect failed - max number of connect attempts reached

  No error:
  @retval EFI_NOT_STARTED         Not running now
  @retval EFI_ALREADY_STARTED     Succesfully started
  @retval EFI_NOT_READY           Succesfully started and start connecting
  @retval EFI_SUCCESS             Succesfully started and connected
**/
EFI_STATUS
EFIAPI
RemoteCfgTlsGetCurrentStatus(
  IN REMOTE_CFG_TLS_PROTOCOL *This
  )
{
  REMOTE_CFG_TLS_WORK_DATA* RCTData;
  EFI_TPL OldTpl;

  OldTpl = gBS->RaiseTPL(REMOTE_CFG_TLS_CALLBACK_TPL);

  RCTData = gRCTData;
  DEBUG ((EFI_D_INFO, "%a.%d gRCTData = 0x%X\n", __FUNCTION__, __LINE__, RCTData));
  if (RCTData != NULL) {
    gRCTStatus = RCTData->Status;
    if (!REMOTE_CFG_TLS_GOOG_STATUS(gRCTStatus)) {
        RemoteCfgTlsStop(This);
        gBS->RestoreTPL(OldTpl);
        DEBUG ((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, gRCTStatus));
        return gRCTStatus;
    }
  }
  
  gBS->RestoreTPL(OldTpl);
  DEBUG ((EFI_D_INFO, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, gRCTStatus));
  return gRCTStatus;
}

EFI_STATUS
EFIAPI
RemoteCfgTlsDxeInit(
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status;
  GLOBAL_CONFIG_PROTOCOL *pGlobalConfigProtocol = NULL;

  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  InitFsUtils(ImageHandle);

  gPrivateData.HandlerProtocol.Start = RemoteCfgTlsStart;
  gPrivateData.HandlerProtocol.Stop = RemoteCfgTlsStop;
  gPrivateData.HandlerProtocol.GetCurrentStatus = RemoteCfgTlsGetCurrentStatus;
  gPrivateData.HandlerProtocol.GetSettings = RemoteCfgTlsGetSettings;
  gPrivateData.HandlerProtocol.SetSettings = RemoteCfgTlsSetSettings;
  
  Status = gBS->InstallProtocolInterface(&gPrivateData.DriverHandle, 
                                         &gRemoteCfgTlsProtocolGuid,
                                         EFI_NATIVE_INTERFACE,
                                         &gPrivateData.HandlerProtocol);
  DEBUG ((EFI_D_INFO, "%a.%d InstallProtocolInterface(): Status = %r\n", __FUNCTION__, __LINE__, Status));
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = gBS->LocateProtocol(&gGlobalConfigProtocolGuid,
                               NULL,
                               (VOID **) &pGlobalConfigProtocol);
  if (EFI_ERROR(Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d LocateProtocol(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  Status = pGlobalConfigProtocol->AddConfig(RemoteCfgTlsConfigSectionName,
                                    RemoteCfgTlsSetConfigFromDictionary, DumpRemoteCfgTlsToDictionary);
  if (EFI_ERROR(Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d AddConfig(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  return EFI_SUCCESS;
}
