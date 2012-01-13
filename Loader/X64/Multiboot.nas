%define ABSADR(X) (X-_StartOsKernel)
;;  Multiboot header
%define  magic          0x00
%define  flags          0x04
%define  checksum       0x08
%define  header_addr    0x0C
%define  load_addr      0x10
%define  load_end_addr  0x14
%define  bss_end_addr   0x18
%define  entry_addr     0x1C

;;typedef struct _RELOCATION_INFO {
;;  UINT32 MultibootHeader;
;;  UINT32 BaseAddress;
;;  UINT32 LoadAddress;
;;  UINT32 LoadSize;
;;  UINT32 KernelEntry; // 
;;} RELOCATION_INFO;

%define MultibootHeader 0x00
%define BaseAddress     0x04
%define LoadAddress     0x08
%define LoadSize        0x0C
%define KernelEntry     0x10

;;
;;
BITS 64

global StartOsKernel
global AsmStartLinuxKernel


;; extern gMultibootInfo 
segment .data
segment .text

StartOsKernel:
BITS 32

pop eax ;; ret addr

pop ebx ;; Param 1 MB Info
pop ebp ;; Param 2 MB RELOCATION_INFO
mov ecx, [ebp+KernelEntry]
mov eax, 0x2BADB002
call ecx
align 8, db 0

gdt:
   ; /* NULL.  */
db    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
   ; /* Reserved.  */
db    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
   ; /* Code segment.  */
db    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9A, 0xCF, 0x00
   ; /* Data segment.  */
db    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x92, 0xCF, 0x00

align 8, db 0

gdtptr:
dw (4*8 - 1)
dd 0 ; gdt

align 8, db 0

%macro LOADPTR 2
  lea %1,[esi + ((%2) - StartOsKernel)]
%endmacro

idtptr:
dw 0
dd 0
BITS 64
AsmStartLinuxKernel:
BITS 32
cli
pop eax ;; ret addr

pop ecx ;; Param 1 Call address
pop ebp ;; Param 2 Params

call .l1
.l1: 
pop  esi ;;
sub  esi, (.l1 - StartOsKernel) ; esi = StartOsKernel


LOADPTR eax, gdt
LOADPTR edi, (gdtptr+2)
mov [edi], eax
LOADPTR edi, gdtptr
lgdt [edi]
;; lidt [idtptr]
LOADPTR edi, reloadCS
mov eax, 0x10
push ax
push edi
retf  ; jmp   0x10:reloadCS

align 32
reloadCS:

mov   ax,0x18
mov   ds,ax
mov   es,ax
mov   ss,ax
mov   fs,ax
mov   gs,ax
xor   ebx,ebx

mov esi, ebp ;; Params


mov   eax,[ecx]
call ecx

