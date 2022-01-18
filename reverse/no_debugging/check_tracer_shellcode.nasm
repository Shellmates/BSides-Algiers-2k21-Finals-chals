rasm2 -ax86.nasm -b64 '  pop r13
  lea rdi, [rel $+7]
  mov rdx, 0xfff
  not rdx
  and rdi, rdx
  xor rsi, rsi
  inc rsi
  shl rsi, 12
  call r13
  cmp eax, r10d
  je short +51
  mov rax, 0x3c
  xor rdi, rdi
  inc rdi
  syscall

fninit
xor rbx, rbx
xor rdx, rdx
inc rdx
fild dword[0x402420]
push r14
fld dword[rsp]
pop r14
fld st0
faddp
fdivp
mov rax,0x49aeb209
push rax
fld dword[rsp]
fcompp
fstsw ax
fwait
sahf
cmovne rbx,rdx

mov eax, dword[0x402420+4]
add eax, r15d
cmp eax, 0x234f27c9
cmovne rbx, rdx
fild dword[0x402420+4]
fisub dword[0x402420]
fild dword[0x402420+8]
xor rax, rax
inc rax
shl rax, 4
push rax
fild qword[rsp]
add rsp, 8
fdivp
faddp
fld1
fadd
sub rsp, 8
fstp qword[rsp]
pop rdi
mov rax, 0x418b1c446f800000
cmp rax, rdi
cmovne rbx, rdx

test rbx, rbx
jz short -32

xor rdi, rdi
mov rax, rdi
inc rax
lea rsi, [0x4023d3]
mov rdx, 22
syscall

jmp short +35

xor rdi, rdi
mov rax, rdi
inc rax
lea rsi, [0x4023ea]
mov rdx, 39
syscall

xor rax, rax
inc rax
lea rsi, [0x402420]
mov rdx, 12
syscall

xor rax, rax
inc rax
lea rsi, [0x402412]
mov rdx, rax
inc rdx
syscall

  mov rax, 0x3c
  xor rdi, rdi
  inc rdi
  syscall
  nop
  nop
' | ruby test.rb
