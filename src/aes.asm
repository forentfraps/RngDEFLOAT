global HealthySeed

section .text

RNG_gen:
  ;rcx - ptr to store data
  ;rdx - how many bytes ( divisible and alibned by 32)
  ;r8 - seed (16 bytes + 16bytes aligned)
  movdqa xmm0, [r8]
  movdqa xmm1, xmm0
  aesenc xmm0, xmm1
  vinsertf ymm0, ymm0, xmm1, 1 


  vaesenc ymm1, ymm0, ymm0
  vaesenc ymm2, ymm1, ymm0
  vaesenc ymm3, ymm2, ymm1
  vaesenc ymm4, ymm3, ymm2
  vaesenc ymm5, ymm4, ymm3
  vaesenc ymm6, ymm5, ymm4
  vaesenc ymm7, ymm6, ymm5
  vaesenc ymm8, ymm7, ymm6
  vaesenc ymm9, ymm8, ymm7

  

HealthySeed:
  ;rcx - buf
  ;rdx - size to write %8  == 0

  rdseed rax
  sub rdx, 8
  mov [rcx + rdx], rax
  cmp rdx, 0
  jnz HealthySeed
  ret

