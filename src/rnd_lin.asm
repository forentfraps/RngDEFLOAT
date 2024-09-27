global HealthySeed

section .text
  

HealthySeed:
  ;rdi - buf
  ;rsi - size to write %8  == 0

  rdseed rax
  sub rsi , 8
  mov [rdi + rsi ], rax
  cmp rsi , 0
  jnz HealthySeed
  ret

