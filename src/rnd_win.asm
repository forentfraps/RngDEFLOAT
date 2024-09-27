global HealthySeed

section .text

HealthySeed:
  ;rcx - buf
  ;rdx - size to write %8  == 0

  rdseed rax
  sub rdx, 8
  mov [rcx + rdx], rax
  cmp rdx, 0
  jnz HealthySeed
  ret

