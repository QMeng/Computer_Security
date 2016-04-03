make
gdb target2
break foo
run test
info frame

p &buf

gdb ./sploit3
break target3.c: 20
r
x/256xw $rsp
c 3