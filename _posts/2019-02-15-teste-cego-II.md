---
layout: post
title:  "Teste Cego de Cerveja II"
date:   2019-02-15 23:17:55 -0200
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
