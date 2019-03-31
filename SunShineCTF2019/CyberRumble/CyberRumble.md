


# Sunshine CTF

## pwnable

### CyberRumble
![](https://i.imgur.com/13EeQsu.png)
[binary file](https://github.com/ICEB3AR/IceBear_CTF_History/blob/master/SunShineCTF2019/CyberRumble/CyberRumble.dms)



```__int64 __fastcall main(__int64 a1, char **a2, char **a3, __int64 a4, __int64 a5, __int64 a6)
{
  char s1; // [rsp+0h] [rbp-70h]
  _BYTE v8[6]; // [rsp+Ah] [rbp-66h]
  _BYTE v9[5]; // [rsp+Bh] [rbp-65h]
  _BYTE v10[3]; // [rsp+15h] [rbp-5Bh]
  unsigned __int64 v11; // [rsp+68h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  sub_CCA("TODO: fix the bugs and test this code more to make sure it works...\n", a2, a3, a4, a5, a6);
  puts("Undertaker Ready");
  do
  {
    printf("Move?\n> ");
    read_100(&s1);
    if ( !strncmp(&s1, "chokeslam ", 0xAuLL) )
    {
      chokeslam();
    }
    else if ( !strncmp(&s1, "tombstone_piledriver ", 0x15uLL) )
    {
      tombstone(v10);
    }
    else
    {
      if ( strncmp(&s1, "old_school ", 0xBuLL) )
      {
        if ( !strncmp(&s1, "last_ride ", 0xAuLL) )
          sub_10C1(v8, "last_ride ");
        if ( !strcmp(&s1, "i_am_a_hacker_just_give_me_the_flag") )
        {
          system("cat flag");
          abort();
        }
        puts("Hey, that's an illegal move! You're disqualified!");
        abort();
      }
      sub_F67(v9);
    }
  }
  while ( strcmp(&s1, "forfeit") );
  return 0LL;
}
```

#### chokeslam

```int chokeslam()
{
  return puts("Undertaker C2 v0.0.1");
}
```
그냥 puts 하나 실행해주고 끝납니다

#### i_am_a_hacker_just_give_me_the_flag

```
sun{get trolled kid this is not the real flag}

No really, it's a bit harder than that.
The real flag is in flag.txt. You may need to chain together issues with multiple command handlers.
```
실제 플래그는 flag.txt파일에 있습니다.  


#### tombstone

```unsigned __int64 __fastcall tombstone(const char *a1)
{
  __int64 v1; // rdx
  __int64 v2; // rcx
  __int64 v3; // r8
  __int64 v4; // r9
  FILE *stream; // [rsp+18h] [rbp-78h]
  char v7; // [rsp+20h] [rbp-70h]
  int v8; // [rsp+80h] [rbp-10h]
  unsigned __int64 v9; // [rsp+88h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  stream = fopen(a1, "r");
  if ( !stream )
  {
    printf("Failed to open file '%s'\n", a1);
    abort();
  }
  memset(&v7, 0, 0x60uLL);
  v8 = 0;
  if ( __isoc99_fscanf(stream, "%99s", &v7) != 1 )
  {
    puts("Reading from file failed!");
    abort();
  }
  fclose(stream);
  sub_CCA("TODO: why does this only show the first word in the file?\n", "%99s", v1, v2, v3, v4);
  printf("File contents: '%s'\n", &v7);
  return __readfsqword(0x28u) ^ v9;
}
```

a1변수에 저장된 이름으로 file 하나를 open해서 scanf로 파일 내용을 가져옵니다.

위에서 알아낸 정보를 통해 flag.txt를 a1에 주고 실행을 시키게 되면 
```
File contents: 'sun{the'
```
이렇게 첫 단어만 나오게 됩니다. 

플래그 내용이 '_' 가 아닌 띄어쓰기가 있기 때문에 scanf로 받아 올때 ' ' 를 만나면 EOF인줄 알기 때문에 더이상 읽어오지 않습니다.

#### old_school

```
unsigned __int64 __fastcall sub_F67(const char *a1)
{
  __int64 v1; // rdx
  __int64 v2; // rcx
  __int64 v3; // r8
  __int64 v4; // r9
  __int64 v5; // rdi
  void *dest; // [rsp+18h] [rbp-28h]
  size_t len; // [rsp+28h] [rbp-18h]
  char v9; // [rsp+34h] [rbp-Ch]
  unsigned __int64 v10; // [rsp+38h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  len = strlen(a1);
  if ( !len )
  {
    puts("No shellcode given.");
    abort();
  }
  dest = mmap(0LL, len, 3, 34, -1, 0LL);
  if ( dest == -1LL )
    abort();
  memcpy(dest, a1, len);
  sub_CCA("TODO: what's the flag for making memory executable?\n", a1, v1, v2, v3, v4);
  mprotect(dest, len, 1);
  printf("Shellcode written to %p.\n", dest);
  printf("Jump to shellcode?\n[y/n] ");
  read_100(&v9);
  v5 = v9;
  if ( tolower(v5) == 'y' )
  {
    (dest)(v5, 4LL);
    abort();
  }
  if ( tolower(v9) == 'n' )
    munmap(dest, len);
  return __readfsqword(0x28u) ^ v10;
}
```

a1 에 저장된 문자열을 함수포인터를 이용해 실행시켜줍니다.

쉘코드를 준다면 실행이 되겠지만 mprotect인자를 1로 줘서 execute가 불가능합니다. 
그리고 그 문자열이 저장된 주소를 출력해줍니다.

따라서 이 부분에서 얻을 수 있는 것은 문자열이 저장된 주소입니다.

#### last_ride
```
void __fastcall __noreturn sub_10C1(const char *a1, __int64 a2)
{
  __int64 v2; // rdx
  __int64 v3; // rcx
  __int64 v4; // r8
  __int64 v5; // r9
  const char *dest; // [rsp+18h] [rbp-18h]
  size_t v7; // [rsp+20h] [rbp-10h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  v7 = strlen(a1);
  if ( v7 > 0x13 )
  {
    puts("Shell command too long!");
    abort();
  }
  dest = malloc(0x14uLL);
  if ( !dest )
    abort();
  sub_CCA("TODO: why does the shell command not work? i wish i knew pointers better...\n", a2, v2, v3, v4, v5);
  memcpy(&dest, a1, 0x14uLL);
  system(dest);
  abort();
}
```
a1에 전달된 인자를 dest에 저장하고 system의 인자로 전달합니다.

하지만 여기서 system(&dest)가 아니고 system(dest)이기 때문에 dest에 주소값을 넣어주어야 합니다. 

#### Vulnerability


```
if ( tolower(v5) == 'y' )
  {
    (dest)(v5, 4LL);
    abort();
  }
  if ( tolower(v9) == 'n' )
    munmap(dest, len);
  return __readfsqword(0x28u) ^ v10;
```
old school에서 실행하시겠습니까? 를 물어볼 때 y를 입력하면 dest를 실행하고, 실패하면 꺼지고, n을 입력하면 munmap을 통해 할당했던 dest를 해제합니다. 

여기서 취약점은 y또는 n을 입력하지 않으면 아무 행동도 취하지 않고 return하기 때문에 출력되었던 pointer값을 사용할 수 있습니다.

따라서 old school 인자로 cat flag.txt를 주게 되면 
dest에 cat flag.txt가 저장될 것이고 우리는 그 포인터 주소를 알게 됩니다.

그리고 last ride에 방금 알아낸 주소값을 인자로 주게 되면
dest에는 cat flag.txt의 주솟값이 들어가고, system(cat flag.txt)가 실행되게 됩니다.


