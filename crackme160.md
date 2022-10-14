# crackme160

160个crackme，虽然年代久远，但是可以用来练手ida/x64dbg，了解一些简单的Pwn技巧，能做多少是多少吧。

## Acid burn

### call stack

在弹窗显示序列号错误的时候，暂停程序，此时跳转到当时指令，在右下角堆栈中往下找就能找到序列号`"CW-XXXX-CRACKED"`

### nop

注意有两个返回错误的分支，一个是因为name不超过3个字符（直接把整个分支nop掉），另一个是序列号检查（把条件跳转nop掉即可）

### Keygen

```asm
0042FA4D | A1 6C174300              | mov eax,dword ptr ds:[43176C]           | 0043176C:&"1111X"
0042FA52 | E8 D96EFDFF              | call acid burn.406930                   |
0042FA57 | 83F8 04                  | cmp eax,4                               |
0042FA5A | 7D 1D                    | jge acid burn.42FA79                    |
0042FA5C | 6A 00                    | push 0                                  |
0042FA5E | B9 74FB4200              | mov ecx,acid burn.42FB74                | 42FB74:"Try Again!"
0042FA63 | BA 80FB4200              | mov edx,acid burn.42FB80                | 42FB80:"Sorry , The serial is incorect !"
...
0042FA87 | 8B45 F0                  | mov eax,dword ptr ss:[ebp-10]           | # name -> eax
0042FA8A | 0FB600                   | movzx eax,byte ptr ds:[eax]             | # ord(name[0]) -> eax
0042FA8D | F72D 50174300            | imul dword ptr ds:[431750]              | # eax *= 0x29
0042FA93 | A3 50174300              | mov dword ptr ds:[431750],eax           |
0042FA98 | A1 50174300              | mov eax,dword ptr ds:[431750]           |
0042FA9D | 0105 50174300            | add dword ptr ds:[431750],eax           | # 自加，相当于eax *= 2
0042FAA3 | 8D45 FC                  | lea eax,dword ptr ss:[ebp-4]            |
0042FAA6 | BA ACFB4200              | mov edx,acid burn.42FBAC                | 42FBAC:"CW"
0042FAAB | E8 583CFDFF              | call acid burn.403708                   |
0042FAB0 | 8D45 F8                  | lea eax,dword ptr ss:[ebp-8]            |
0042FAB3 | BA B8FB4200              | mov edx,acid burn.42FBB8                | 42FBB8:"CRACKED"
0042FAB8 | E8 4B3CFDFF              | call acid burn.403708                   |
0042FABD | FF75 FC                  | push dword ptr ss:[ebp-4]               |
0042FAC0 | 68 C8FB4200              | push acid burn.42FBC8                   | # [42FBC8] = 0x2D 即 '-'
0042FAC5 | 8D55 E8                  | lea edx,dword ptr ss:[ebp-18]           |
0042FAC8 | A1 50174300              | mov eax,dword ptr ds:[431750]           | # [431750] = eax
0042FACD | E8 466CFDFF              | call acid burn.406718                   |
0042FAD2 | FF75 E8                  | push dword ptr ss:[ebp-18]              |
0042FAD5 | 68 C8FB4200              | push acid burn.42FBC8                   | # [42FBC8] = 0x2D 即 '-'
0042FADA | FF75 F8                  | push dword ptr ss:[ebp-8]               |
0042FADD | 8D45 F4                  | lea eax,dword ptr ss:[ebp-C]            | # [ebp-C] = 'CW-XXXX-CRACKED'
0042FAE0 | BA 05000000              | mov edx,5                               |
0042FAE5 | E8 C23EFDFF              | call acid burn.4039AC                   | 
0042FAEA | 8D55 F0                  | lea edx,dword ptr ss:[ebp-10]           |
0042FAED | 8B83 E0010000            | mov eax,dword ptr ds:[ebx+1E0]          |
0042FAF3 | E8 60AFFEFF              | call acid burn.41AA58                   |
0042FAF8 | 8B55 F0                  | mov edx,dword ptr ss:[ebp-10]           | # [ebp-10] = userinputSerial
0042FAFB | 8B45 F4                  | mov eax,dword ptr ss:[ebp-C]            |
0042FAFE | E8 F93EFDFF              | call acid burn.4039FC                   |
0042FB03 | 75 1A                    | jne acid burn.42FB1F                    | # 判断
0042FB05 | 6A 00                    | push 0                                  |
0042FB07 | B9 CCFB4200              | mov ecx,acid burn.42FBCC                | 42FBCC:"Congratz !!"
0042FB0C | BA D8FB4200              | mov edx,acid burn.42FBD8                | 42FBD8:"Good job dude =)"
0042FB11 | A1 480A4300              | mov eax,dword ptr ds:[430A48]           |
0042FB16 | 8B00                     | mov eax,dword ptr ds:[eax]              |
0042FB18 | E8 53A6FFFF              | call acid burn.42A170                   |
0042FB1D | EB 18                    | jmp acid burn.42FB37                    |
0042FB1F | 6A 00                    | push 0                                  |
0042FB21 | B9 74FB4200              | mov ecx,acid burn.42FB74                | 42FB74:"Try Again!"
0042FB26 | BA 80FB4200              | mov edx,acid burn.42FB80                | 42FB80:"Sorry , The serial is incorect !"
```

总结：取name第一个字符的ascii码，乘以0x29，再乘以2，`"CW-"+result+"CRACKED"`即为序列号。

**Python Keygen:**

```python
name = input("Enter your name: ")
firstAscii = name.encode("ascii")[0]
result = str(firstAscii * 0x29 * 2)
print("Your key is: " + "CW-" + result + "CRACKED")
```



## Afkayas.1

### nop

与001相同，先在弹窗时暂停，在调用堆栈中观察，找到唯一一个从`afkayas.1`主程序返回到`msvbvm50`模块的堆栈

```
地址=0019F274
返回到=740DE5A9 // msvbvm50 动态链接库在内存高处
返回自=00402622 // afkayas.1 程序代码在内存低处
大小=1C
注释=afkayas.1.00402622
```

```asm
0040258B     | 74 58                 | je afkayas.1.4025E5                       | 推测这里就是判断指令，右键二进制nop填充
0040258D     | 68 801B4000           | push afkayas.1.401B80                     | 401B80:L"You Get It"
00402592     | 68 9C1B4000           | push afkayas.1.401B9C                     | 401B9C:L"\r\n"
00402597     | FFD7                  | call edi                                  |
00402599     | 8BD0                  | mov edx,eax                               |
0040259B     | 8D4D E8               | lea ecx,dword ptr ss:[ebp-18]             |
0040259E     | FFD3                  | call ebx                                  |
004025A0     | 50                    | push eax                                  |
004025A1     | 68 A81B4000           | push afkayas.1.401BA8                     | 401BA8:L"KeyGen It Now"
```

填充后继续程序，随便输入即可成功，提示KeyGen It Now，试试就试试（

### Keygen

同样先定位到主程序位置，然后找到程序起点（一般为 `push ebp` ），打断点，继续执行，然后F8步进分析：

```asm
00402310  | 55                  | push ebp                                  | # 这里的push ebp最可疑 因为后面调用到各种vb的字符串函数
...
0040240F  | 8B45 E4             | mov eax,dword ptr ss:[ebp-1C]             | [ebp-1C]:L"Type In Your Name"
00402412  | 50                  | push eax                                  |
00402413  | 8B1A                | mov ebx,dword ptr ds:[edx]                |
00402415  | FF15 E4404000       | call dword ptr ds:[<&__vbaLenBstr>]       | # LenBstr函数计算Name的长度
0040241B  | 8BF8                | mov edi,eax                               |
0040241D  | 8B4D E8             | mov ecx,dword ptr ss:[ebp-18]             |
00402420  | 69FF FB7C0100       | imul edi,edi,17CFB                        | # 将长度与0x17CFB相乘
00402426  | 51                  | push ecx                                  |
00402427  | 0F80 91020000       | jo afkayas.1.4026BE                       |
0040242D  | FF15 F8404000       | call dword ptr ds:[<&rtcAnsiValueBstr>]   | # 该函数返回首字母的Ansi值
00402433  | 0FBFD0              | movsx edx,ax                              |
00402436  | 03FA                | add edi,edx                               | # result = len*0x17CFB + firstAnsi
00402438  | 0F80 80020000       | jo afkayas.1.4026BE                       |
0040243E  | 57                  | push edi                                  |
0040243F  | FF15 E0404000       | call dword ptr ds:[<&__vbaStrI4>]         | # 返回result的十进制表示的字符串
00402445  | 8BD0                | mov edx,eax                               |
00402447  | 8D4D E0             | lea ecx,dword ptr ss:[ebp-20]             |
...
00402510  | 8B45 E8             | mov eax,dword ptr ss:[ebp-18]             |
00402513  | 8B4D E4             | mov ecx,dword ptr ss:[ebp-1C]             | # ecx = [ebp-1C]: result
00402516  | 8B3D 00414000       | mov edi,dword ptr ds:[<&__vbaStrCat>]     | # edi = StrCat()
0040251C  | 50                  | push eax                                  |
0040251D  | 68 701B4000         | push afkayas.1.401B70                     | 401B70:L"AKA-"
00402522  | 51                  | push ecx                                  |
00402523  | FFD7                | call edi                                  | # str = StrCat("AKA-",result)
00402525  | 8B1D 70414000       | mov ebx,dword ptr ds:[<&__vbaStrMove>]    |
0040252B  | 8BD0                | mov edx,eax                               |
0040252D  | 8D4D E0             | lea ecx,dword ptr ss:[ebp-20]             |
00402530  | FFD3                | call ebx                                  |
00402532  | 50                  | push eax                                  |
00402533  | FF15 28414000       | call dword ptr ds:[<&__vbaStrCmp>]        | # StrCmp(serial, str)
00402539  | 8BF0                | mov esi,eax                               | # if equals return 0 to eax to esi
0040253B  | 8D55 E0             | lea edx,dword ptr ss:[ebp-20]             | # 后面就是检测是否一致吧大概
...
0040258B  | 74 58               | je afkayas.1.4025E5                       |
0040258D  | 68 801B4000         | push afkayas.1.401B80                     | 401B80:L"You Get It"
00402592  | 68 9C1B4000         | push afkayas.1.401B9C                     | 401B9C:L"\r\n"
```

总结：先取出name的长度len, 然后取出name第一个字符的ANSI值firstAnsi, 让后计算len*0x17CFB+firstAnsi,将计算的值转换为十进制文本，前面加上”AKA-”组成最后的serial

**Python Keygen:**

```python
name = input("Enter your name: ")
nameLen = len(name)
firstAnsi = name.encode("ansi")[0]
result = str(nameLen * 0x17CFB + firstAnsi)
print("Your key is: " + "AKA-" + result)
```



## Afkayas.2

### nop

跟002基本完全是一样，此处省略

### Keygen

与002很相似，就是多了好几步浮点数运算，一样找到主程序入口

```asm
004080F0 | 55                       | push ebp                                | <-- This
......
004081F5 | FF15 F8B04000            | call dword ptr ds:[<&__vbaLenBstr>]     | # 返回name的长度
004081FB | 8BF8                     | mov edi,eax                             |
004081FD | 8B4D E8                  | mov ecx,dword ptr ss:[ebp-18]           |
00408200 | 69FF 385B0100            | imul edi,edi,15B38                      | # len *= 0x15B38
00408206 | 51                       | push ecx                                |
00408207 | 0F80 B7050000            | jo afkayas.2.4087C4                     |
0040820D | FF15 0CB14000            | call dword ptr ds:[<&rtcAnsiValueBstr>] | # 返回首字符Ansi值
00408213 | 0FBFD0                   | movsx edx,ax                            |
00408216 | 03FA                     | add edi,edx                             | # Ansi + len
00408218 | 0F80 A6050000            | jo afkayas.2.4087C4                     |
0040821E | 57                       | push edi                                |
0040821F | FF15 F4B04000            | call dword ptr ds:[<&__vbaStrI4>]       | # str(Ansi + len)
......
004082E9 | FF15 74B14000            | call dword ptr ds:[<&__vbaR8Str>]       | # 将str转为十进制放入st(0)
004082EF | D905 08104000            | fld st(0),dword ptr ds:[401008]         |
# fld读取位于[401008]的浮点数到st(0) 内存定位到0x401008 得到00 00 20 41大端41 20 00 00 转换为十进制浮点数为10放入st(0) 之前的st(0)推到st(1)
004082F5 | 833D 00904000 00         | cmp dword ptr ds:[409000],0             | 
004082FC | 75 08                    | jne afkayas.2.408306                    |
004082FE | D835 0C104000            | fdiv st(0),dword ptr ds:[40100C]        | # st(0)/[40100C] = 10.0/5.0 = 2.0
00408304 | EB 0B                    | jmp afkayas.2.408311                    |
00408306 | FF35 0C104000            | push dword ptr ds:[40100C]              |
0040830C | E8 578DFFFF              | call <JMP.&_adj_fdiv_m32>               |
00408311 | 83EC 08                  | sub esp,8                               |
00408314 | DFE0                     | fnstsw ax                               |
00408316 | A8 0D                    | test al,D                               |
00408318 | 0F85 A1040000            | jne afkayas.2.4087BF                    |
0040831E | DEC1                     | faddp st(1),st(0)                       | # strSum = strSum + 2.0
...... # 这中间省略的大概是vb自己搞的存储数字的过程，忽略即可
004083FB | DC0D 10104000            | fmul st(0),qword ptr ds:[401010]        |
# 注意fmul读取的是qword也就是double类型的浮点数得到0x4008000000000000 转换为十进制浮点数为3 即 strSum = st(0) *= 3.0
00408401 | 83EC 08                  | sub esp,8                               |
00408404 | DC25 18104000            | fsub st(0),qword ptr ds:[401018]        | # st(0) -= 2.0
......
004084E5 | DC25 20104000            | fsub st(0),qword ptr ds:[401020]        | # st(0) -= -15
004084EB | 83EC 08                  | sub esp,8                               |
004084EE | DFE0                     | fnstsw ax                               |
004084F0 | A8 0D                    | test al,D                               |
004084F2 | 0F85 C7020000            | jne afkayas.2.4087BF                    |
004084F8 | DD1C24                   | fstp qword ptr ss:[esp],st(0)           |
......
004085C7 | 50                       | push eax                                |
004085C8 | FF15 18B14000            | call dword ptr ds:[<&__vbaHresultCheckO |
004085CE | 8B45 E8                  | mov eax,dword ptr ss:[ebp-18]           |
004085D1 | 50                       | push eax                                | # 这里就是返回结果的指令（eax一般作为函数返回数据的寄存器） 下面就是与用户输入的serial作比较得到je的条件
......
00408677 | 74 62                    | je afkayas.2.4086DB                     |
00408679 | 8B35 14B14000            | mov esi,dword ptr ds:[<&__vbaStrCat>]   |
0040867F | 68 C06F4000              | push afkayas.2.406FC0                   | 406FC0:L"You Get It"
00408684 | 68 DC6F4000              | push afkayas.2.406FDC                   | 406FDC:L"\r\n"
```

**Python Keygen:**

```python
name = input("Enter your name: ")
nameLen = len(name)
firstAnsi = name.encode("ansi")[0]
result = str(nameLen * 0x17CFB + firstAnsi)
print("Your key is: " + "AKA-" + result)
```

### remove nag

nag就是那种很烦人的启动窗口，比如说开启程序后出现一张图片等几秒才能进入主程序的这种（不知道“加载中”算不算nag呢？），这个程序的nag就是这样，等几秒才能进入。

参考吾爱的帖子：https://www.52pojie.cn/thread-612982-1-1.html

可以说完全不会，VB5毕竟是上个世纪的产物了，也只能在一些老旧的教程里找到一些特殊的方法，4C法就是其中之一。

具体过程与52里的完全一致，就是新时代的x32dbg可以用补丁来保存exe，这一点要记住。

## ajj.1

很有年代感的crackme，，，没有弹窗增加了一点找到主程序入口的难度，但只要暂停然后在call stack中找到返回到内存低处的堆栈，跳转到那里即可，更方便的方法是查找字符串，直接定位到注册成功的分支。

### nop

字符串查找到“恭喜恭喜，注册成功”这一串，跳转，观察附近的条件跳转。

```
0045803B | 75 76                    | jne ckme.4580B3                         | # 直接跳过输出成功的过程
00458092 | 75 AB                    | jne ckme.45803F                         | # 造成循环
```

nop掉以后，随意输入点击灰色图框即可（朱茵的照片也太有年代感了，毕竟是我还没出生时就有的程序🤣）

### Keygen

一开始光看x32dbg真的看不懂在干什么，到网上查了一下知道了delphi有专门的反汇编工具DeDe可以得到窗体的各种信息，发现了chkcode、Panel1DblClick、Panel1Click四个重要的事件。

chkcode：

```asm
00457C40 | 55                         | push ebp                                | # chkcode事件
00457C41 | 8BEC                       | mov ebp,esp                             |
00457C43 | 51                         | push ecx                                |
00457C44 | B9 05000000                | mov ecx,5                               |
00457C49 | 6A 00                      | push 0                                  |
00457C4B | 6A 00                      | push 0                                  |
00457C4D | 49                         | dec ecx                                 |
00457C4E | 75 F9                      | jne ckme.457C49                         |
00457C50 | 51                         | push ecx                                |
00457C51 | 874D FC                    | xchg dword ptr ss:[ebp-4],ecx           |
00457C54 | 53                         | push ebx                                |
00457C55 | 56                         | push esi                                | 
00457C56 | 8BD8                       | mov ebx,eax                             | 
00457C58 | 33C0                       | xor eax,eax                             | 
00457C5A | 55                         | push ebp                                |
00457C5B | 68 3D7E4500                | push ckme.457E3D                        |
00457C60 | 64:FF30                    | push dword ptr fs:[eax]                 |
00457C63 | 64:8920                    | mov dword ptr fs:[eax],esp              |
00457C66 | 8BB3 F8020000              | mov esi,dword ptr ds:[ebx+2F8]          | 
00457C6C | 83C6 05                    | add esi,5                               | # 5为初始数 后面一长串的call大概就是为了把nameLen加到这个5上
...
```

双击事件和单击事件：

```asm
00457E7C | 55                         | push ebp                                | panel1双击事件
......
00457EF5 | 83BE 0C030000 3E           | cmp dword ptr ds:[esi+30C],3E           |  # 第一次是检测[esi+30C]是否为0x3E 0x3E来自于chkcode事件，也就是必须注册码需要正确
00457EFC | 75 0A                      | jne ckme.457F08                         |
00457EFE | C786 0C030000 85000000     | mov dword ptr ds:[esi+30C],85           | # 如果chkcode正确，赋值85在单击事件中是否为0x85
......
00457FB2 | 8BE5                       | mov esp,ebp                             |
00457FB4 | 5D                         | pop ebp                                 |
00457FB5 | C3                         | ret                                     | # 双击事件结束 若chkcode正确，[esi+30C]为0x85 下一次单击事件就会进入成功分支
00457FB8 | 55                         | push ebp                                | panel1单击事件
00457FB9 | 8BEC                       | mov ebp,esp                             |
00457FBB | B9 04000000                | mov ecx,4                               |
00457FC0 | 6A 00                      | push 0                                  |
00457FC2 | 6A 00                      | push 0                                  |
00457FC4 | 49                         | dec ecx                                 |
00457FC5 | 75 F9                      | jne ckme.457FC0                         |
00457FC7 | 51                         | push ecx                                |
......
00458031 | 81BE 0C030000 85000000     | cmp dword ptr ds:[esi+30C],85           | # 检测[esi+30C]是否为0x85
0045803B | 75 76                      | jne ckme.4580B3                         |
......
004580A9 | BA 14814500                | mov edx,ckme.458114                     | 458114:"恭喜恭喜！注册成功"
```



经过单步调试分析，大概了解到注册码就是 `“黑头Sun Bird” + (5+nameLen) + "dseloffc-012-OK" + name `

比如说用户名`admin`，注册码就是`黑头Sun Bird10dseloffc-012-OKadmin`

大体过程：chkcode若正确则设置`[esi+30C]`为`0x3E`，双击事件读取chkcode的返回若为`0x3E`则设置其为`0x85`，单击事件检测是否为`0x85`，也就是说整个检测是`注册码正确->双击事件->单击事件`这个流程，相当于点击三次panel1才能出现图片
