# letkite-lite

**letkite** 的开源版——把多台 VPS 聚合成一个远程 MCP 服务，挂到 Claude、Kimi 或 GLM 上。纯 SSH，被管机器零改造。

[English](../README.md) · 中文

[架构](ARCHITECTURE.md) · [参考](REFERENCE.md) · [运维](OPERATIONS.md) · [故障速查](TROUBLESHOOTING.md)

---

## 1. 装网关

先把域名 A 记录指向这台机并等生效。

```bash
git clone https://github.com/letkite/letkite-lite.git && cd letkite-lite
sudo deploy/install.sh
```

交互问域名、管理员用户名（默认当前登录用户）、口令（回车即自动生成并打印一次）。
其余全自动：系统依赖、Caddy、SSH 密钥、配置、systemd、证书、起服务、自测。

全自动：

```bash
sudo deploy/install.sh --domain mcp.example.com -y [--self-enroll] [--lock-anthropic]
```

## 2. 接入客户端

所有客户端都填同一个 URL，就是安装器打印的那个：

```
https://mcp.example.com/mcp
```

- **Claude**：设置 → 连接器 → 添加自定义连接器。
- **Kimi**：添加 MCP 服务器，粘贴同一个 URL。
- **GLM / Z.ai**：同上，添加 MCP 服务器填这个 URL。

每个客户端都会跳到你自己的登录页，登录并批准即接上。第一次只勾
`fleet.read` + `fleet.exec`。

```bash
sudo vpsmcp clients      # 当前放行哪些客户端，各自的回调地址
sudo vpsmcp redirects    # 被拒的回调，以及放行它的命令
```

能不能接上，只取决于客户端的 OAuth 回调地址在不在白名单里。Claude、Kimi、GLM
内置（`VPSMCP_CLIENTS=claude,local,kimi,glm`）。别的客户端，或者厂商换了回调地址，
一条命令：

```bash
sudo vpsmcp redirect allow https://example.ai/api/mcp/callback
```

`vpsmcp redirects` 会把被拒的那个 URL 原样打出来，不用猜；加完立即生效，不用重启。
只放行你认得的地址——授权码就是发到那里去的。

## 3. 加节点

目标机上一条命令，不需要令牌，入口永久有效：

```bash
curl -sSf https://mcp.example.com/enroll/install.sh | sudo bash
```

全静默：无输出，退出码 0。节点名默认取本机 hostname。

```bash
... | sudo bash -s -- --alias web-01                 # 指定名字
... | sudo bash -s -- --alias web-01 --tags prod,hk  # 带标签
... | sudo bash -s -- --user deploy                  # 换本机账号名
... | sudo bash -s -- --self                         # 用你的 ssh 登录用户($SUDO_USER)
... | sudo bash -s -- -k <口令>                       # 服务端设了 VPSMCP_ENROLL_KEY 时
... | sudo bash -s -- -v                             # 排障看每一步
... | sudo bash -s -- --uninstall                    # 摘除本机
```

节点上只落一个低权限账号和网关的**公钥**，不装代码、不下发私钥。
同一台机器重复执行是原地更新，不会新增条目。

**免 root**（不建专用账号，网关直接以「你」这个用户登录）：

```bash
curl -sSf https://mcp.example.com/enroll/install.sh | bash -s -- --rootless
... | bash -s -- --rootless --port 2222              # 非默认 SSH 端口
```

免 root 模式只把网关公钥追加到你自己的 `~/.ssh/authorized_keys`，不碰任何系统配置，
所以你的账号必须已经开了 `PubkeyAuthentication`，端口非 22 时要自己带 `--port`
（没有 root 读不到 sshd 配置）。代价：网关此后以你的账号操作，隔离性等同于该账号——
除非你接受「网关等于在这台机上有 root」，否则别用能 sudo 的用户。默认（带 `sudo`）
会另建一个无 sudo 的低权限 `ops` 账号，这正是它需要 root 的原因。

想让「ssh 登录用户」成为整个 fleet 的默认(这样只写 `--alias NAME`、不带
`--user`/`--self` 就用登录用户接入),在网关上设 `VPSMCP_ENROLL_USER='@session'`
再重启。sudo 风险同上:网关此后能做的事等同于你那个登录账号。

新节点默认权限 `fleet.read,fleet.exec,fleet.write`（`VPSMCP_ENROLL_SCOPES`）。

任何知道 URL 的人都能把自己的机器注册进来。收紧：

```ini
VPSMCP_ENROLL_MODE=open|approve|off
VPSMCP_ENROLL_KEY=<口令>
VPSMCP_ENROLL_ALLOW_CIDRS=1.2.3.0/24
```

## 4. 管理

```bash
sudo vpsmcp nodes                                  # node_id / 别名 / 地址 / 账号
sudo vpsmcp node remove  <node_id|别名>
sudo vpsmcp node scopes  <node_id|别名> fleet.read,fleet.exec
sudo vpsmcp node rename  <node_id|别名> <新别名>
sudo vpsmcp node tags    <node_id|别名> a,b
sudo vpsmcp check                                  # 逐台连通性
sudo deploy/healthcheck.sh                         # 分层体检

sudo vpsmcp clients                                # 放行的客户端
sudo vpsmcp redirects                              # 回调白名单 + 被拒记录
sudo vpsmcp redirect allow <uri>                   # 再放行一个客户端
sudo vpsmcp redirect deny  <uri>
sudo vpsmcp grants                                 # 谁手上有活的令牌
sudo vpsmcp revoke <client_id>
```

别名允许重名。身份是 `node_id`（address:port:user 的哈希），重名时传它。

## 更新

```bash
cd letkite-lite && git pull && sudo deploy/upgrade.sh --fast
```

配置与数据不动：节点不用重新接入，授权也不失效。
回滚 `sudo deploy/upgrade.sh --rollback`。

## 卸载

```bash
# 单台节点
sudo vpsmcp node remove web-01
curl -sSf https://mcp.example.com/enroll/install.sh | sudo bash -s -- --uninstall

# 整个网关
sudo deploy/uninstall.sh
```

顺序不能反：网关会趁自己还能用，先把公钥从各台节点摘掉，再删本机配置。

## 四点

1. CLI 一律 `sudo vpsmcp ...`。包装器会切到服务账号，权限行为和守护进程一致。
2. 客户端授权之后不要改资源 URL——它已经绑进签发的令牌里了。
3. 命令护栏防手滑不防攻击。真正的边界是节点上那个无特权 SSH 账号，别给它 sudo。
4. `--lock-anthropic` 只放行 Anthropic 的出口网段，等于把 Kimi、GLM、Claude Code
   全挡掉。只有「只用网页版 Claude」时才开（`--allow-cidr` 可以再加你自己的网段）。

## 许可证

MIT
