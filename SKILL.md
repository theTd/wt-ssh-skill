---
name: wt-ssh-manager
description: |
  管理 Windows Terminal 里的 ssh 主机簿/会话（分组、跳板机、端口、密钥、默认 profile），可从 ~/.ssh/config 批量导入，可选 TPM vault 保护密钥与口令；也能把主机簿条目同步进 FileZilla 站点管理器并命令行直连（filezilla/fz），或在 WT 菜单里放一个随主机条目管理的 SFTP 入口（edit X --sftp，带跳板自动隧道）。Use when the user wants to 管理 Windows Terminal 里的 ssh 连接/主机/会话/服务器列表：添加、修改、删除、重命名、排序 ssh 服务器配置，改跳板机(jump host)、端口、密钥、标签页标题、默认配置文件，查看或新建"ssh 组/分组/文件夹"，从 ~/.ssh/config 导入主机，或说"帮我在 Windows Terminal 里加一台服务器/连 X 的入口"。也适用于"wt 里那个 ssh 分组"、"终端下拉菜单里的 ssh"等指代，以及"用 FileZilla 打开主机簿里的某台服务器 / 从主机簿开 FileZilla 连接"、"给某台主机加个 SFTP 菜单入口"。不管理 WSL/PowerShell 等本地 profile（除 defaultProfile 外）。
---

# Windows Terminal ssh 主机簿管理

用户在 Windows Terminal 的下拉菜单里有一个（可多个）**`ssh` 分组**，就是本 skill 管理的主机簿：
`scripts/wtssh.py` 提供增删改查、导入、分组，以及可选的 TPM vault 密钥保管。**不要手改 settings.json**——
WT 对这个文件有自己的序列化风格，脚本负责写出 WT 兼容的 JSON（写入前校验 JSON、原子替换、自动备份
`settings.json.wtssh.bak`）。手编 JSON 会留下 diff 噪音，还可能让 WT 弹配置错误。

## 机制（先读懂再动手）

**settings.json 自动发现**：`--settings` > `WTSSH_SETTINGS` > 自动探测（Store 稳定版 / Store 预览版 /
免安装版三处标准路径，首个命中即用）；全部落空 → 报错退出，stderr 列出探测过的路径。

- **一个分组 = 两处协同**：`newTabMenu` 里名字等于组名的 `folder` 的 `entries`（顺序 = 菜单顺序），
  加上 `profiles.list` 里 `ssh:` 前缀的 profile（`commandline` 就是 `ssh ...` 命令）。
  SSH 主机**默认且推荐**进名为 `ssh` 的组（省略 `--group` 即此）；不强硬——用户指定别的组用 `--group`。
- **`sftp:` 伴生 profile = FileZilla 菜单入口**：`edit X --sftp` 会在 profiles.list 里
  建一条 `sftp:X`（GUID 独立、生成时过 cmd 元字符红线），**默认且推荐钉进名为 `sftp` 的
  newTabMenu folder**（与 `ssh` 组并列的另一个下拉分组；`--sftp-group` / `$WTSSH_SFTP_GROUP`
  可改，不强硬——用户要跟 SSH 放一起时 `--sftp-group ssh`）。commandline 固定为
  `<shim> filezilla X --tunnel auto`——**身份在点击时才从主机簿解析**（host/port/key/跳板链后续改动零传播），
  `--tunnel auto` = 有跳板才隧道。伴生不是主机簿条目：所有 `ssh:` 枚举（`ungrouped`/`hidden`/doctor 逐条体检）
  都不收它；`list` 只在对应 ssh 行上标 `sftp: true` 和 `sftpGroup`。`remove`/`rename` 会传播到伴生
  （删掉/改名）。`move` 只重排当前 `--group` 里的 ssh 条目：伴生在独立 `sftp` 组时不跟着重排；
  仅当 `--sftp-group` 与 `--group` 相同且两者钉在同一 folder 时，才保持紧邻。hidden 条目也可以挂伴生：
  ssh 从所有 folder 消失，菜单里只在 `sftp` 组看到 `sftp:X`（"仅 SFTP 入口"形态，属预期）。
  CLI 仍支持 `add X ... --sftp` 一步创建，但 **agent 不得在用户只是加主机时顺手带上**——见下文
  「添加主机与 SFTP 伴生」。doctor 只在 settings.json 被手改出
  异常时报 `sftp-orphan`（ssh 条目没了；孤儿伴生用 `edit X --no-sftp` 移除，对手改死的名字网开一面）/
  `sftp-cmd-unsafe`（伴生名字带 cmd 元字符）/`sftp-bad-line`（commandline 非规范形）/
  `sftp-default`（伴生被手设为 default）。工具不提供把伴生设为 default/hidden 的路径。
- **条目名在整个 ssh 命名空间内唯一**（跨组同名会报 already exists）；组只决定条目挂在哪个菜单文件夹下。
- **跳板机默认不进主机簿**：`--hidden` 条目仍是 `ssh:` profile（`--jump` / 渲染链 / `connect` / `print` 都能解析到它），
  但 `hidden: true` 且**不写入任何 folder**——WT 下拉菜单的 ssh 分组里看不到它。Windows Terminal 对 folder 里的
  profile **即使 hidden 也会画出来**，所以不能只改 `hidden` 而留在 folder 里。
- 带前缀、未 hidden、但不在任何 folder 里的条目会落到 WT 的 "remaining profiles"，`list` 用 `"ungrouped": true` 标出。
  `hidden` 条目单独放在 `list` 的 `"hidden"` 数组，不当成菜单项。
- 写操作带互斥锁（`settings.json.wtssh.lock`，60s 过期）；WT 运行中修改是热重载的，无需重启。
- 序列化承诺：wtssh 渲染 WT 兼容风格（4 空格缩进、键排序、LF、无尾换行）；WT 也会自行重写该文件，
  因此这**不是**字节级互承诺——只是"不引入风格噪音"。

## 调用方式

```bash
python <本skill目录>/scripts/wtssh.py [--group <组名>] [--sftp-group <组名>] [--settings <路径>] <子命令>
```

Windows 上 `python` 不存在时依次试 `py -3`、`python3`。脚本要求 **Python ≥ 3.12**（f-string 嵌套同类
引号），低版本会在语法层直接 SyntaxError。所有输出是 JSON（人类可读的报错走 stderr，前缀
`wtssh: error:`）。`--group`/`--sftp-group`/`--settings`/`--secrets`/`--keys` 都是**子命令之前**的全局参数；
`--secrets`/`--keys` 指向 vault 目录，演练时可指向副本，等价环境变量为
`WTSSH_GROUP`/`WTSSH_SFTP_GROUP`/`WTSSH_SETTINGS`/`WTSSH_SECRETS`/`WTSSH_KEYS`。

## 语言 → 命令对照（核心表）

| 用户意图 | 命令 |
|---|---|
| 看看有哪些服务器/ssh 列表/主机 | `list`（不带 `--group` → `{"groups":{"<组>":[菜单项]},"ungrouped":[...],"hidden":[跳板身份]}`；带 `--group` → **仅该组菜单**平铺数组，不含 hidden；`--full` 附完整 profile） |
| 加一台 `alpha`，用户 u、地址 h、端口 p、密钥 k | `add alpha --user u --host h --port p --key k`（**不要**顺手带 `--sftp`；加完必须询问是否加伴生 SFTP，见「添加主机与 SFTP 伴生」） |
| 加的机器要走跳板/先登 `beta` | 先确保跳板条目存在（agent **MUST** 传 `--hidden`，CLI 省略则进菜单），再 `add alpha ... --jump beta`（默认 **preserve**：组内条目名**原样**存为 `-J beta`；链上每跳都是本簿条目时 connect 会**渲染**成逐跳身份链——见「打开会话」；要写死成 `user@host[:port]` 用 `--jump-mode expand`，展开后该跳不再携带身份，只能回退 `-J`） |
| **加跳板机（只给目标当跳，不出现在下拉菜单）** | `add jumper --user u1 --host h1 --key wtv:key1 --hidden`。用户没说「跳板也要能在菜单里打开」时 **MUST** 加 `--hidden`，禁止把跳板做成可见菜单项。 |
| **跳板机用 key1、目标机用 key2（两把都在 vault）** | `add jumper --user u1 --host h1 --key wtv:key1 --hidden` + `add target --user u2 --host h2 --key wtv:key2 --jump jumper`；连 `target` 时逐跳解封（**整条链 1 个 PIN 窗**：批量解封一次同意）、口令按跳精确派发。跳板仍在簿里，只是不在菜单。 |
| 跳板也要能在菜单里直接打开 | 新建时不加 `--hidden`，或事后 `edit jumper --visible`（从其它组摘走，写入**当前**组 folder + `hidden: false`） |
| 把已有跳板从菜单拿掉（保留给 `--jump` 用） | `edit jumper --hidden`（从所有 folder 清引用 + `hidden: true`）。**不要 `remove`**——那会拆掉目标机的渲染链。 |
| 加手动 ssh 选项（隧道、保活等） | `add alpha --host h --extra "-L 8080:127.0.0.1:80 -o ServerAliveInterval=30"` |
| 加完设为默认（新标签页直接是它） | `add ... --default`，或事后 `set-default alpha` |
| 改地址/端口/用户/密钥 | `edit alpha --host h2 --port 2222`（只传要改的；未传 `--extra` 时手动选项原样保留） |
| 改/清手动 ssh 选项 | `edit alpha --extra "-D 1080 -4"`；清空用 `--extra none` |
| 去掉跳板机 | `edit alpha --jump none` |
| 改标签页显示标题（不改连接名） | `edit alpha --title "标题"`；清掉用 `--title ""` |
| 从 ~/.ssh/config 批量导入 | `import`（或 `--ssh-config <路径>`）。工具本身不加伴生 SFTP；导入后必须询问这批要不要 `edit X --sftp`（默认进 `sftp` 组）；同意后再 edit，不要回头改成带 sftp 的重做。见「添加主机与 SFTP 伴生」 |
| 新建/切换到别的分组 | `--group prod add p1 --host 10.0.0.9`（folder 不存在则新建，追加在 newTabMenu 末尾） |
| 重命名 | `rename old new`（GUID 保留；其它条目 `-J 旧名` 一并改写并在 `rewroteJump` 列出；条目有口令时弹 1 次 PIN 重封；`wtv:` 密钥引用**不动**、无需 PIN） |
| 删掉这台 | `remove alpha`（清理所有 folder 引用；同名密钥文件**保留**并报 `keptKeys`；是默认 profile 时回落到本机真实 shell）。被其它条目 `--jump` 时**拒绝**（改用 `edit --hidden`）；确认拆链才 `--force`。 |
| 排到最前/最后/某台后面 | `move alpha --top` / `--bottom` / `--after beta` / `--before beta` |
| 现在默认是哪个 | `get-default` |
| 查某个条目的完整定义/GUID | `show alpha` / `guid alpha` |
| 看某条目实际会执行什么 ssh 命令 | `print alpha --cmd`（内嵌 ssh 命令行原文） |
| 看某条目的跳板链/身份结构（无秘密） | `print alpha`（默认 `--plan`：JSON，target/hops/keys 名单、渲染计划、`pinPrompts`、`secrets`，不含口令；`render.mode=legacy` 附回退原因，与 `doctor` 同源） |
| 体检条目（名字可作别名？密钥引用悬空？跳板链怎么解析？ssh 版本够不够？跳板是否还在菜单？） | `doctor`（全量）或 `doctor alpha`；JSON findings（`warn`/`info`），退出码恒 0。`jump-menu` = 被别人 `--jump` 但仍在菜单；`hidden-menu` = hidden 却还在 folder；`hidden-default` = hidden 且是 default；`sftp-orphan` = 伴生 SFTP 入口的 ssh 条目没了（`edit X --no-sftp` 可移除）；`sftp-cmd-unsafe` = 伴生名字带 cmd 元字符；`sftp-bad-line` = 伴生 commandline 不是规范形；`sftp-default` = 伴生被手设为 default |
| 给条目口令上 TPM vault 保护 | `secret set alpha`（隐藏输入，stdin 被管道接管时弹原生框；connect 时登录口令只自动填给本条目 user@host 的标准密码提示——kbdint 通道关闭，kbdint-only 服务器不自动登录，手输走 `open --no-askpass`；条目应带显式 `--user`，否则 doctor 报 `secret-user`） |
| 去掉口令保护（恢复直连） | `secret remove alpha` |
| 查哪些条目存了口令 | `secret list`（只列条目名；**没有 `get`**——口令从不以明文离开脚本，唯一释放路径是 connect 的弹窗链） |
| 导入私钥文件到 TPM vault（**独立密钥，无需主机条目**） | `key import KEYNAME <keyfile>`（加密源会弹原生框收口令，**口令全程不过 LLM/管道**；密钥+口令同封一个 AES-256-GCM blob；`--move` 封装后覆写删除源文件；若恰好存在同名条目，会把它的身份**改写**成这把密钥） |
| 查独立密钥及引用者 | `key list`（文件名+命令行推断，**不弹 PIN**；给 `referrers`） |
| 重命名独立密钥 | `key rename OLD NEW`（1 次 PIN 重封，所有引用条目自动重指向） |
| 移除独立密钥 | `key remove KEYNAME`（被任何条目引用则拒绝；`--force` 剥掉引用后删——剥引用改写被拒时按报错先 `rename`/修复该条目再重试） |
| 导出密钥到口令保护文件 | `key export KEYNAME <outfile>`（CNG PIN + 新口令二次确认；拒绝覆盖已有文件） |
| 一次 PIN、TTL 内免 PIN（ssh-agent 缓存） | `agent load [--ttl 8h] [KEY...]`（整批只弹 1 个 PIN 窗；`agent status` 查看、`agent unload [--all]` 清除；connect 到期前自动走缓存免 PIN，`--no-agent` 强制走 PIN 路） |
| 条目挂/换独立密钥 | `add/edit alpha ... --key wtv:KEYNAME`（也可 `--key <路径>` 用普通文件；`edit --key none` 解绑） |
| 初始化/管理 TPM vault | `vault init`（弹 2 窗：设 PIN + 自测）/ `vault status` / `vault remove`（演练 env 下**拒绝执行**，防误删真 TPM 键——见纪律 §8） |
| 连一下 X（connect 的别名） | `open alpha`（与 `connect` 同义；`--no-askpass` 显式退出口令派发，ssh 在终端里自己问口令） |
| 登录并跑命令取返回值（原生 ssh 风格） | `run alpha -- uptime -p`（`command` 拼在目的地之后，空命令=交互登录；也可裸写 `wtssh alpha uptime -p`，首 token 非子命令时自动补 `run`；stdout 只透传远端输出、wtssh 自身输出全走 stderr、退出码即 ssh 的；条目自带 tail 时加命令会拒绝，`--tunnel-forward` 不可与命令同用） |
| 用 FileZilla 打开主机簿里的 X | `filezilla alpha`（别名 `fz`；把条目同步进 FileZilla 站点管理器后 `filezilla -c` 直连，见「FileZilla 桥」） |
| 给 X 在 WT 菜单里放一个 SFTP 入口 | `edit X --sftp`（默认进 `sftp` 组，点击即开 FileZilla；带跳板自动走 `--tunnel` 隧道，见「FileZilla 桥」）。去掉用 `edit X --no-sftp`。用户要跟 SSH 放同一组时 `--sftp-group ssh edit X --sftp` |

约定：`NAME` 一律是去掉 `ssh:` 前缀的名字（用户说 "alpha" 就是 `alpha`，不是 `ssh:alpha`）。

### 参数解析规则

- **密钥路径**：脚本把 `~/` 展开为绝对路径；反斜杠路径建议先规范成正斜杠；含空格的路径无需处理
  （写命令行时加引号，交给 ssh 之前再拆掉引号——`ssh_argv` 会把 token 还原成裸值，否则 ssh 会去找一个
  字面带引号的文件名而静默跳过这把密钥）。
- **只给 `user@host`**：拆成 `--user` 和 `--host`。
- **跳板与 jumpMode**：`--jump` 接受字面 `user@host[:port]`（原样存储）或组内条目名（含 `--hidden` 的跳板身份条目）。**默认 `preserve`**：
  条目名**原样**写入 `-J`（与 import 的别名语义一致——ssh 在运行期按用户 config 的 `Host` 块解析它，
  所以 `edit` 不会再把别名悄悄展开丢掉）；`--jump-mode expand` 才在写入口把条目名解析成
  `user@host[:port]` 并递归串联其自身跳板。字段与值永不矛盾：对已有条目**单传**
  `--jump-mode expand`（不带 `--jump`）会把**存量跳板值**一并展开；`add` 只在带 `--jump` 时才落
  `expand` 字段。条目上的 `jumpMode` 字段只在偏离默认时落盘（`expand`）。
  清除跳板只在 `edit` 里用 `--jump none`；`add --jump none` 会报错。`doctor` 会报告跳板链的解析来源
  （组内条目/用户 config 别名/字面主机）。
- **分组落点（默认推荐，不强硬）**：
  1. SSH 主机默认且推荐进 `ssh` 组（省略 `--group`）。用户指定别的组名则 `--group <名>`。跳板机默认 `--hidden`，不进任何组。
  2. SFTP 伴生入口默认且推荐进 `sftp` 组（`edit X --sftp`；folder 由 `--sftp-group` / `$WTSSH_SFTP_GROUP` 决定，默认 `sftp`）。用户明确要求跟 SSH 放一起时才 `--sftp-group ssh`（或设成与 `--group` 相同）。
- **添加主机与 SFTP 伴生（MUST）**：
  1. 用户说「加一台主机 / 加 SSH / 导入」时：**禁止**在同一次 `add` 里带 `--sftp`，即使工具支持 `add --sftp`。先只加 SSH（`import` 本身不加伴生）。
  2. 加完后（或收尾确认时）**必须积极询问**：要不要给这台（或这批）在 WT 菜单里加一个伴生 SFTP 入口（默认进 `sftp` 组，点开即 FileZilla）。
  3. 用户同意 → 再 `edit X --sftp`（不要回头改成 `add --sftp` 重做）。用户一开始就明确要求「同时要 SFTP」→ 仍先 `add` 再 `edit --sftp`，可以不再问。
  4. 用户拒绝、或明确只要 SSH：不加伴生。
  5. 不要把「没提 SFTP」当成默认要加，也不要当成默认不加而不问——**问**是这条纪律的核心。
- **跳板机 vs 主机簿（MUST）**：用户要「经 X 连 Y / 加跳板」且**没有**主动说「跳板也要出现在菜单里 / 我也要直接连跳板」时：
  1. 跳板用 `add X ... --hidden`（已存在且还在菜单里 → `edit X --hidden`）；
  2. 目标用 `add Y ... --jump X`（Y 进菜单）；
  3. **禁止**为了菜单干净去 `remove X`——hidden 条目仍是渲染链的身份来源，删了 Y 会连不上或丢掉跳板钥。
  4. 用户明确要求跳板进菜单时才省略 `--hidden` 或 `edit X --visible`。
  `import` 仍默认进菜单（那是用户 ssh config 的 Host 别名）；导入后某条只当跳板、用户没要求留在菜单，再 `edit --hidden`。
  `--hidden` 不能兼 `--default`；对 hidden 条目 `move` / `set-default` 会拒绝（先 `--visible`）。
  若跳板目前是 default profile，必须先 `set-default` 到别的条目再 `--hidden`，否则 `edit --hidden` 会拒绝（hidden 的 default 仍会在新标签打开）。
  `doctor` 对「被别人 `--jump` 但仍在菜单」报 `jump-menu`；对 hidden 却仍在 folder 报 `hidden-menu`；对 hidden 且是 default 报 `hidden-default`。
  `rename` 会把其它条目 `-J 旧名` 一并改成新名（`rewroteJump`）。
- **端口**：只写数字；没说就保持默认（不传 `--port`，命令行里就不出现 `-p`）。
- **手动选项**：`--extra` 是单字符串，按 shell 分词后原样插在 `-p` 之后、目的地之前；
  `-L/-R/-D/-o/-W/-4/-t` 等 wtssh 不建模的选项靠它保命。第一个**不以 `-` 开头**的 token 起（远程命令等）
  会落在目的地**之后**（`list` 行里显示为 `tail`），不会被提升成主机；`edit` 不传 `--extra` 时两者都原样保留。
  该字符串按 **ssh config 同款引号规则**分词（双引号包裹可含空格；**反斜杠是字面字符、不是转义符**），
  Windows 反斜杠路径可以直写：`--extra "-o ProxyCommand=C:\Tools\p.exe"` 原样保留。
- **名称冲突**：`add`/`rename` 撞名会报错退出；把现状 `list` 给用户看再问怎么处理。
- **名字字符集（安全红线）**：条目名/密钥名不得含 cmd 元字符 `& | < > ^ % !` 或控制字符——routed
  标签页经 cmd.exe 启动，这些字符会分裂/重定向/展开命令行（已实证的注入路径，`%` 连引号都挡不住）。
  `add`/`rename <新名>`/`key import` 直接拒绝；`import` 静默跳过这类别名；存量 routed 条目由
  `list` 告警（stderr），用 `rename '<旧名>' <安全名>` 迁移（旧名位置的校验是宽松的，这就是逃生通道）。
- **routed 行的载荷红线**：routed 行 `--` 之后嵌入的 ssh 命令（host/user/选项/远程命令）同样经
  cmd.exe，同样不得携带 `& | < > ^ % !` 与控制字符（`%` 连引号都挡不住；`!` 可经注册表延迟展开
  把环境变量值拼进参数，一并拒绝）。所有写路径整体拒绝（报错给清理指引）；`import` 跳过并给原因、
  不中止整批；`secret set`/`key import` 在任何 blob 落盘**之前**拒绝；存量毒名/毒载荷由 `list` 告警。
  普通明文行不经 cmd.exe，`&` 字面传给 ssh，不受此限。
- 用户只说"加台机器 x.x.x.x"没给名字 → 用 host 第一段做名字并向用户复述确认。

### 打开会话（用户说"连一下 X / 开个 X"）

```powershell
wt -p "ssh:alpha"      # 新窗口
wt nt -p "ssh:alpha"   # 当前窗口新标签
```

无 vault 绑定的条目直连（`ssh -i <路径> ...`）；有 vault 密钥/口令的条目打开时弹 **1 个 CNG PIN 窗**
（这一次交互既是同意也是释放；窗上的 Use Context 会写明用途，例如「连接主机 alpha（user@host），使用密钥 k」），然后启动 ssh。
引用 vault 密钥的条目 connect 时会在选项区**最前**追加 `-o PasswordAuthentication=no -o
ChallengeResponseAuthentication=no`（命令行 `-o` 先出现者胜，用户自己的 `-o` 无法翻案）：
派发出去的是**密钥会话口令**，绝不能被 ssh 喂给登录密码/keyboard-interactive 提示，否则恶意
服务端能把它当登录凭据收走。副作用：这类条目只走公钥认证，公钥被拒就干净地失败。
connect/doctor 会在条目用到 vault 密钥/口令时探测 `ssh -V`：**OpenSSH < 8.4** 不认识
`SSH_ASKPASS_REQUIRE`，口令会退化为**终端明示提示**输入（stderr 有警告）——"标签页里不出现口令提示"
的承诺只在 ≥ 8.4 的 ssh 上成立。

**跳板链渲染 + 逐跳口令派发**：一条链（含每跳自身的 `--jump` 递归展平）上**每一跳都是本簿条目**时，
connect 不走 `-J`，而是现场渲染临时 `-F` 配置（owner-only 目录，不透明块名，真实主机名只在块的
`HostName`）：每跳身份来自**它自己的条目**（块内 `IdentitiesOnly yes`），目标条目的 `-i/-J` 移入配置块、
其余选项原样保留在 argv。口令派发纪律（**红线**）：整个 ssh 进程树只有**一个** askpass dispatcher——
只应答本次注册的**密钥**口令提示（精确匹配、一次性发放），**绝不把 A 跳的口令喂给 B 跳**；口令只经
owner-only 映射文件传递，**不进环境变量、不进 argv**。**整条链只弹 1 个 PIN 窗**（`unwrap-many` 批量
解封，Use Context 列明解封哪些密钥）。
**host-key 确认**：派发激活后所有提示都路由给 askpass，所以**未知的 host key 必须在派发激活前交互
确认**——已知块零开销跳过；未知块中的首块（本机直拨入口，无跳板时即目标本身）先直连探测（无需任何口令，指纹与 yes/no 在终端完整可见），跳板后的下游块跳过直连（本机拨号视角不对，注定超时）、直落隧道；
仍未知的经渲染链辅助探测（每处未知 host key 弹**原生 Yes/No 对话框**；工具只询问、绝不自动接受）。拒绝或未
确认即在该阶段清晰失败并点名主机（附手动指引）。脚本场景设 `WTSSH_NO_HOSTKEY_PROBE=1` 跳过。
**回退与硬拒绝**：链上有非本簿跳板（字面/用户 config 别名——身份在用户 config 里，渲染会丢）、跳板带
`--extra`/远程命令或自带 `-F`、跳板链成环、跳板持有 stored secret 而本条目不带 vault 密钥 → 回退常规
`-J`（stderr 说明原因，`print --plan` 的 `render.reason` 同源）。**硬拒绝（exit 4，不是回退）**：本连接
将激活口令派发而某跳持有 stored secret——那种跳在两条路径上都永远连不上；先 `key import` 该跳凭据、
加 `--no-askpass` 回退全交互、或改免密公钥。目标条目存 secret（无 vault 密钥）时回退旧路：登录口令走
**身份门**（只自动填给本条目 user@host 的标准密码提示，跳板的提示一律得空串），kbdint 整体关闭。
`--no-askpass` 显式退出口令派发（口令提示回终端）。直连条目引用多把 vault 密钥同样走渲染 + dispatcher
（整链仍只 1 次 PIN）。离线检查渲染结果：`WTSSH_RENDER_DRY=1 wtssh connect alpha` 打印 JSON，不碰
vault、不启动 ssh。渲染链中**未入库的加密明文密钥**无法被应答（stderr 有告警，先 `key import`）。

**跑命令模式（`run`，给脚本用的登录口）**：与 `connect` 同一条链路（渲染/agent/legacy、PIN、派发、
预检全一样），只多两件事——`command` 拼在目的地之后当远端命令（`rebuild_target_argv` 与 legacy
都是"目的地之后原样保留"，远程命令自己的 `-x` 形 flag 不会被提前）；stdout 纯度承诺：run 路径
wtssh 自身 print **零 stdout**（dry-run JSON 也改走 stderr，`__askpass` 的 stdout 是给 ssh 管道读的，
不算；例外是 host-key 预检探针子进程——它们继承 stdio，常态输出为空，管道场景下介意就先确认 key 已知）。
`run NAME` 空命令 = 交互登录（同 `connect`）。裸写 `wtssh NAME ...`
等价（main 里预扫描：跳过全局参数后首 token 非子命令名、非 `-` 开头即补 `run`；子命令名恒优先，
真有条目叫 `list` 这种名字时用 `run list ...` 指名；前导 `-` 的名字建不出来也不支持裸写，
存量手改名撞上时用 `run -- <name>` 再不行就先 `rename`）。run 的 wtssh 选项（`--no-askpass` 等）
**必须写在 NAME 之前**，NAME 之后全部是远端命令（含 `-x` 形）；条目 `extra` 里自带的 `-t` 等
与 run 混用时遵循 ssh 本身语义。两条硬拒绝：条目自带 tail 又追加命令、
`--tunnel-forward`（`-N` 无远端 shell）又带命令——都是"拼出来 ssh 会静默误解"的形态，响亮失败。
管道喂 stdin 前先确认 host key 已知（未知 key 的交互确认会占用 stdin；脚本场景可用
`WTSSH_NO_HOSTKEY_PROBE=1` 并接受失败语义）。

**ssh-agent 缓存（一次 PIN，TTL 内免 PIN）**：`agent load` 把 vault 密钥（默认全部，可点名）一次解封
（仍只 1 个 PIN 窗）后塞进系统 ssh-agent，默认有效 8h（`--ttl 8h/90m/3600`，或 `$WTSSH_AGENT_TTL`）。
此后 connect 若所需密钥**全部**在 agent 里（指纹实时核验）→ 走 agent 分支：pub 选择器 +
`IdentitiesOnly yes`，无容器、无派发、**零 PIN**（stderr 会注一行）；缺任何一把 → 静默回落 PIN 路。
`--no-agent` / `$WTSSH_NO_AGENT=1` 强制走 PIN 路。`print --plan` 的 `agentCached` 只说明哪些钥有缓存
记录（离线提示），不承诺免 PIN。FileZilla 流（PPK 会话密钥）与 stored-secret（登录口令）不受益，
照旧走 PIN。TTL 到期后 wtssh 不再使用并尝试摘除，但密钥字节仍留在 agent 内存直到服务重启——硬清除用
`agent unload`（默认摘 wtssh 跟踪的钥——活着的 + 已过期的，不动用户手加的；`--all` = `ssh-add -D` 会连用户自己的
一起清）。agent 服务没起时 `agent status` 会给 `Start-Service ssh-agent` 指引。

### FileZilla 桥（`filezilla NAME`，别名 `fz`）

`filezilla.exe -c <site-path>` 可命令行直连 Site Manager 里的一个站点（site-path = 字面根 `0` + `/`
分隔的 Folder/Server 名，精确大小写匹配）；`sftp://` URL 带不了密钥且密码会进 argv，**不用**。「先同步
站点、再 `-c` 启动」是安全的——每次启动都是新进程、连接前现读站点簿。

`wtssh filezilla alpha [--tunnel [yes|auto]] [--keyfile <路径>] [--no-open] [--remove-site] [--to-clipboard] [--filezilla <exe路径>]`：

- 在 `%APPDATA%\FileZilla\sitemanager.xml` 里维护一个以**当前 `--group`**（默认 `ssh`）命名的 `<Folder>`（如 `0/ssh/alpha`），
  **不碰**用户自建的根级站点。这与 WT 菜单里 `sftp:` 伴生默认进 `sftp` 组不是同一棵树——点 `sftp:X` 仍按条目身份同步到当前 `--group` 对应的 FileZilla 文件夹。写前自动备份 `sitemanager.xml.wtssh.bak`（滚动单份），原子替换、写前解析校验；
  损坏文件**不修**，报错并指向备份。只读 settings.json，不写它。
- **主机簿是身份事实源**：Host/Port/User 每次同步。认证语义：
  - 条目 `--key` 是明文路径 → 同步为 Keyfile + Logontype 5（密钥型）；
  - 条目 `--key` 是 `wtv:` vault 引用：
    - **真正启动 FileZilla 时**（无 `--no-open`）→ 弹 1 次 CNG PIN，导出临时加密 PPK v2 会话密钥并绑到站点（有跳板走隧道路径；无跳板走直连路径，站点仍写真实 `host:port`，不写通用代理）；FileZilla 退出后覆写清扫；
    - **只同步不启动**（`--no-open`）或站点已有 Keyfile → 保留已有 Keyfile，否则降级为 Logontype 2（连接时 FileZilla 自己弹密码框）并在 warnings 里说明；**绝不**把口令/密钥内容写进站点簿；
  - 无 key 条目 → ask 型（FileZilla 连接时弹密码框；stored secret 从不出脚本）。
  - 密码登录要粘贴免输 → `--to-clipboard`（显式二次确认才复制）：先弹原生 `Yes/No` 确认框（标题为确认语、写明条目身份与剪贴板风险），确认后再弹 1 次 `CNG PIN` 解封登录口令并复制到剪贴板，口令永不打印到终端/`JSON`/日志（`JSON` 只给 `passwordClipboard:true/false`）。直连专用（有跳板解析成隧道即拒绝）、需已有 `stored secret`、条目不得绑定任何密钥（含明文 `--key` 路径：其站点是密钥型、无处可粘）、与 `--no-open/--remove-site/--keyfile/--tunnel` 互斥；`wtv:` 密钥条目无登录口令可复制（它的会话口令 phrase 本就自动进剪贴板）。`PIN` 在站点同步之后（口令在内存中存活最短），取消 `PIN` 会留下已同步未启动的 `ask` 站点——无秘密、幂等，属预期。剪贴板不是秘密通道（同用户进程可读、`Win+V` 历史/云同步/`RDP` 会带走、不自动清空；非 `ASCII` 口令经 `owner-only` 会话目录中转、用后覆写清扫，强杀残留由会话清扫器回收）：粘贴后尽快覆盖清除，不要勾 `FileZilla` 的“记住密码”；复制失败不打印口令，仍启动供手输。
- **跳板链不可表达**：FileZilla SFTP 没有 jump host 概念，普通同步里条目的 `--jump` 被忽略并告警
  （直连语义）。**要真跳板链 → 用 `--tunnel`**（SOCKS 代理 + 真实地址，见下）。主机簿菜单里的
  `sftp:` 伴生入口固定带 `--tunnel auto`：有跳板才隧道，无跳板即普通直连——点菜单入口的人不需要知道区别。
- `--remove-site` 只删组文件夹下同名站点（组文件夹删空则一并移除）；`--no-open` 只同步不启动
  （不需要 filezilla.exe 也能做同步/删除）。`--filezilla` 给了但路径不存在直接报错，不静默回退。
- **rename / remove / 换 `--group` 不传播到 FileZilla**：站点簿里会留下旧名字/旧组的历史快照（仍可连）。
  同步时会把这些"不再匹配任何主机簿条目"的孤儿站点**点名告警**（不代删），用
  `wtssh filezilla 旧名 --remove-site` 清理。若同名组文件夹里已有**不在主机簿里**的站点，首次向其中
  插入新站点时会告警（`--remove-site` 按名删，注意区分）。
- filezilla.exe 探测：`--filezilla`（路径不存在直接报错）> `$WTSSH_FILEZILLA` > Program Files (x64/x86)
  标准安装目录 > PATH；探测只在**真正要启动**时进行，`--no-open`/`--remove-site` 在没装 FileZilla 的
  机器上也能完成同步/清理。
- 演练钩子 `WTSSH_FZ_SITEMANAGER` / `WTSSH_FZ_FILEZILLAXML` 分别指向站点簿与 filezilla.xml 副本
  （设置时 stderr 有提醒）；测试**必须**用它们，别直接写活站点簿或活设置。`--tunnel` 的密钥解封（PIN）
  与隧道（真实连接）是**真动作**，演练时同样注意。

#### `--tunnel`（真跳板链 → FileZilla：SOCKS 代理 + 真实地址）

`wtssh filezilla NAME --tunnel`（≡ `--tunnel yes`；与 `--keyfile`/`--remove-site`/`--no-open` 互斥）一步完成：

1. **SOCKS 隧道**：链可渲染时父进程直接跑隧道 ssh（`-N -D 127.0.0.1:私有端口`——bind 地址钉死 loopback，
   条目级 `GatewayPorts` 改不动；目的地是渲染链**末跳**，与 `-J`
   链的 stdio 转发同一拨号视角；条目自带 `-p` 从隧道 argv 剥除、由渲染块携带），并在其前置**带认证的
   SOCKS5 门卫**：FileZilla 拨公开端口（凭据见第 4 点），无凭据的本机进程一律拒绝——Windows 的
   loopback 监听没有按用户的 ACL，匿名 `-D` 等于向同机其他账户开放整条跳板链；链不可渲染时回退子进程
   跑 `connect NAME --tunnel-forward …`（legacy `-L`：裸 TCP 无认证钩子，该路径**不做**此加固，站点重写
   `127.0.0.1:<端口>`，不碰通用代理）。渲染链/host-key 预检/口令派发与 connect 共用同一套 helper。
2. **会话密钥（条目带 `wtv:` 密钥时）**：导出密钥与链上每把密钥在**一个** CNG PIN 窗批量解封（Use
   Context 写明「建立隧道并导出会话密钥」）→ 以**随机 passphrase** 重加密为**加密 PPK v2**（FileZilla 的
   SFTP 引擎原生只加载 PuTTY PPK，OpenSSH/PEM 容器每次连接都弹转换框）写进 owner-only 会话目录，隧道
   断即覆写清扫；纯明文/无密钥链路完全不碰 vault、零 PIN。
3. **站点保留真实地址**：Host/Port 写条目本来的 `host:port`（经 SOCKS 让**末跳**去拨，正是 `-J` 的拨号
   语义），`BypassProxy` 钉 0（fallback 模式钉 1——站点拨的是本地监听口）。站点 Keyfile 换成本次会话
   密钥文件；隧道结束后文件被清扫，之后的普通同步识别残留会清理降级为 ask 型并告警——用 `--keyfile`
   重绑明文密钥恢复长期直连。
4. **FileZilla 通用代理指向本会话 SOCKS 门卫**：写 `filezilla.xml` 五键（SOCKS5 + **本会话随机
   user/password**，凭据只存在于父进程内存与该文件本身，JSON/日志/审计一律不落）（写前捕获原值、我拉起
   的实例退出后精确写回含"原本不存在则删除"，写前备份）；此前已在运行的别的 FileZilla 实例不受影响，
   但其退出保存以后存者为准（已知边界）。**通用代理是全局单份**设置：不要并发跑两个
   `--tunnel` 会话（后写者胜）。
5. **口令投递（红线）**：真终端（TTY）→ stderr + JSON + 剪贴板三处可得；**管道输出（agent/日志捕获）→
   只复制进剪贴板，口令本身不出现**（凭据不进 transcript/日志；唯一例外是管道 + 剪贴板失败这一无渠道
   形态——回退明文展示并标注失败）。每次会话口令全新，FileZilla 的"记住"对下次无效；本地端口就绪后才
   启动 FileZilla（监听建立前隧道死亡由轮询 fail-fast）。
6. **生命周期绑定**：wtssh 等**自己拉起的 FileZilla 实例**退出，然后停代理进程、恢复通用代理、覆写清扫
   会话密钥与渲染配置——"关掉 FileZilla 即收尾"。隧道先死 → 主动关掉该 FileZilla 并以隧道退出码收尾；
   终端 Ctrl-C → 隧道与该窗口一并关闭、恢复代理；任何异常路径的兜底都先关窗、再恢复代理。

**`--tunnel auto`（`sftp:` 伴生菜单入口的固定形态）**：点击时看条目——有 `--jump` 才走上述隧道流程；
无跳板则直连。无跳板但条目带 `wtv:` 时，仍弹 1 次 PIN 导出会话密钥（`sessionKey.mode=direct-vault`），不写通用代理、不建 SOCKS；无 vault 密钥的无跳板条目才是零 PIN 的普通同步。因此模式互斥（`--keyfile`/`--remove-site`/
`--no-open`）只在**真正隧道化**的条目上生效：`--tunnel auto --no-open` 对无跳板条目是合法的"只同步不启动"（vault 条目此时仍降级 ask，不导出临时密钥）。
跳板链渲染条件不满足时与 `--tunnel yes` 同一套回退；JSON 结果附 `tunnelAuto: "tunnel"|"direct"` 说明本次解析。

`--tunnel` 的隧道本体是 connect 的公开能力：`wtssh connect NAME --tunnel-forward
LOCAL_PORT:REMOTE_HOST:REMOTE_PORT`（纯转发模式：`-N -L`，`-L` 远端从目标机命名空间解析；渲染链/派发
/预检照常生效）。单用它即可给任何支持本地端口的工具当跳板隧道。

### import（从 OpenSSH client config 导入）

`import` 读 `~/.ssh/config`（或 `--ssh-config <路径>`），一个 `Host` 别名生成一个条目：

- 结构化关键字映射为字段：`HostName→host`、`User→user`、`Port→port`、`ProxyJump→jump`、
  `IdentityFile→key`（多个 `IdentityFile` 时第一个进 `-i`，其余以 `-o IdentityFile=...` 进 `--extra`）。
- **行内 `#` 注释按 ssh 语义剥离**：未加引号且**位于 token 起始**的 `#`
  起注释到行尾——`HostName ex.com # note` 只存 `ex.com`，`Host t3 # c` 只建 `t3` 一个条目；
  token 中间或引号内的 `#` 是字面字符（`ex#ample.com` 原样保留）；`ProxyJump` 的值在**任意** `#` 处截断
  （ssh 的 jump 解析器如此，`lit#x.com` 实际连 `lit`）；`ProxyCommand`/`RemoteCommand`/`LocalCommand`
  的值是"整行剩余部分"，**永不**剥注释。
- **其余所有关键字**（`ServerAliveInterval`、`ForwardAgent`、`ProxyCommand`…）原样变成 `-o Key=Value`
  token 存进 `--extra`，由 ssh 自己解释，语义无损。
- `Include` 递归展开（相对路径按包含它的文件所在目录解析，glob 展开，缺文件跳过）。
- 跳过：通配别名（含 `*`/`?`/`!`）、含 cmd 元字符（`&`/`|`/`<`/`>`/`^`/`%`/`!`）的别名、`Host *` 块、
  `Match` 块、以及所有 Host 块之外的全局默认——这些规则在条目真正连接时仍会被 ssh 从原 config 读到，
  不必复制进条目。
- 名字已存在的条目跳过（`skipped` 里给出原因），不覆盖。
- 单条构建失败（值里嵌引号等导致命令行无法回读）只跳过该条，`skipped` 里的 `reason` 就是脚本的
  具体报错（不再是一句笼统的静态文案）。
- 含空格的路径在 `IdentityFile` 里**必须加引号**（不加引号会按空白切分成多段，这与 ssh 行为一致）；
  同一 `Host` 块内重复关键字按 ssh 规则取**首个**值（`IdentityFile`/`LocalForward`/`SetEnv` 等累积型除外）。
- 输出：`{"imported":[...],"skipped":[{"name":...,"reason":...}]}`。

## 无 vault 模式（默认形态）

vault 是**可选附加层**。没有 TPM / 没做过 `vault init` 的机器上：

- `add --key <路径>` + `import` + `list`/`edit`/`move`/`rename`/`remove` 全部照常工作；
- 条目就是明文 `ssh -i <密钥路径> user@host`，密钥文件由用户自己保管（仓库外目录）；
- 只有 `secret set` / `key import` / `key export` / `vault *` 需要 TPM，缺了会明确报错。

把密钥收进 vault 的路径：`key import KEYNAME <文件>`（建议 `--move`），源文件即被安全清除；
**这一步不需要任何主机条目**。之后用 `add/edit --key wtv:KEYNAME` 把条目挂上来；一把密钥可以
挂多个条目。此后 connect 走 PIN→ssh 链路（1 个 CNG PIN 窗）。

## 独立密钥模型（standalone key）

密钥与主机条目**解耦**：

- vault 里每把密钥是独立对象 `keys/<KEYNAME>.wtv`（载荷 `fmt 4`，`name = KEYNAME` 自绑定）；
- 条目通过 commandline 里的 `-i wtv:KEYNAME` **引用**密钥（commandline 仍是唯一事实源）——这是**唯一**的引用
  写法，工具不认识"字面 `.wtv` 路径"那种写法（不存在需要兼容的旧形态）；
- **互斥不变式**：一个条目不能同时有 `wtv:` 引用和 stored secret（`add`/`edit`/`secret set`
  三处都设防）——密钥的口令在它自己的 blob 里，connect 只派发一套口令；
- **悬空引用**（`wtv:` 指向不存在的密钥）不对称：`add` **拒绝新建**（新建即报错，避免"写入却连不上"），
  `edit` **容忍存量**（否则一个手改坏的条目就再也改不动了）；`connect` 遇到它响亮报错，不会静默误连；
- `key import KEYNAME` 对**同名条目**是"**改写**其 `-i`"（替换，不是追加）——不会留下第二个身份，
  也不会让 connect 回落到旧的明文密钥；
- 条目 `rename`/`remove` **不再触碰**密钥 blob（remove 时同名密钥文件保留并报告 `keptKeys`）；
- `key rename OLD NEW` 是重命名密钥的唯一合法路径（1 次 PIN 重封 + 引用者重指向）；
  手工复制/改名 `.wtv` 会被 "blob swap refused" 拒绝（exit 4）；
- **载荷只有 `fmt 4` 一种**：没有旧格式可读，带 `fmt` 缺失/其它值的 blob 一律报"不支持的
  格式"并要求重存；
- **`list` 行的 `vaultKey`** 表示"**这条 commandline 引用了 vault 密钥**"（不看"是否存在同名 blob"），
  并额外给 `vaultKeys`（引用了哪些）与 `vaultKeysMissing`（引用了但文件不存在）。条目改名/改引用后，
  旧密钥可能变成 `key list` 里 `referrers: []` 的**孤儿**——这是合法状态，用 `key remove KEYNAME` 清理。

## 保密架构（TPM vault）

实现要点（密码学细节与进程模型见 scripts/cng-vault.ps1）：

1. **vault init（一次性）**：TPM 上建 RSA 解密专用键（UI Policy = PROTECT|FORCE_HIGH），弹 2 窗：设 PIN +
   consent 自测；已存在 vault 键时拒绝（脚本与 cng-vault.ps1 双护栏）。
2. **封装**：随机 DEK 以 AES-256-GCM 封载荷，DEK 由 vault 公钥包裹；blob 的**类型常量**（`wtssh:key` /
   `wtssh:secret`）与**属主名字**双重绑定——把 blob 复制/改名到别处会在解密后被显式拒绝（exit 4，
   "blob swap refused"）。合法改名只有 `key rename`（密钥，PIN 重封）与条目 `rename`（只重封其口令 blob）。
3. **connect（每次）**：commandline 改写为 `<shim> connect <name> -- <原 ssh 命令>`；打开标签 → **1 个
   CNG PIN 窗**（同意即释放；Use Context 注明用途，stderr 同步打一行防盲输；WT 每标签一个进程，故每标签
   1 窗）→ 容器写入 `%TEMP%\wtssh-key-*`（owner-only DACL）→ ssh 以容器为 `-i`，口令经 owner-only 映射
   文件喂 askpass dispatcher（**不进环境变量、不进 argv**），私钥只在 ssh 进程内解密、不落盘，会话结束
   覆写删除。强杀/关标签时 finally 不执行——目录带 owner.pid 标记，由下一次写操作或 connect 的清扫回收
   （活跃会话永不触碰）。
4. **key export**：PIN（用途写明）→ 原生弹窗收新口令（二次确认）→ 进程内重加密 → 原子落位；拒绝覆盖、
   拒绝空口令。`key rename` / 带口令条目的 `rename` 同样在 PIN 窗写明在重命名什么。

**安全边界（向用户如实说明，勿夸大）**：

- **TPM PIN（真保密层）**：RSA 私钥驻留 TPM 不可导出；离线偷走 `secrets/`+`keys/` 无法解密；同用户进程
  静默解密恒被拒。但 FORCE_HIGH 不是安全桌面：同用户恶意进程可以直接调 cng-vault.ps1 弹真窗，
  人输 PIN 就交出 DEK——防的是"静默/离线"，不防"骗人输 PIN"。且 PIN 窗内的 Use Context 文案由调用方
  进程**任意提供**——同用户恶意进程可以带任何诱导文案弹**真**窗，所以**窗内用途文字不可作为信任依据**；
  信任锚只有"这个窗是不是你自己刚发起的操作触发的"。
- **运行时窗口**：connect 全程无私钥明文落盘、无子进程 argv / 环境变量暴露；但会话口令在 connect 进程与
  ssh 子进程的内存、以及 owner-only 口令映射文件里存在整场会话（映射文件结束即覆写删除）；
  vault 侧与 `key export` 的重加密输出统一为 OpenSSH 格式（PEM 源导出后格式会变，ssh 均可读），
  唯 `filezilla --tunnel` 的会话密钥导出为加密 PPK v2（FileZilla 原生格式，见 FileZilla 桥一节）。
- **agent 缓存窗口（TTL 内免 PIN 的代价）**：`agent load` 后解密后的私钥在 ssh-agent 内存里活整个 TTL，
  且 agent 管道（`\\.\pipe\openssh-ssh-agent`）对 Authenticated Users 可连——**比 vault 的 owner-only
  DACL 弱**：同机其他登录用户能拿缓存钥做认证（能用不能导出，经典 ssh-agent tradeoff）。另两点实测事实：
  Windows 服务 agent 拒绝 `ssh-add -t/-c`（约束型添加一律 "agent refused operation"），所以 TTL 是
  wtssh 侧强制（到期回落 PIN + 尝试摘除），不是服务端过期——到期残留靠 `agent unload`/服务重启清；
  Windows ssh-add 从不走 SSH_ASKPASS，所以 load 瞬间会在 owner-only 临时文件里放一份无口令私钥
  （加完即覆写删除）。agent 分支**永不**开 `ForwardAgent`（跳板链走 ProxyCommand，agent 不出本机）。
- **未导入的条目不受任何保护**：`add --key <路径>` 只是路径引用（现网明文密钥仍在）；`key import` 默认是
  copy，`--move` 才删除源文件。
- **非 vault blob 一律拒绝读取**（DPAPI 文件、别的 envelope、`fmt` 不是 4 的载荷），
  报错会给出重存命令（`key remove KEYNAME` + `key import KEYNAME <file>`，或 `secret set NAME`）；不自动迁移。
  没有"旧格式例外"：只有 `fmt 4` 一种载荷，其它一律是损坏或外来文件。

## 环境适配

| 变量 | 作用 |
|---|---|
| `WTSSH_SETTINGS` | 指定 settings.json（`--settings` 优先级更高） |
| `WTSSH_GROUP` | ssh: 条目的默认分组名（`--group` 优先级更高），默认 `ssh` |
| `WTSSH_SFTP_GROUP` | sftp: 伴生的默认分组名（`--sftp-group` 优先级更高），默认 `sftp` |
| `WTSSH_UI_LANG` | 原生日志框语言：`zh`（默认）/ `en` |
| `WTSSH_SECRETS` / `WTSSH_KEYS` / `WTSSH_SHIM_DIR` | vault 目录与 shim 目录（默认 `%LOCALAPPDATA%\wtssh\{secrets,keys}`、`%LOCALAPPDATA%\wtssh`）；演练/测试钩子。这俩 env 粘在 shell 会话里容易被忘掉：`list`/`key list`/`secret list`/`vault status` 在它们被设置时会打一行 stderr 提醒"当前报告描述的是演练沙箱，不是真实 vault" |
| `WTSSH_RUN_DIR` / `WTSSH_AUDIT_DIR` | 渲染链的 run 目录（`-F` 配置 + 口令映射，默认 `%LOCALAPPDATA%\wtssh\run`）与审计日志目录（默认 `%LOCALAPPDATA%\wtssh\log`）；演练钩子 |
| `WTSSH_AGENT_DIR` | agent 缓存目录（pub 选择器 + keys.json 索引，公开材料；默认 `%LOCALAPPDATA%\wtssh\agent`；`--agent-dir` 优先级更高）；演练钩子 |
| `WTSSH_RENDER_DRY` | 设为 `1` 时 `connect` 只物化渲染计划并打印 JSON（块/argv/配置原文），不碰 vault、不启动 ssh |
| `WTSSH_AGENT_TTL` | `agent load` 默认有效期（`--ttl` 优先级更高），默认 `8h` |
| `WTSSH_NO_AGENT` | 设为 `1` 时 connect 无视 agent 缓存（与 `--no-agent` 同效） |
| `WTSSH_NO_HOSTKEY_PROBE` | 设为 `1` 时跳过派发前的交互式 host-key 预检（脚本场景；未知的 host key 届时仍会在连接时失败） |
| `WTSSH_ALLOW_LOOSE_ACL` | 机密文件的 owner-only DACL 落不了地时（FAT/网络盘等无 ACL 卷），默认**拒绝运行**（fail-closed，密钥/口令映射不落盘）；设为 `1` 才降级为 chmod + 一次性警告继续 |
| `WTSSH_AUDIT` | 设为 `verbose` 时审计日志记录派发命中/渲染摘要；默认只记未命中与失败 |
| `WTSSH_FILEZILLA` | filezilla.exe 路径（`--filezilla` 优先级更高）；默认探测标准安装目录与 PATH |
| `WTSSH_FZ_SITEMANAGER` | 指向 sitemanager.xml 副本的演练钩子；设置时 `filezilla` 动作打一行 stderr 提醒"当前描述的是副本，不是真实站点簿" |
| `WTSSH_FZ_FILEZILLAXML` | 指向 filezilla.xml 副本的演练钩子；设置时 `filezilla --tunnel` 打一行 stderr 提醒"通用代理写入描述的是副本，不是真实设置" |

- **启动器 shim**：routed 条目与 `sftp:` 伴生条目的 `commandline` 指向 `%LOCALAPPDATA%\wtssh\wtssh.cmd`
  （内容 = 解释器 + `wtssh.py` 绝对路径），由相关写操作保证存在、内容漂移即重写。**shim 路径不变**时，
  Python 被移动/重装后重跑任一这类写操作即可恢复**全部** routed 条目（它们指向 shim 文件本身，不用逐条改）；
  `WTSSH_SHIM_DIR` 变了则只有本次写操作触及的条目跟上。

## 安全与纪律（MUST）

1. **只碰自己管理的组**：脚本改名字等于 `--group` 的 folder 与 `ssh:` profile，以及 `--sftp` 时名字等于
   `--sftp-group` 的 folder 与 `sftp:` 伴生；`defaultProfile` 仅在
   `set-default`/`--default`/删除默认条目时按上表处理。其他 folder 只在删除条目或 `edit --hidden` 时清引用。
2. **删除前确认**：`remove` 不可逆（`.wtssh.bak` 只是滚雪球式单份备份）——先 `show` 给用户复述再执行，
   除非用户明确说"删掉 X"。跳板机只是不想出现在菜单里时用 `edit X --hidden`，**不要删**。
3. **密钥不落库**：密钥路径写进 settings.json 没问题（本就是本机私有文件），但**永远不要**把密钥内容、
   口令或 `commandline` 之外的敏感字段写进任何外部文件/git。
4. **报错即停**：脚本以 `wtssh: error:` 前缀退出非 0——不要绕过脚本直接改 JSON"救急"。
5. **验证习惯**：改动后跑一次 `list` 确认 JSON 合法；让用户看 WT 下拉菜单是否立即出现（热重载）。
6. settings.json 是 WT 的活文件：用户提到 WT 弹配置错误弹窗时，先 `list`/`show` 自检，再从
   `settings.json.wtssh.bak` 恢复并报告。
7. **本机现状不入档**：条目、默认 profile、GUID、分组一律以 `list`/`get-default` 的实时输出为准，
   本文件不记录任何具体主机。本 skill 只管 Windows Terminal 入口，不改其它工具（如路由器）管辖的配置。
8. **测试/演练不写活配置**：任何写子命令（`add`/`edit`/`remove`/`rename`/`move`/`set-default`/`import`/
   `key *`/`secret *`/`agent load`/`agent unload`）在做验证时**必须**用 `--settings <副本>`（或 `WTSSH_SETTINGS`），并用
   `--secrets`/`--keys`/`--agent-dir` 指向临时目录。活文件里只有 `.wtssh.bak` 是**滚动单份**备份，vault blob
   **没有备份**：写第二次就回不到测试前，删掉的 blob 更无从还原。验证收尾还必须**核对活目录已摘干净**
   （条目 / blob 都回到原状）。验证若直接落在活配置/活 vault 上，中途一出错就没有退路；"哪一步不做备份"
   必须事先向用户讲明，不要写在做不到的操作描述里。
   另注意：`vault remove` 在 `WTSSH_KEYS`/`WTSSH_SECRETS` 被设置时会直接拒绝（演练 env 下两道 blob
   护栏都指向空目录，会误删真 TPM 键）——不要在演练 env 里测它，也无意绕过。
   另注意：`agent load/unload` 的 `--agent-dir` 只隔离索引，`ssh-add` 本体永远连真实 agent——演练里只跑
   `agent status` 或 mock，真加真删只在用户明确要求时做。
9. **跳板默认不进菜单**：见上文「跳板机 vs 主机簿」。向用户汇报主机列表时，报 `groups`（菜单）即可；
   `hidden` 是给 `--jump` 用的身份条目，不要当成下拉菜单里的服务器。
