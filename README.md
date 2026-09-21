# wt-ssh-manager

Windows Terminal `ssh` 主机簿管理 skill：用 `scripts/wtssh.py` 增删改查 WT 下拉菜单里的 SSH 入口（分组、跳板机、端口、密钥、默认 profile），可选 TPM vault 保管密钥与口令，并可把条目同步进 FileZilla 站点管理器或在 WT 菜单里放 SFTP 入口。

权威 agent 操作说明见 [SKILL.md](SKILL.md)；本 README 只给人看的项目速览。

## 目录结构

- `SKILL.md` — agent 指令全文（机制、命令对照表、安全纪律），改行为先读它。
- `scripts/wtssh.py` — 全部功能的唯一实现（约 400KB，Python ≥ 3.12）。所有输出是 JSON；人类可读报错走 stderr，前缀 `wtssh: error:`。
- `scripts/cng-vault.ps1` — TPM vault 加解密 helper（密码学细节与进程模型在此）。
- `scripts/passphrase-prompt.ps1`、`scripts/dpapi.ps1` — 口令弹窗 / DPAPI 辅助。
- `tests/` — pytest 覆盖（agent、dispatcher、run、sock gate、FileZilla 隧道、SFTP 菜单、DACL、hostkey 探测等）。

## 环境要求

- Windows + Windows Terminal（Store 稳定版 / 预览版 / 免安装版，settings.json 自动探测）。
- Python ≥ 3.12（Windows 上 `python` 不存在时依次试 `py -3`、`python3`）。
- 可选：TPM（vault：`secret` / `key` / `vault` 子命令才需要）、FileZilla（`filezilla`/`fz` 才需要）、OpenSSH ≥ 8.4（低于此版本 vault 口令退化为终端明示输入）。

## 快速开始

```bash
# 查看主机簿（不带 --group 看全部分组 + ungrouped + hidden）
python scripts/wtssh.py list

# 加一台主机（默认进 ssh 组；加完按纪律要问用户是否加伴生 SFTP，见下）
python scripts/wtssh.py add alpha --user u --host h --port 22 --key C:/keys/alpha.pem

# 连它（vault 条目弹 1 个 CNG PIN 窗后启动 ssh）
python scripts/wtssh.py connect alpha
# 别名：open alpha；跑远端命令：run alpha -- uptime -p

# 从 ~/.ssh/config 批量导入
python scripts/wtssh.py import

# 体检
python scripts/wtssh.py doctor
python scripts/wtssh.py doctor alpha
```

全局参数（`--group` / `--sftp-group` / `--settings` / `--secrets` / `--keys`）一律写在子命令之前，也可用 `WTSSH_GROUP` / `WTSSH_SFTP_GROUP` / `WTSSH_SETTINGS` / `WTSSH_SECRETS` / `WTSSH_KEYS` 环境变量。

## 核心概念（三句话）

1. **一个分组 = 两处协同**：`newTabMenu` 里同名 `folder` 的 `entries`（顺序 = 菜单顺序）+ `profiles.list` 里 `ssh:` 前缀的 profile。SSH 主机默认进 `ssh` 组（`--group` 可改）。
2. **跳板机默认不进菜单**：`add jumper ... --hidden`（hidden 条目仍可被 `--jump` 引用、渲染、connect，只是不出现在下拉菜单）。只当跳板就别 `remove` 它。
3. **`sftp:` 伴生是菜单入口，不是主机**：`edit X --sftp` 在 `sftp` 组（默认与 `ssh` 组并列）建 `sftp:X`，点击即开 FileZilla；身份在点击时才从主机簿解析，后续改动零传播。

## 常用命令对照

| 意图 | 命令 |
|---|---|
| 看列表 / 看单条 / 看 GUID / 看默认 | `list [--full]`、`show NAME`、`guid NAME`、`get-default` |
| 加主机 / 改字段 / 清手动选项 / 去跳板 | `add NAME --user/--host/--port/--key/--jump/--extra/--default`、`edit NAME ...`、`edit NAME --extra none`、`edit NAME --jump none` |
| 跳板机（不进菜单） | `add jumper ... --hidden`；拿掉菜单可见性用 `edit X --hidden`，恢复用 `edit X --visible` |
| 分组 / 重命名 / 删除 / 排序 / 设默认 | `--group prod add ...`、`rename OLD NEW`、`remove NAME`、`move NAME --top/--bottom/--after X/--before X`、`set-default NAME` |
| 看实际 ssh 命令 / 看跳板链计划 | `print NAME --cmd`、`print NAME`（默认 `--plan`，无秘密） |
| 导入 OpenSSH config | `import [--ssh-config PATH]` |
| 口令进 vault / 去掉 / 查有哪些 | `secret set NAME`、`secret remove NAME`、`secret list`（无 `get`） |
| 独立密钥（无需主机条目） | `key import KEYNAME FILE [--move]`、`key list`、`key rename OLD NEW`、`key remove KEYNAME`、`key export KEYNAME OUTFILE` |
| 一次 PIN、TTL 内免 PIN | `agent load [--ttl 8h] [KEY...]`、`agent status`、`agent unload [--all]` |
| 连 / 跑命令 | `connect NAME`（别名 `open`）、`run NAME -- CMD...`（裸写 `wtssh NAME CMD...` 等价） |
| FileZilla | `filezilla NAME`（别名 `fz`）、`--tunnel [yes|auto]` 走跳板隧道、`--no-open` 只同步、`--remove-site` 清理 |
| SFTP 菜单伴生 | `edit X --sftp`（去掉用 `--no-sftp`；跟 SSH 同组用 `--sftp-group ssh`） |
| Vault 管理 | `vault init` / `vault status` / `vault remove` |

两条 agent 纪律（详见 `SKILL.md`）：加主机时**禁止**顺手带 `--sftp`——先只加 SSH，加完必须问用户要不要伴生 SFTP；跳板机用户没说要进菜单时 **MUST** `--hidden`。

名字红线：条目名/密钥名及 routed 行载荷不得含 cmd 元字符 `& | < > ^ % !` 或控制字符（经 cmd.exe 启动，会分裂命令行；`%` 连引号都挡不住）。

## 保密架构（摘要）

- vault 可选。无 TPM 的机器上明文 `--key` 路径 + `import` + 增删改查照常工作。
- `vault init` 后：`key import` 把私钥收进 `%LOCALAPPDATA%\wtssh\keys\<NAME>.wtv`（AES-256-GCM，DEK 由 TPM RSA 键包裹，blob 与名字双绑定，复制改名会被拒绝）；条目用 `-i wtv:KEYNAME` 引用。
- `connect` 时弹 1 个 CNG PIN 窗 → 容器写 owner-only 临时目录 → ssh 以容器为 `-i`，口令经 owner-only 映射文件喂 askpass（不进环境变量/argv），结束覆写删除。整条跳板链只弹 1 个 PIN 窗，一跳一口令精确派发。
- 安全边界：防静默/离线，不防"骗人输 PIN"；PIN 窗内的用途文字不可作信任依据。`agent load` 后私钥在 ssh-agent 内存活整个 TTL（同机其他用户可用不能导），到期靠 wtssh 侧强制回落。

## FileZilla 桥（摘要）

`filezilla NAME` 把主机簿身份同步进 `%APPDATA%\FileZilla\sitemanager.xml` 的同名组文件夹后 `filezilla -c` 直连；`--jump` 在普通同步里被忽略并告警，真跳板链用 `--tunnel`（SOCKS 代理 + 真实地址，会话密钥为随机口令加密 PPK v2，关 FileZilla 即收尾）。`rename`/`remove`/换组不传播到站点簿，孤儿站点只告警不代删。

## 测试

```bash
python -m pytest tests/ -q
```

写子命令的验证必须落在副本上（`--settings <副本>` + `--secrets`/`--keys`/`--agent-dir` 指向临时目录），别写活配置、活 vault；`agent load/unload` 演练只跑 `agent status` 或 mock。FileZilla 演练用 `WTSSH_FZ_SITEMANAGER` / `WTSSH_FZ_FILEZILLAXML` 指向副本。

## 安全与习惯

- 不要手改 `settings.json`——脚本负责 WT 兼容 JSON（写前校验、原子替换、自动备份 `settings.json.wtssh.bak`，滚动单份）。
- `remove` 不可逆：先 `show` 复述再执行（除非用户明确说删）。
- 改动后跑一次 `list` 确认 JSON 合法，看 WT 下拉菜单是否热重载出现。
- WT 报配置错误时先 `list`/`show` 自检，再从 `.wtssh.bak` 恢复。
