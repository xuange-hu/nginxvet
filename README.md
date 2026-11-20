# nginxvet

[![tests](https://img.shields.io/badge/tests-235-brightgreen)](https://github.com/xuange-hu/nginxvet/actions)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![deps](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](https://github.com/xuange-hu/nginxvet/blob/main/pyproject.toml)

**零依赖、证据式的 nginx 配置安全审计器（中文优先 / Chinese-first）。**

Most nginx linters read one directive at a time. nginxvet reads the *effective*
configuration: it expands `include`, models nginx's real inheritance rules,
and runs three passes — directive, relation, cross-file — so it can report the
finding that single-pass tools structurally cannot see: **the `add_header`
inheritance trap**.

```
CRITICAL NGV201  location /api/ defines add_header; 3 server-level security header(s) are dropped here: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options
         at <demo>/nginx.conf:44 (offset 1120, len 26)
         saw: add_header X-Debug 1;
         fix: Repeat all security add_header directives inside the location, or move the extra header up to server level.
...
55 finding(s) across 5 file(s): 2 critical, 5 high, 32 medium, 15 low, 1 note
```

## 与 gixy 的差异

| | gixy | nginxvet |
|---|---|---|
| 依赖 | 多个第三方包 | **零运行时依赖**，stdlib only |
| 分析 | 单遍指令级 | **三遍**：指令 / server-location 关系 / include 跨文件 |
| `add_header` | 逐行看，每行都"正确" | 建模 nginx 继承：**location 有 add_header → server 级安全头全部失效** |
| 证据 | 主要是规则名 | 每条结论带 `path / line / byte offset / 原始片段` |
| 交互 | 无 effective 查询 | `nginxvet effective <host> [--location /path]` 回答"这里最终生效的头部有哪些" |
| CI | 文本 | SARIF 2.1.0 + `--fail-on` + 6 个 MCP 工具 |

## 三步跑通

```console
# 1. 安装（无需解析任何依赖）
pip install .

# 2. 扫描真实配置（include 会自动展开）
nginxvet scan /etc/nginx/nginx.conf /etc/nginx/conf.d/

# 3. 旗舰命令：这个 location 到底有哪些安全头？
nginxvet effective example.com /etc/nginx/nginx.conf --location /api/user
effective headers from: location /api/
  x-debug: 1
  MISSING core headers: strict-transport-security, content-security-policy, x-frame-options
  ADD_HEADER TRAP: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options were dropped by the location's own add_header
```

没有现成机器？`nginxvet demo` 运行内置语料，37 条规则全部命中。

## 核心卖点：add_header 继承陷阱

nginx 的 `add_header` **从不合并**：一旦某个 location 里出现任意一条
`add_header`，server（及 http）级的所有 `add_header` 在该 location 内全部失效。
于是仅仅为了调试加的一行 `add_header X-Debug 1;`，就会让整个 URL 树丢掉
HSTS、CSP 和 X-Frame-Options。

这是单遍分析发现不了的：每一行单独看都是对的。`nginxvet effective` 直接回答
"这个 location 最终生效的安全头是什么"，并列出被丢掉的那些。

## 检查什么

三遍、37 条规则（全文见 [docs/rules.md](docs/rules.md)）：

| 遍 | 规则 | 关注点 |
|---|---|---|
| `directive` | NGV101–NGV121 | 单条指令：版本泄漏、autoindex、TLS 协议/套件、日志、请求体大小、if+rewrite…… |
| `relation` | NGV201–NGV208 | server/location 关系：**add_header 继承陷阱**、proxy_set_header 丢失、命名 location、if 覆盖、upstream keepalive…… |
| `crossfile` | NGV301–NGV308 | include 展开后的效果：加固被回退、include 触发头部陷阱、通配符顺序、TLS 策略不一致、重复/缺失 include…… |

## 证据式输出与 CI

每条 Finding 都有 `path` / `line` / `offset` / `saw` 四要素；SARIF 保留同样的
字段与字节偏移，`--fail-on` 提供门禁：

```console
nginxvet scan /etc/nginx/ --format sarif --fail-on high > nginxvet.sarif
```

## MCP server

提供 6 个工具（scan、effective、demo、rules、explain、parse），`mcp` 为可选
extra 且惰性导入：

```console
uvx --from "git+https://github.com/xuange-hu/nginxvet#egg=nginxvet[mcp]" nginxvet-mcp
```

其中 `nginxvet_effective` 是 agent 真正需要的那个工具。

## 安装说明

- Python 3.10+，零运行时依赖；mcp 是可选 extra，核心包永不导入它。
- 根 `conftest.py` 让 `git clone && pip install . && pytest` 离线可跑。
- CI 校验：3.10–3.13 矩阵、fresh-clone、徽章数 = pytest 收集数、MCP manifest。

## 相关工具

零依赖审计器家族的一员：
[sysctlvet](https://github.com/xuange-hu/sysctlvet)（sysctl）、
[sshdguard](https://github.com/xuange-hu/sshdguard)（sshd_config）、
[sudolint](https://github.com/xuange-hu/sudolint)（sudoers）、
[unitlint](https://github.com/xuange-hu/unitlint)（systemd unit）、
[cronlint](https://github.com/xuange-hu/cronlint)（crontab）、
[firelint](https://github.com/xuange-hu/firelint)（防火墙规则）。

## License

MIT。规则刻意有立场，每条都在 [docs/rules.md](docs/rules.md) 里给出论据。
