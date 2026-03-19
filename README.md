# screc

用 Rust 编写的 StripChat 直播录制工具，提供 **CLI** 和 **GUI** 两种使用方式。具有自动监控、智能重试、多用户并发录制和加密流解密功能。

代码参考了 [StreaMonitor](https://github.com/lossless1024/StreaMonitor) 项目。

## 功能特性

- 🎥 **直播间监控** — 自动检测 StripChat 主播直播状态
- 📹 **在线自动录制** — 检测到公开直播时立即开始录制
- 🖥️ **原生 GUI** — 基于 [GPUI](https://github.com/zed-industries/zed) 的桌面客户端，支持实时状态监控、模特管理和日志查看
- 🔄 **中断重试** — 网络错误和分片失败时自动重试
- 👥 **多用户并发** — 同时监控和录制多个主播
- 🔐 **加密流解密** — 支持 MOUFLON 加密流的自动解密（含多头处理）
- ⚙️ **智能分辨率** — 自动选择最接近用户设定的分辨率
- 🌐 **代理支持** — HTTP / HTTPS / SOCKS5 代理及认证
- 🍪 **Cookie 支持** — 访问需要身份认证的内容
- 🚫 **删除账号检测** — 自动检测并停止监控已删除的账号
- 🌍 **地理封锁检测** — 识别地理限制，自动调整检查频率
- ❌ **优雅关闭** — Ctrl+C 优雅停止和资源清理

## 系统要求

- **Rust** 1.82+（Rust 2024 Edition）
- **FFmpeg** — 用于视频格式转换，需在 PATH 中
- **网络连接** — 访问 StripChat API 和视频流

## 安装

### 从源码编译

```bash
git clone <repository-url>
cd screc

# 仅编译 CLI
cargo build --release --package screc

# 仅编译 GUI
cargo build --release --package screc-gui

# 编译所有
cargo build --release --workspace
```

编译产物位于 `target/release/` 目录。

### 安装 CLI 到系统

```bash
cargo install --path crates/screc-cli
```

## 项目结构

```
crates/
├── screc-cli/    # 命令行客户端（二进制名：screc）
├── screc-core/   # 核心录制库（配置、下载、API、解密）
└── screc-gui/    # GUI 桌面客户端（二进制名：screc-gui）
```

## 使用方法

### CLI

```bash
# 录制单个主播
screc -u "streamer1"

# 录制多个主播
screc -u "streamer1,streamer2,streamer3"

# 指定输出目录和分辨率
screc -u "streamer1" -o ./recordings -r 720

# 使用配置文件
screc -c ./my-config.json

# 生成默认配置文件
screc --generate-config

# 启用调试日志
screc -u "streamer1" -d

# 使用代理和 cookies
screc -u "streamer1" --proxy "socks5://127.0.0.1:1080" --cookies "session_id=abc123"
```

### GUI

直接运行 `screc-gui` 即可。GUI 自动读取同目录下的 `config.json` 配置文件。

GUI 提供：

- **模特状态表格** — 实时显示各模特的直播状态、录制状态、录制时长、文件路径
- **模特管理** — 动态添加/删除/启用/禁用模特
- **实时日志** — 彩色日志查看，支持自动滚动
- **主题同步** — 跟随系统主题

## 命令行参数

| 参数                | 短参数 | 类型   | 默认值        | 描述                           |
| ------------------- | ------ | ------ | ------------- | ------------------------------ |
| `--config`          | `-c`   | String | `config.json` | 配置文件路径                   |
| `--usernames`       | `-u`   | String | —             | 要录制的用户名，多个用逗号分隔 |
| `--output-dir`      | `-o`   | String | `downloads`   | 录制文件输出目录               |
| `--resolution`      | `-r`   | u32    | `1080`        | 期望的视频分辨率高度           |
| `--check-interval`  | —      | u64    | `30`          | 离线时的检查间隔（秒）         |
| `--debug`           | `-d`   | Flag   | `false`       | 启用调试日志                   |
| `--proxy`           | —      | String | —             | 代理服务器 URL                 |
| `--proxy-username`  | —      | String | —             | 代理认证用户名                 |
| `--proxy-password`  | —      | String | —             | 代理认证密码                   |
| `--log-to-file`     | —      | Flag   | `true`        | 是否输出日志到文件             |
| `--log-file`        | —      | String | 自动生成      | 日志文件路径                   |
| `--cookies`         | —      | String | —             | Cookie 字符串                  |
| `--generate-config` | —      | String | `config.json` | 生成默认配置文件（独立功能）   |

## 配置文件

JSON 格式。使用 `screc --generate-config` 可快速生成。

### 配置项

| 选项             | 类型          | 默认值             | 描述                                     |
| ---------------- | ------------- | ------------------ | ---------------------------------------- |
| `usernames`      | Array[Object] | `[]`               | 模特列表，每项含 `username` 和 `enabled` |
| `output_dir`     | String        | `"downloads"`      | 录制文件输出目录                         |
| `resolution`     | Number        | `1080`             | 期望的视频分辨率高度                     |
| `check_interval` | Number        | `30`               | 离线检查间隔（秒）                       |
| `debug`          | Boolean       | `false`            | 启用调试日志                             |
| `proxy`          | String/null   | `null`             | 代理服务器 URL                           |
| `proxy_username` | String/null   | `null`             | 代理认证用户名                           |
| `proxy_password` | String/null   | `null`             | 代理认证密码                             |
| `user_agent`     | String        | `"Mozilla/5.0..."` | HTTP User-Agent                          |
| `log_to_file`    | Boolean       | `true`             | 是否输出日志到文件                       |
| `log_file_path`  | String        | `"logs"`           | 日志文件目录                             |
| `cookies`        | String/null   | `null`             | Cookie 字符串                            |

### 示例

```json
{
  "usernames": [
    { "username": "streamer1", "enabled": true },
    { "username": "streamer2", "enabled": false }
  ],
  "output_dir": "downloads",
  "resolution": 1080,
  "check_interval": 30,
  "debug": false,
  "proxy": "socks5://127.0.0.1:1080",
  "proxy_username": null,
  "proxy_password": null,
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "log_to_file": true,
  "log_file_path": "logs",
  "cookies": null
}
```

## 代理支持

| 类型   | 格式                 | 示例                             |
| ------ | -------------------- | -------------------------------- |
| HTTP   | `http://host:port`   | `http://127.0.0.1:8080`          |
| HTTPS  | `https://host:port`  | `https://proxy.example.com:8080` |
| SOCKS5 | `socks5://host:port` | `socks5://127.0.0.1:1080`        |

配置优先级：命令行参数 > 配置文件 > 环境变量（`HTTP_PROXY` / `HTTPS_PROXY`）。

## 工作原理

1. **加载配置** — 合并配置文件和命令行参数
2. **状态监控** — 定期调用 StripChat API 检测主播状态
3. **自动录制** — 检测到公开直播时立即开始录制
4. **流获取** — 获取 HLS 视频流 URL 和播放列表
5. **分辨率选择** — 自动选择最佳分辨率
6. **分片下载** — 下载 M3U8 播放列表中的视频分片
7. **解密处理** — 自动处理 MOUFLON 加密分片
8. **格式转换** — 使用 FFmpeg 将分片合并为 MP4

### 直播状态

| 状态            | 行为                    |
| --------------- | ----------------------- |
| **Public**      | 立即开始录制            |
| **Private**     | 每 5 秒检查             |
| **Offline**     | 每 30 秒检查            |
| **LongOffline** | 每 5 分钟检查           |
| **NotExist**    | 账号已删除，停止监控    |
| **Restricted**  | 地理封锁，每 5 分钟检查 |
| **Error**       | 20 秒后重试             |
| **Unknown**     | 每 30 秒检查            |

### 错误处理

- 网络连接失败 — 自动重试，最多 3 次
- 分片下载失败 — 跳过该分片，继续下载
- 418 / 404 / 403 — 自动跳过
- 429 频率限制 — 延迟后重试
- 连续 10 次无新分片 — 认为直播结束

### 优雅关闭

`Ctrl+C` 触发优雅关闭：向所有任务发送关闭信号 → 等待资源清理 → 60 秒超时保护。

## 输出文件

```
<output-dir>/<username>/<username>-<timestamp>.mp4    # 录制文件
logs/screc-YYYY-MM-DD-HH-MM-SS.log                   # 日志文件
```

## 故障排除

| 问题         | 解决方案                                 |
| ------------ | ---------------------------------------- |
| 编译失败     | 升级 Rust 至 1.82+（Rust 2024 Edition）  |
| FFmpeg 错误  | 安装 FFmpeg 并添加到 PATH                |
| 网络连接失败 | 检查网络，配置代理                       |
| API 访问失败 | 更换代理或稍后重试                       |
| 磁盘空间不足 | 清理空间或更改输出目录（高清约 1-3GB/h） |
| Cookie 无效  | 检查格式和过期时间，重新获取             |
| 程序无法关闭 | 等待 60 秒超时或强制终止                 |

## 主要依赖

| 库                        | 用途                                                     |
| ------------------------- | -------------------------------------------------------- |
| `tokio`                   | 异步运行时                                               |
| `reqwest`                 | HTTP 客户端（含 cookies / SOCKS5）                       |
| `clap`                    | 命令行参数解析                                           |
| `serde` / `serde_json`    | JSON 序列化                                              |
| `m3u8-rs`                 | M3U8 播放列表解析                                        |
| `sha2` / `base64`         | 加密流解密                                               |
| `fern` / `log`            | 日志系统                                                 |
| `gpui` / `gpui-component` | GUI 框架（[Zed](https://github.com/zed-industries/zed)） |

## 许可证

[MIT](LICENSE) — Copyright © 2025 无聊波波

## 贡献

欢迎提交 Issue 和 Pull Request。
