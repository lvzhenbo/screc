# screc - StripChat 录制工具

screc 是一个 `100%` 由 AI 驱动的、用 Rust 编写的 StripChat 直播录制工具，具有自动监控、智能重试和多用户并发录制功能。

代码参考了 [StreaMonitor](https://github.com/lossless1024/StreaMonitor) 项目，使用 Github Copilot 将 Python 代码转为 Rust 代码。

## 最近更新

- ✨ **改进的MOUFLON解密**: 支持多个MOUFLON头的处理和更好的错误处理（参考 StreaMonitor 最新提交）
- 🚫 **删除账号检测**: 自动检测并停止监控已删除的模特账号
- 🌍 **地理封锁检测**: 识别地理限制和受限内容，自动调整检查频率

## 功能特性

- 🎥 **直播间监控**: 自动检测 StripChat 主播直播状态
- 📹 **在线自动录制**: 检测到公开直播时立即开始录制
- 🔄 **中断重试机制**: 网络错误和分片失败时自动重试
- 👥 **多用户并发**: 同时监控和录制多个主播
- 🔐 **加密流解密**: 支持 MOUFLON 加密流的自动解密
- ⚙️ **智能分辨率选择**: 自动选择最接近用户设定的分辨率
- 📁 **自动文件管理**: 自动创建输出目录和文件命名
- 🌐 **代理支持**: 支持 HTTP/HTTPS/SOCKS5 代理及认证
- ❌ **优雅关闭**: 支持 Ctrl+C 优雅停止和资源清理

## 系统要求

- **Rust**: 1.82 或更高版本 (支持 Rust 2024 Edition)
- **FFmpeg**: 用于视频格式转换 (需在 PATH 中)
- **网络连接**: 访问 StripChat API 和视频流

## 安装和编译

### 编译安装

```bash
# 克隆仓库
git clone <repository-url>
cd screc

# 编译项目 (Debug)
cargo build

# 编译优化版本 (Release)
cargo build --release
```

### 安装到系统

```bash
# 编译并安装到 cargo 的 bin 目录
cargo install --path .

# 现在可以在任何地方使用 screc 命令
screc --usernames <主播用户名>
```

## 使用方法

### 基本用法

```bash
# 录制单个主播
screc --usernames "streamer1"

# 录制多个主播（用逗号分隔）
screc --usernames "streamer1,streamer2,streamer3"

# 生成默认配置文件（config.json）
screc --generate-config

# 生成指定名称的配置文件
screc --generate-config my-config.json

# 使用配置文件
screc --config ./my-config.json

# 启用调试日志
screc --usernames "streamer1" --debug

# 指定输出目录和分辨率
screc --usernames "streamer1" --output-dir ./recordings --resolution 720

# 禁用文件日志（仅控制台输出）
screc --usernames "streamer1" --log-to-file false

# 指定自定义日志文件
screc --usernames "streamer1" --log-file ./my-log.log

# 使用 cookies
screc --usernames "streamer1" --cookies "session_id=abc123; user_token=xyz789"
```

## 命令行参数

| 参数                | 短参数 | 类型   | 默认值         | 描述                                             |
| ------------------- | ------ | ------ | -------------- | ------------------------------------------------ |
| `--config`          | `-c`   | String | `config.json`  | 配置文件路径                                     |
| `--usernames`       | `-u`   | String | -              | 要录制的用户名，多个用逗号分隔                   |
| `--output-dir`      | `-o`   | String | `downloads`    | 录制文件输出目录                                 |
| `--resolution`      | `-r`   | u32    | `1080`         | 期望的视频分辨率高度 (如 720, 1080)              |
| `--check-interval`  | -      | u64    | `30`           | 离线时的检查间隔（秒）                           |
| `--debug`           | `-d`   | Flag   | `false`        | 启用调试日志输出                                 |
| `--proxy`           | -      | String | -              | 代理服务器 URL                                   |
| `--proxy-username`  | -      | String | -              | 代理认证用户名                                   |
| `--proxy-password`  | -      | String | -              | 代理认证密码                                     |
| `--log-to-file`     | -      | Flag   | `true`         | 是否输出日志到文件                               |
| `--log-file`        | -      | String | auto-generated | 日志文件路径                                     |
| `--cookies`         | -      | String | -              | Cookie 字符串 (格式: "key1=value1; key2=value2") |
| `--generate-config` | -      | String | `config.json`  | 生成默认配置文件，可指定文件名（独立功能）       |

## 配置文件

配置文件使用 JSON 格式，支持以下选项：

### 生成配置文件

使用 `--generate-config` 参数可以快速生成默认配置文件：

```bash
# 生成默认配置文件 config.json
screc --generate-config

# 生成指定名称的配置文件
screc --generate-config my-settings.json

# 生成配置文件到指定目录
screc --generate-config ./configs/prod-config.json
```

**注意**: 生成配置文件功能不能与其他录制相关参数同时使用，需要单独执行。

### 配置选项

配置文件使用 JSON 格式，支持以下选项：

| 选项             | 类型          | 默认值             | 描述                    |
| ---------------- | ------------- | ------------------ | ----------------------- |
| `usernames`      | Array[String] | `[]`               | 要监控的主播用户名列表  |
| `output_dir`     | String        | `"downloads"`      | 录制文件输出目录        |
| `resolution`     | Number        | `1080`             | 期望的视频分辨率高度    |
| `check_interval` | Number        | `30`               | 离线时的检查间隔（秒）  |
| `debug`          | Boolean       | `false`            | 是否启用调试日志        |
| `proxy`          | String/null   | `null`             | 代理服务器 URL          |
| `proxy_username` | String/null   | `null`             | 代理认证用户名          |
| `proxy_password` | String/null   | `null`             | 代理认证密码            |
| `user_agent`     | String        | `"Mozilla/5.0..."` | HTTP 请求用户代理字符串 |
| `log_to_file`    | Boolean       | `true`             | 是否输出日志到文件      |
| `log_file_path`  | String        | `"logs"`           | 日志文件目录路径        |
| `cookies`        | String/null   | `null`             | Cookie 字符串           |

### 配置文件示例

```json
{
  "usernames": ["streamer1", "streamer2"],
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
  "cookies": "session_id=abc123; user_token=xyz789"
}
```

## 日志系统

screc 具有完整的日志系统，默认启用，支持彩色控制台输出和文件日志记录。

- **ERROR** (红色) - 错误信息，如录制失败、网络错误等
- **WARN** (黄色) - 警告信息，如配置文件加载失败等
- **INFO** (绿色) - 一般信息，如录制开始、状态变化等
- **DEBUG** (蓝色) - 调试信息，需要使用 `--debug` 参数启用
- **时间戳**: 精确到毫秒的时间戳显示
- **格式化**: 清晰的日志格式便于阅读

### 文件日志

文件日志默认启用，可以通过配置控制：

```bash
# 启用文件日志（默认）
screc --usernames "streamer1" --log-to-file

# 禁用文件日志
screc --usernames "streamer1" --log-to-file false

# 指定日志文件路径
screc --usernames "streamer1" --log-file "my-log.log"
```

### 日志文件位置

如果不指定日志文件路径，程序会自动生成：

- **文件名格式**: `screc-YYYY-MM-DD-HH-MM-SS.log`
- **默认位置**: 程序所在目录的 `logs` 文件夹
- **自动创建**: 如果目录不存在会自动创建

### 配置文件中的日志设置

```json
{
  "log_to_file": true,
  "log_file_path": "logs"
}
```

或指定具体文件：

```json
{
  "log_to_file": true,
  "log_file_path": "./my-logs/custom-log.log"
}
```

## Cookie 支持

screc 支持使用 cookies 来访问需要身份认证的内容。Cookie 功能主要用于：

- 访问私人直播或会员专用内容
- 绕过某些地区限制
- 提高 API 请求成功率

### Cookie 配置方式

1. **命令行参数** (优先级最高):

```bash
screc --usernames "streamer1" --cookies "session_id=abc123; user_token=xyz789"
```

2. **配置文件**:

```json
{
  "cookies": "session_id=abc123; user_token=xyz789; preference=enabled"
}
```

### Cookie 格式

Cookie 字符串应遵循标准的 HTTP Cookie 格式：

- 多个 cookie 用分号和空格分隔：`"key1=value1; key2=value2"`
- 单个 cookie 格式：`"key=value"`

### 获取 Cookie

1. **浏览器开发者工具**:

   - 打开浏览器访问 StripChat
   - 按 F12 打开开发者工具
   - 切换到 Network 标签页
   - 刷新页面，查看任一请求的请求头
   - 复制 Cookie 头的值

2. **浏览器插件**:
   - 使用如 "Cookie Editor" 等浏览器插件
   - 导出相关站点的 cookies

**注意**:

- Cookie 可能包含敏感信息，请妥善保管
- Cookie 有过期时间，可能需要定期更新
- 使用 Cookie 需要遵守网站的使用条款

## 代理支持

screc 具有统一的代理配置系统，支持多种代理类型和认证方式。

### 支持的代理类型

| 类型   | URL 格式             | 示例                             |
| ------ | -------------------- | -------------------------------- |
| HTTP   | `http://host:port`   | `http://127.0.0.1:8080`          |
| HTTPS  | `https://host:port`  | `https://proxy.example.com:8080` |
| SOCKS5 | `socks5://host:port` | `socks5://127.0.0.1:1080`        |

### 代理配置方式

1. **命令行参数** (优先级最高):

```bash
screc --usernames "streamer1" \
  --proxy "socks5://127.0.0.1:1080" \
  --proxy-username "user" \
  --proxy-password "pass"
```

2. **配置文件**:

```json
{
  "proxy": "socks5://127.0.0.1:1080",
  "proxy_username": "user",
  "proxy_password": "pass"
}
```

3. **环境变量** (优先级最低):

程序会自动读取以下环境变量：

- `HTTP_PROXY` / `http_proxy`
- `HTTPS_PROXY` / `https_proxy`

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=https://proxy.example.com:8080
```

## 工作原理

程序的录制流程如下：

1. **初始化配置** - 加载配置文件和命令行参数，设置代理和认证信息（包括 cookies）
2. **状态监控** - 程序定期调用 StripChat API 检查主播状态（使用配置的 cookies 进行认证）
3. **自动触发** - 检测到公开直播时立即开始录制
4. **流获取** - 获取 HLS 视频流 URL 和播放列表
5. **分辨率选择** - 根据用户设置自动选择最佳分辨率
6. **分片下载** - 下载 M3U8 播放列表中的视频分片
7. **解密处理** - 自动处理 MOUFLON 加密的视频分片
8. **重试机制** - 分片失败时自动重试，网络中断时恢复下载
9. **格式转换** - 使用 FFmpeg 将分片合并为 MP4 文件

## 直播状态识别

程序能识别以下直播状态并相应调整行为：

- **Public** - 主播正在公开直播，立即开始录制
- **Private** - 主播在私人秀中，每 5 秒检查一次状态
- **Offline** - 主播离线，每 30 秒检查一次状态
- **LongOffline** - 长时间离线，每 5 分钟检查一次状态
- **NotExist** - 模特账号已删除，停止监控（自动退出）
- **Restricted** - 地理封锁或访问受限，每 5 分钟检查一次状态
- **Error** - 发生错误，等待 20 秒后重试
- **Unknown** - 未知状态，每 30 秒检查一次状态

## 智能重试和错误处理

程序具有完善的错误处理和优雅关闭机制：

### 网络错误处理

- **网络连接失败** - 自动重试，最多 3 次
- **分片下载失败** - 跳过该分片，继续下载其他分片
- **418 "I'm a teapot"** - 正常 CDN 响应，自动跳过
- **404/403 错误** - 分片不可用，自动跳过
- **429 频率限制** - 延迟后重试
- **连续 10 次无新分片** - 认为直播结束，停止录制

### 优雅关闭机制

程序支持通过 `Ctrl+C` 信号进行优雅关闭：

1. **信号捕获** - 捕获 SIGINT 信号（Ctrl+C）
2. **任务通知** - 向所有录制任务发送关闭信号
3. **资源清理** - 等待所有任务完成清理工作
4. **超时保护** - 最多等待 60 秒，防止程序挂起
5. **状态报告** - 实时显示关闭进度和状态

## 输出文件

### 录制文件

录制的视频文件将保存在以下路径结构：

```
<output-dir>/<username>/<username>-<timestamp>.mp4
```

### 日志文件

如果启用了文件日志，日志文件将保存在：

```
logs/
└── screc-YYYY-MM-DD-HH-MM-SS.log
```

### 配置文件

默认配置文件位置：

```
./config.json
```

## 使用须知

- **网络要求** - 需要稳定的网络连接访问 StripChat API 和视频流
- **存储空间** - 确保有足够磁盘空间，高清录制每小时约 1-3GB
- **FFmpeg 依赖** - 必须安装 FFmpeg 并确保在系统 PATH 中
- **使用条款** - 请遵守 StripChat 的使用条款和相关法律法规
- **隐私保护** - 请尊重主播和观众的隐私权，合理使用
- **并发限制** - 建议同时录制的主播数量不超过 10 个

## 故障排除

### 常见问题及解决方案

**编译失败**

- 原因：Rust 版本过低
- 解决：升级到 Rust 1.82 或更高版本（支持 Rust 2024 Edition）

**FFmpeg 错误**

- 原因：FFmpeg 未安装或不在 PATH 中
- 解决：安装 FFmpeg 并将其添加到系统环境变量

**网络连接失败**

- 原因：网络问题或防火墙阻拦
- 解决：检查网络连接，必要时配置代理

**API 访问失败**

- 原因：IP 被限制或站点维护
- 解决：更换代理服务器或稍后重试

**磁盘空间不足**

- 原因：存储空间不够
- 解决：清理磁盘空间或更改输出目录

**日志文件写入失败**

- 原因：日志目录权限不足或磁盘空间不足
- 解决：检查目录权限，或使用 `--log-to-file false` 禁用文件日志

**程序无法优雅关闭**

- 原因：录制任务卡死或网络阻塞
- 解决：等待 60 秒超时或强制终止进程

### HLS 下载问题

**418 "I'm a teapot" 错误**
这是正常现象，CDN 使用此状态码表示分片暂时不可用，程序会自动跳过。

**重复分片下载**
程序会自动检测并跳过重复分片，不会造成重复下载。

**连续空播放列表**
当连续 10 次检查都没有新分片时，程序认为直播已结束并自动停止。

**分片下载超时**
网络不稳定时可能发生，程序会自动重试最多 3 次。

### 代理相关问题

**代理连接失败**

- 检查代理地址和端口是否正确
- 确认代理服务器正在运行

**代理认证失败**

- 验证用户名和密码是否正确
- 确认代理服务器支持认证

**代理速度慢**

- 尝试更换其他代理服务器
- 检查代理服务器的网络状况

### Cookie 相关问题

**Cookie 认证失败**

- 检查 Cookie 格式是否正确（应为 "key1=value1; key2=value2" 格式）
- 确认 Cookie 是否已过期，尝试重新获取
- 验证从正确的网站域名获取 Cookie

**Cookie 无效或权限不足**

- 确保 Cookie 来源于已登录的账户
- 检查账户是否有访问目标内容的权限
- Cookie 可能需要包含必要的会话和认证信息

**Cookie 频繁过期**

- Cookie 有时间限制，需要定期更新
- 可以设置自动化脚本定期获取新的 Cookie
- 考虑在配置文件中更新 Cookie 而不是命令行参数

## 开发信息

### 项目结构

项目采用模块化设计，各文件职责如下：

- `src/main.rs` - 主程序入口和命令行参数处理
- `src/config.rs` - 配置管理和参数解析
- `src/stripchat.rs` - StripChat API 集成和录制逻辑
- `src/downloader.rs` - HLS 视频流下载器
- `src/utils.rs` - 工具函数和辅助方法

### 主要依赖库

- `reqwest` - HTTP 客户端和代理支持
- `tokio` - 异步运行时和并发处理
- `serde` / `serde_json` - JSON 序列化和反序列化
- `clap` - 命令行参数解析
- `m3u8-rs` - M3U8 播放列表解析
- `anyhow` - 错误处理
- `fern` - 日志系统管理
- `colored` - 彩色控制台输出
- `chrono` - 时间处理和格式化
- `log` - 日志接口
- `sha2` / `base64` - 加密和编码处理
- `url` - URL 解析和处理

## 许可证

MIT

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。
