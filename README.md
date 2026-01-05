# s5route

一个在 Debian 上运行的 V2Ray 出口选择器：网页模式交互，支持订阅解析与一键切换出口，入口为 SOCKS5（端口可自定义）。

## 功能

- 添加并刷新 V2Ray 订阅（vmess/vless/trojan/ss）。
- 订阅节点一键作为出口选择。
- SOCKS5 入口地址与端口可配置。
- Web UI 采用 Apple 风格设计。

## 依赖

- Node.js 18+（建议 20+）
- 已安装的 V2Ray Core（Debian 可通过 apt 或官方 release）

## 快速开始

```bash
npm install
npm start
```

浏览器打开（默认 Web 端口 22007，可通过环境变量 `PORT` 覆盖）：

```
http://localhost:22007
```

## 一键安装为 systemd 服务

```bash
./install.sh
```

安装后将以当前用户运行，并开机自启。脚本会在需要时自动安装 Node.js 20（使用 NodeSource）。可选的环境变量可写入 `/etc/default/s5route`（例如 `PORT=22007`）。

## 访问令牌（可选）

为了避免任何人直接打开站点，可以在 `data/state.json` 中设置：

```json
{
  "settings": {
    "accessToken": "你的访问令牌"
  }
}
```

首次访问请在 URL 中带上 `?token=你的访问令牌`，服务会写入 Cookie，之后即可正常访问静态资源与接口。

## 使用说明

1. 在“入口设置”中确认 SOCKS5 监听地址与端口（默认 `0.0.0.0:1080`）。
2. 填写订阅链接并添加，点击刷新即可拉取节点。
3. 在“节点出口”中选择一个节点，点击“选择”后会自动启动 V2Ray。

生成的配置文件位于 `data/v2ray.generated.json`，日志输出到 `data/v2ray.log`。

## V2Ray 路径与参数

- 默认可执行路径：`/usr/local/bin/v2ray`
- 默认参数：`run -c data/v2ray.generated.json`

若你的 Debian 安装的是旧版或路径不同，请在网页中修改“V2Ray 可执行路径”和“参数”。

## 说明

- 本项目会直接拉起 V2Ray 进程，适合个人或单机使用。
- 如需生产部署，建议把本服务与 V2Ray 放在 systemd 中管理。
