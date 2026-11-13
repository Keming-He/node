# node — aggregator 自部署说明（Keming-He/node）

本仓库内容来自上游 [wzdnzd/aggregator](https://github.com/wzdnzd/aggregator)（Apache-2.0），
用 GitHub Actions 定时收集公开免费代理源，并将客户端配置写入自己的 Gist。
Secret Gist 不会公开列出，但持有链接的人可以读取内容，不是需要登录的私有存储。
零服务器、零费用。

## 工作流（仓库自带，`.github/workflows/`）

| 工作流 | 触发 | 做什么 |
|---|---|---|
| Collect (`collect.yaml`) | 每周一 08:00 (Asia/Shanghai) + 手动 | 重新收集候选订阅/节点；原始输出保留 `--skip` 行为 |
| Refresh (`refresh.yaml`) | 每 2 小时 + 手动 | 刷新已有订阅的候选节点 |
| Publish verified subscriptions (`publish-verified.yaml`) | 每小时第 17 分钟、Collect/Refresh 成功后、手动 | 开启证书校验，通过三次 HTTPS 请求筛选节点，同时发布 Clash 与 Shadowrocket 订阅 |

Actions 的 cron 使用 UTC；定时任务可能排队延后。发布任务复用 `GIST_PAT` 和 `GIST_LINK`，无需新增凭据。

## 自动更新订阅

- `clash.yaml` / `singbox.json`：原始候选配置，可能包含未通过连接测试的节点。
- `verified-clash.yaml`：供 Mihomo 的 HTTP proxy-provider 使用，仅包含本次检测通过的节点。
- `shadowrocket.txt`：与 `verified-clash.yaml` 相同节点的 Base64 分享链接订阅，支持当前源中的 Hysteria2、SS、VMess、Trojan，以及 VLESS。
- `verified-status.json`：检测时间、来源版本、各节点测试结果及格式兼容性排除记录，不包含密码。

使用不含版本哈希的稳定 Raw 地址：`https://gist.githubusercontent.com/<owner>/<gist_id>/raw/shadowrocket.txt`。
Shadowrocket 扫描此地址对应的 `sub://` 订阅二维码后，可更新整组节点；不再使用单节点二维码或只导出 VMess 的 `v2ray.txt`。

每个节点都必须通过 Cloudflare、Google、再次 Cloudflare 的 HTTPS 204 请求。TLS 节点启用证书校验；
不能准确转换为受支持分享链接的特殊配置会被排除并记录。两个输出在同一次 Gist PATCH 中更新。
如果网络故障、配置异常或没有节点通过，发布任务失败并保留上次成功订阅，不会用空列表覆盖。
当完成检测但 0 个节点通过时，仍更新 `verified-status.json`：`status=unavailable`、
`available_count=0`，并记录 `last_success_at` 和保留的旧节点数量。旧订阅此时只是恢复缓存，
不能视作当前可用节点；恢复成功后状态重新变为 `ok`。
检测来自 GitHub runner，不能代表手机或 Mac 的网络延迟；客户端仍需本地测速。

Mac 使用 `verified-clash.yaml` 的 HTTP provider，每 30 分钟拉取；自动选择组每 5 分钟本地测速。
桌面修补脚本维护 provider 和策略组，不再内嵌会过期的 GitHub 节点密码。

## 首次启用（仓库主人本人操作，凭据不经过任何人）

1. 新建一个 **Secret Gist** 占位（任意文件名/内容），记下 `Keming-He/<gist_id>`。
2. GitHub Settings → Developer settings → Personal access tokens，
   建一个**只勾 `gist`** 权限的 PAT。
3. 本仓库 Settings → Secrets and variables → Actions，加两个 Secrets：
   - `GIST_PAT` = 上一步的 PAT
   - `GIST_LINK` = `Keming-He/<gist_id>`
4. Actions 页打开 **Collect**，手动 **Run workflow** 跑第一次；
   成功后 Gist 里会出现 `clash.yaml` 等候选文件，随后自动触发发布任务；
   发布任务成功后，Clash provider 用 `verified-clash.yaml`，Shadowrocket 用 `shadowrocket.txt`。

## 注意

- Actions 若显示工作流被禁用，先在 Actions 页点启用（导入/推送进来的工作流有时默认停用）。
- `GIST_PAT` 是凭据：只存在 GitHub Secrets 里，不要写进代码、README 或任何聊天。
- 聚合的是公开免费源，节点质量参差、轮换快：只适合临时上网，不要过银行、主账号等敏感流量。
- 与上游同步：本地 `git remote add upstream https://github.com/wzdnzd/aggregator.git` 后
  `git fetch upstream && git merge upstream/main` 再 push。
