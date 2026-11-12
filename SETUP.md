# node — aggregator 自部署说明（Keming-He/node）

本仓库内容来自上游 [wzdnzd/aggregator](https://github.com/wzdnzd/aggregator)（Apache-2.0），
用 GitHub Actions 定时爬取公开免费代理源、验证后写入自己的 Gist，Gist 链接即私有订阅地址。
零服务器、零费用。

## 工作流（仓库自带，`.github/workflows/`）

| 工作流 | 触发 | 做什么 |
|---|---|---|
| Collect (`collect.yaml`) | 每周一 00:00 (Asia/Shanghai) + 手动 | `python -u subscribe/collect.py --all --overwrite --skip` 重新收集新订阅/节点 |
| Refresh (`refresh.yaml`) | 每 2 小时 + 手动 | `python -u subscribe/collect.py --all --refresh --overwrite --skip` 只刷新已有订阅的节点 |

## 首次启用（仓库主人本人操作，凭据不经过任何人）

1. 新建一个 **Secret Gist** 占位（任意文件名/内容），记下 `Keming-He/<gist_id>`。
2. GitHub Settings → Developer settings → Personal access tokens，
   建一个**只勾 `gist`** 权限的 PAT。
3. 本仓库 Settings → Secrets and variables → Actions，加两个 Secrets：
   - `GIST_PAT` = 上一步的 PAT
   - `GIST_LINK` = `Keming-He/<gist_id>`
4. Actions 页打开 **Collect**，手动 **Run workflow** 跑第一次；
   成功后 Gist 里会出现 `clash.yaml` / `v2ray.txt` 等输出文件，
   Gist 的 Raw 链接即订阅地址（Clash 用 clash 文件，小火箭用 v2ray 文件）。

## 注意

- Actions 若显示工作流被禁用，先在 Actions 页点启用（导入/推送进来的工作流有时默认停用）。
- `GIST_PAT` 是凭据：只存在 GitHub Secrets 里，不要写进代码、README 或任何聊天。
- 聚合的是公开免费源，节点质量参差、轮换快：只适合临时上网，不要过银行、主账号等敏感流量。
- 与上游同步：本地 `git remote add upstream https://github.com/wzdnzd/aggregator.git` 后
  `git fetch upstream && git merge upstream/main` 再 push。
