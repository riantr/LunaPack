# LunaPack 发布资产 CI-only 设置清单

**目标**：Release 资产只能由 CI 上传；任何人从本机 `gh release upload` 或网页上传的文件都会被 workflow 校验拦下。

**适用仓库**：`riantr/LunaPack`
**对应 workflow**：`.github/workflows/release.yml`、`.github/workflows/release-audit.yml`
**对应 README**：Releases → CI-only release assets

下面只列需要你在 **GitHub 设置页面** 操作的 5 步，沿用 README 原编号 **0 / 1 / 2 / 4 / 5**。第 3 步（发布 job 用 App token）和第 6 步（digest / uploader 校验）已经写进 workflow，不用你填。

**填写约定**：把 `<...>` 换成实际值，完成后把 `- [ ]` 改成 `- [x]`。

---

## 第 0 步 — 核查当前基线（只读，不改设置）

- [ ] 打开发布页：<https://github.com/riantr/LunaPack/releases/tag/v0.1.31>
- [ ] 本地执行：

  ```bash
  gh api repos/riantr/LunaPack/releases/tags/v0.1.31 \
    --jq '.assets[] | [.name, .uploader.login] | @tsv'
  ```

- [ ] 确认 8 个资产的 uploader 全是 `github-actions[bot]`

记录：资产数 ______ / 8 ｜ 异常上传者：____________________

> 若发现任何人类账号上传的资产，先在那条 release 上手工删除它，再继续。

---

## 第 1 步 — 收紧人类写权限

路径：仓库 → **Settings** → **Collaborators and teams**

- [ ] 列出当前有 Write / Maintain / Admin 的人与团队：

  ```
  ______________________________________________
  ```

- [ ] 把日常开发者改成 **Read** 或 **Triage**：

  ```
  ______________________________________________
  ```

- [ ] 保留一个最小发布身份用于推 `v*` tag（第 5 步要用）：

  ```
  ______________________________________________
  ```

- [ ] 确认没有遗留的 PAT / token 还持有 `Contents: write`

### 必须知道的边界

**仓库 owner 无法把自己降到 Read**，owner 永远有写权限。所以：

- 如果 `riantr` 是个人账号且你是 owner，**没有任何 GitHub 开关能阻止你本人手动上传**。实际防线是：写权限集中在极少数身份 + workflow 发布校验 + 每日审计，人工上传会立刻变红并被发现。
- 要做到连 owner 也硬阻断，需要把仓库迁到 **组织**，让 owner 角色由组织持有，个人账号只保留 Read/Triage，发布完全交给第 2 步的 App。

---

## 第 2 步 — 创建发布专用 GitHub App

创建入口：<https://github.com/settings/apps/new>
（组织仓库则为：组织 Settings → Developer settings → GitHub Apps → New GitHub App）

### 基础信息

| 字段 | 填写值 |
| --- | --- |
| GitHub App name | `<app-name>`，建议 `lunapack-release`：____________________ |
| Homepage URL | `https://github.com/riantr/LunaPack` |
| Webhook URL | 留空，并取消勾选 **Active** |
| Where can this GitHub App be installed? | **Only on this account** |

### 权限（Repository permissions）

| 权限 | 取值 |
| --- | --- |
| Metadata | Read-only（默认强制） |
| Contents | **Read & write** |
| 其余所有权限 | No access |

### 生成凭据

- [ ] 创建后复制 **Client ID**（以 `Iv1.` 开头）：`____________________`

  > ⚠️ 必须是 **Client ID**，不是纯数字的 App ID。workflow 里的变量 `RELEASE_APP_CLIENT_ID` 传给的是 `client-id` 参数，填错会在铸造 token 时失败。

- [ ] 点 **Generate a private key**，下载 `.pem` 文件，全文保留（含 `-----BEGIN RSA PRIVATE KEY-----` 与 `-----END RSA PRIVATE KEY-----`），填入第 4 步的 secret
- [ ] bot 登录名 = `<app-name>[bot]`，例如 `lunapack-release[bot]`：`____________________`

### 安装

- [ ] **Install App** → **Only select repositories** → 只勾选 `riantr/LunaPack`
- [ ] 在仓库 Installed GitHub Apps 列表中确认可见

---

## 第 4 步 — 创建 release environment

路径：仓库 → **Settings** → **Environments** → **New environment**

| 配置项 | 填写值 |
| --- | --- |
| Name | `release` |
| Environment variable → Name | `RELEASE_APP_CLIENT_ID` |
| Environment variable → Value | `<第 2 步 Client ID>` |
| Environment secret → Name | `RELEASE_APP_PRIVATE_KEY` |
| Environment secret → Value | `<第 2 步 .pem 全文>` |
| Required reviewers | 勾选，选 1–2 名审批人：____________________ |
| Deployment branches and tags | Selected branches and tags → 添加 `v*` |

- [ ] 以上全部填完并保存

> 注意：给环境加 `v*` tag 限制后，从 Actions 页面用 `workflow_dispatch` 手动触发的发布可能被环境规则拦截（dispatch 的 ref 是默认分支）。日常请通过推 `v*` tag 触发。

### 另一个变量要放仓库级（不是 environment）

路径：仓库 → **Settings** → **Secrets and variables** → **Actions** → **Variables** → **New repository variable**

| 配置项 | 填写值 |
| --- | --- |
| Name | `RELEASE_APP_LOGIN` |
| Value | `<第 2 步 bot 登录名>`，例如 `lunapack-release[bot]` |

- [ ] 已添加。每日审计 workflow 用只读 token 读取它，不需要 App 私钥，所以不能放进带审批的 `release` 环境。

---

## 第 5 步 — 添加 v* tag ruleset

路径：仓库 → **Settings** → **Rules** → **Rulesets** → **New ruleset** → **New tag ruleset**

| 配置项 | 填写值 |
| --- | --- |
| Ruleset name | `Protect release tags`（或自定义）：____________________ |
| Target patterns | `v*` |
| Enforcement | Active |
| Rules | 勾选可用的限制项，至少 **Restrict deletions** 和 **Block force pushes** |
| Bypass list | 只选第 1 步保留的发布身份：____________________ |

- [ ] 规则已启用

> 这一步管的是"谁能创建 / 删除 tag"，不是 asset 上传。asset 的防线是 workflow 发布校验 + 每日审计。

---

## 完成后自检

- [ ] 推一个测试 `v*` tag，观察 release job 日志出现：

  ```
  Verified N assets: digest, size and uploader (<app-name>[bot]) all match
  ```

- [ ] 次日上午查看 Actions 中的 **Audit release assets**，应为绿色并输出：

  ```
  Audited 8 assets on vX.Y.Z: all uploaded by <app-name>[bot]
  ```

- [ ] 故意从本机试一次 `gh release upload vX.Y.Z somefile --clobber`（**仅在你拥有写权限时**）：
  - 若上传成功，审计应在下一次运行时变红 → 说明检测有效
  - 记得立即删除该资产并重跑 release workflow

## 常见失败与修复

| 现象 | 原因 / 修复 |
| --- | --- |
| `release automation is not configured` | 第 4 步的 Client ID 或私钥没填，或填在了错误的 environment |
| 铸造 token 失败 | Client ID 填成了 App ID；或 App 未安装到该仓库；或 App 权限不足 |
| `was uploaded by ... expected ...` | 有人手动上传了资产。删除该资产后重跑 release workflow |
| 审计 workflow 报未配置 | 仓库级变量 `RELEASE_APP_LOGIN` 缺失 |
| `workflow_dispatch` 的 release job 被环境拦住 | 环境限制了 `v*`，改用推 tag 触发 |
