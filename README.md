# dependency-metadata-review

面向 Java/JVM 合并请求的依赖校验元数据审查 CLI。它解析并语义化对比 Gradle
`gradle/verification-metadata.xml`，把“正常版本升级产生的几百行哈希变化”和
“同一版本偷改哈希/来源/签名信任”区分开，并向 Maven Central、内部 Maven 仓库核对
checksum 与 PGP 签名。

> 典型攻击：MR 名义上只改业务代码，却在几千行校验元数据中把某个**未升版本**构件的
> SHA-256 和来源地址一起改成后门构件。普通评审很难发现。

## 它检查什么

- 语义级 diff，而不是逐行噪声：
  - `group:artifact:version` 新增、删除、版本升级/降级；
  - 按 artifact 文件名、classifier、extension 配对新旧版本；
  - 同一 GAV 下 hash 被替换；
  - source/repository URL、URL 形式的 `origin/reason` 被增删改；
  - PGP fingerprint/pin 变化；
  - Gradle `<also-trust>` 多哈希新增/删除；
  - 弱算法、哈希长度错误、短 PGP ID。
- 安全策略降级：
  - `verify-metadata=false` / `verify-signatures=false`；
  - 新增 `<ignored-key>`；
  - 新增 `<trusted-artifacts><trust ...>`，尤其是 `name=".*"`、`regex="true"`；
  - 新增 regex 范围的 trusted key。
- 外部核对：
  - Maven 标准布局下的 `.sha1/.sha256/.sha512`；
  - sidecar 缺少目标算法时，可下载构件并本地计算摘要；
  - 支持 `also-trust` 多值，任一授权摘要匹配即可；
  - 通过本机 `gpg` 校验 `.asc`，并与配置或 base 分支已有 fingerprint pin 对比；
  - 支持 Maven Central、公共镜像、`file://` 本地仓库和带环境变量凭证的内部仓库。
- MR 降噪：
  - 正常升级的多个 artifact 折叠为 “Verified upgrade artifacts”；
  - 相同 `group:artifact` 的旧/新版本自动配对；
  - JSON 报告包含稳定 finding ID，可用于去重 MR 评论；
  - Markdown 报告可直接写入 PR comment 或 GitHub Step Summary。

## 快速体验

要求 JDK 17+。仓库自带一个离线 fixture：

- `com.acme:widget-lib:1.4.0 -> 1.5.0`：正常升级，checksum 与本地 Maven 仓库一致；
- `com.internal:billing-client:2.9.0 -> 3.0.0`：内部库升级，匹配内部仓库；
- `com.acme:auth-core:2.1.0`：版本不变，hash 和 source host 同时改成未授权地址，
  且新 hash 与官方仓库不一致，应判为 `CRITICAL`。

```bash
./gradlew installDist

./build/install/dependency-metadata-review/bin/dependency-metadata-review \
  --base test-fixtures/before/gradle/verification-metadata.xml \
  --head test-fixtures/after/gradle/verification-metadata.xml \
  --build-patch test-fixtures/build-change.patch \
  --config config/demo-offline.properties \
  --format markdown
```

工具会以退出码 `1` 失败，因为 fixture 中存在 CRITICAL。生成 JSON：

```bash
./build/install/dependency-metadata-review/bin/dependency-metadata-review \
  --base test-fixtures/before/gradle/verification-metadata.xml \
  --head test-fixtures/after/gradle/verification-metadata.xml \
  --build-patch test-fixtures/build-change.patch \
  --config config/demo-offline.properties \
  --format json \
  --output build/review.json
```

运行测试：

```bash
./gradlew test
```

## 命令行

```text
--base <file>             base 分支的 verification-metadata.xml（必需）
--head <file>             MR/head 分支的 verification-metadata.xml（必需）
--metadata-patch <file>   元数据文件 unified diff，用于检查信任策略降级
--build-patch <file>      build.gradle/pom.xml/libs.versions.toml 的 diff，可重复
--config <file>           properties 配置
--format markdown|json    默认 markdown
--output <file>           输出文件，否则 stdout
--fail-on <gate>          INFO/LOW/MEDIUM/HIGH/CRITICAL/NONE
--offline                 只做 diff/策略检查，不访问仓库
```

退出码：

- `0`：没有达到 gate 的 finding；
- `1`：存在阻断 finding；
- `2`：参数或配置错误；
- `3`：IO/验证执行错误。

## 推荐判定规则

| 场景 | 默认级别 | 说明 |
|---|---:|---|
| 同版本 hash 改变，且与官方/授权仓库不一致 | CRITICAL | 高度疑似后门或元数据被篡改 |
| 新 source host 不在允许列表 | CRITICAL | 可能指向 typosquat/恶意同名库 |
| checksum mismatch | CRITICAL | 不应合并，必须离线核实 |
| PGP 签名无效 | CRITICAL | 签名与构件不匹配 |
| 关闭 metadata/signature verification | CRITICAL | 安全开关被降级 |
| 宽泛 `.*` trusted-artifact 规则 | CRITICAL | 可能绕过全部依赖校验 |
| 同版本 hash 改变，但新 hash 匹配 Central | HIGH | 可能是元数据修正/重发布，仍需人工确认 |
| PGP 有效但 fingerprint 未固定 | HIGH | 任何人都能生成可信 UID 的 key |
| 公共坐标只匹配非公共仓库且无变体策略 | HIGH | 可能是内部重打包，也可能是来源替换 |
| 内部坐标在内部仓库不可达/凭证失败 | HIGH | fail closed，检查 CI 凭证后重跑 |
| 内部坐标在所有仓库均 404 | MEDIUM | 可能是未配置内部仓库，转人工/内部源核对 |
| 正常版本升级且 checksum 匹配授权仓库 | 不产生阻断 finding | 计入 verified upgrades |

## 内部库与“同版本不同产物”

这是本工具刻意避免误报的地方：

1. `internalGroupPrefixes=com.example,...` 中的坐标在 Maven Central 404 时不会被
   直接判为恶意，而是提示“内部坐标，需要内部仓库或人工确认”。
2. 配置内部 Maven 仓库后，工具会用内部仓库的 `.sha256` 或下载构件计算摘要。
3. 同一版本在 Central 和内部仓库可能有合法的不同构建产物。请为窄范围
   `group:artifact` 添加带 reason 的策略：

```properties
repositories=central,internal
repo.internal.url=https://nexus.example.com/repository/maven-public/
repo.internal.internal=true
repo.internal.usernameEnv=NEXUS_USERNAME
repo.internal.passwordEnv=NEXUS_PASSWORD

internalGroupPrefixes=com.example

policy.repackaged.coordinate=com.example:repackaged-client
policy.repackaged.allowRepositorySpecificArtifact=true
policy.repackaged.allowedRepositories=internal
policy.repackaged.trustedFingerprints=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
policy.repackaged.reason=Internal reproducible rebuild; timestamps stripped
```

如果元数据使用 Gradle 的 `<also-trust value="..."/>` 记录多个合法摘要，工具会把它们
作为同一算法的候选值：仓库摘要等于主值或任一 `also-trust` 值都算匹配。

## PGP 签名

配置示例：

```properties
signature.mode=ALL
gpg.executable=gpg

# 推荐使用从 gradle/verification-keyring.keys 导出的独立 keyring
gpg.keyring=.ci/trusted.kbx
trustedPgpFingerprints=YOUR_40_HEX_FINGERPRINT,...
```

如果没有配置 keyring，工具会尝试通过 `keys.openpgp.org` 按元数据中的 key ID/fingerprint
拉取公钥到临时 `GNUPGHOME`，再调用 GPG 验证 `.asc`。请注意：

- “签名有效”只说明持有对应私钥者签了该构件；
- UID 可以任意伪造，信任必须来自固定 fingerprint、项目官方 `KEYS` 文件或组织 keyring；
- 工具只把 **base 分支已有** 的 trusted key 和配置中的 fingerprint 当作预存信任，
  不会因为 MR 新增了一个 `<trusted-key>` 就自动信任它。

## MR/CI 集成

仓库包含 GitHub Actions 示例：
`.github/workflows/dependency-metadata-review.yml`。它会：

1. 取出 PR base/head；
2. 生成元数据和构建文件 diff；
3. 编译并安装 CLI；
4. 输出 Markdown 到 `GITHUB_STEP_SUMMARY`；
5. 有 HIGH/CRITICAL finding 时让步骤失败。

GitLab/Jenkins 同理，核心命令是：

```bash
git diff "$BASE...$HEAD" -- gradle/verification-metadata.xml > metadata.patch
git show "$BASE:gradle/verification-metadata.xml" > base.xml

./gradlew installDist
./build/install/dependency-metadata-review/bin/dependency-metadata-review \
  --base base.xml \
  --head gradle/verification-metadata.xml \
  --metadata-patch metadata.patch \
  --build-patch build-files.patch \
  --config .ci/dependency-review.properties \
  --format markdown \
  --output dependency-review.md
```

可以把 Markdown 作为 PR/MR comment；JSON 中的稳定 `id` 可用于更新同一条评论，而不是
每次推送追加新评论。

## 安全边界

- Maven checksum sidecar 和构件来自同一个仓库/传输通道时，checksum 主要证明传输一致性；
  若仓库本身被攻陷，攻击者也能同时替换 sidecar。高安全等级应启用 PGP 并用带外 fingerprint。
- 标准 Gradle `verification-metadata.xml` XSD **没有** artifact/source URL 字段；来源通常
  只能从 settings/build 仓库配置推断，或写在自由文本 `origin/reason` 中。本工具支持自定义
  `<source url="..."/>`、`sourceUrl` 属性以及 URL 形式的 `origin/reason`，但不会把
  `origin="Generated by Gradle"` 当作人工审计证明。
- 匹配内部仓库不等于绝对可信；内部仓库凭据、权限和 key 管理仍是信任根。
- 该工具不执行下载的构件，也不从下载目录加载代码；PGP 验证仅让 GPG 只读读取签名和构件。

## 代码结构

```text
com.example.depreview
├── cli/       参数解析与退出码
├── config/    properties 配置、仓库和窄策略
├── gradle/    XXE-hardened SAX parser
├── diff/      语义 diff、版本配对、构建文件关联
├── verify/    Maven 布局、HTTP/file transport、checksum、GPG
├── analyze/   风险判定与信任策略 diff
└── report/    Markdown/JSON 输出
```

## 后续可增强

- 直接读取 `settings.gradle(.kts)` 的仓库列表和凭证/镜像映射；
- GitLab MR discussion API 去重评论；
- SARIF 输出；
- 对 `verification-keyring.keys` 的 diff 做 fingerprint/撤销检查；
- 缓存公共仓库 checksum/PGP 结果，进一步加速几百条记录的 MR；
- 支持 Maven 自定义 checksum metadata 或公司内部 JSON/YAML 格式的适配器。
