# PySAML2 多角色实体元数据密钥使用边界审查

- 审查对象：pysaml2 7.5.5（本仓库 `src/saml2/`，基线提交 `3bcd2ce`）
- 审查范围：单个 `EntityDescriptor` 同时含 `IDPSSODescriptor`、`SPSSODescriptor`、
  `AttributeAuthorityDescriptor`，且 `KeyDescriptor` 覆盖 `use="signing"`、
  `use="encryption"` 与未指定 `use` 三种情形时，从元数据加载、证书选择到验签调用的实际行为
- 配套实验：`security-review/experiment_cert_selection.py`（全程离线，密钥现场生成，
  仅端到端用例需要本机 `xmlsec1`）；pytest 包装见
  `security-review/test_experiment_cert_selection.py`
- 结论口径：每条结论标注 **已证实问题 / 明确安全 / 部署前提**，并附源码位置与实验编号（S1–S8）

---

## 1. 数据流总览

```
元数据 XML
  └─ InMemoryMetaData.parse()/MetaDataFile.load()/MetaDataExtern.load()
       └─ parse_and_check_signature()      mdstore.py:728   （元数据自身验签，可被静默跳过）
            └─ do_entity_descriptor()      mdstore.py:555   （to_dict 后按角色分桶存放）
                 └─ MetaData.certs(eid, descriptor, use)    mdstore.py:479   （唯一的证书选择函数）
                      ├─ sigver.SecurityContext._check_signature()  sigver.py:1355 → 1372  验签
                      ├─ request.Request._do_redirect_sig_check()   request.py:109-113     Redirect 验签
                      └─ entity.Entity._encrypt_assertion()         entity.py:647-661      加密选证书
```

三个生产调用点（`sigver.py:1372`、`request.py:111`、`entity.py:642` 与 `entity.py:661`）
**全部硬编码 `descriptor="any"`**，库内部不存在按消息所属角色（IdP/SP/AA）选择描述符的调用。

---

## 2. 元数据加载阶段

### 2.1 角色分桶是保留的，但只在数据结构层面

`do_entity_descriptor()` 把每个角色描述符分别存入
`spsso_descriptor / idpsso_descriptor / role_descriptor / authn_authority_descriptor /
attribute_authority_descriptor / pdp_descriptor`（角色清单见 `mdstore.py:573`）。
`certs()` 也支持传入具体角色名做作用域查询（`mdstore.py:510-512`）。
实验 S1a–S1c 证实：**显式指定角色时，选择结果严格限定在该角色描述符内**，IdP 的签名证书
不会从 `spsso` 查询中返回。这是库本身具备、但生产路径没有使用的能力。

### 2.2 元数据自身验签的静默放行（部署前提，P1）

`parse_and_check_signature()` 的前两道判断（`mdstore.py:731-735`）：

```python
if not self.cert:          # 未配置元数据签名证书
    return True
if not self.signed():      # 元数据本身没有签名
    return True
```

即：本地文件（`MetaDataFile.load → parse_and_check_signature`，`mdstore.py:793-795`）
与远程拉取（`MetaDataExtern.load`，`mdstore.py:862-870`；远程无 `cert` 时在
`mdstore.py:1068-1069` 被默认成空串）在“没配签名证书 / 元数据未签名”时都直接加载，
不会产生任何告警。此时元数据里的每一个 `KeyDescriptor` 都被当作可信锚点，
其可信性完全外推给传输通道（受控文件、TLS 等）。

配套的通道类默认值同样偏宽松：`verify_ssl_cert = False`（`config.py:186`）。
这不是 pysaml2 的代码缺陷，而是必须由部署方显式闭合的信任前提（见第 6 节）。

### 2.3 有效期检查只覆盖 EntityDescriptor 而不覆盖证书

`check_validity=True`（`MetadataStore.__init__` 默认值，`mdstore.py:1006`）只检查
`valid_until`（`mdstore.py:556-563`、`627-635`），与 `KeyDescriptor` 内证书的
`notBefore/notAfter` 无关。元数据路径上没有任何证书时效过滤（详见 4.3）。

### 2.4 重复 EntityID 的处理

同一元数据源内重复的 `entityID` 会被整条丢弃并向 stderr 打印
`Duplicated Entity descriptor`（`mdstore.py:566-568`）；不同源之间则按
`MetadataStore.metadata` 字典分别保存，查询时按源顺序返回首个命中。该行为与证书去重无关。

---

## 3. 证书选择函数 `MetaData.certs()`（`mdstore.py:479-514`）

### 3.1 `use` 过滤规则

核心判断在 `mdstore.py:493`：

```python
if "use" not in key or key_use == use:
```

- `use="signing"` 查询只收 `use="signing"` 与未指定 `use` 的 KeyDescriptor；
- `use="encryption"` 查询只收 `use="encryption"` 与未指定 `use"` 的 KeyDescriptor；
- 未指定 `use` 的 KeyDescriptor 对两类查询都可见（实验 S2a/S2b 证实）。

这与 SAML 2.0 元数据规范（saml-metadata-2.0-os §2.4.1.1，省略 `use` 即同时适用于
签名与加密）一致，属于**明确安全且符合规范**的组合，前提是部署方理解省略 `use`
意味着该密钥被授权用于两种用途。

### 3.2 已证实问题 P2：`descriptor="any"` 把所有角色汇成一个验证池

`mdstore.py:501-509` 的 `"any"` 分支按固定顺序
`spsso → idpsso → role → authn_authority → attribute_authority → pdp`
遍历**全部**角色描述符并 `extend` 到同一结果列表，不携带任何“该证书属于哪个角色”的标签。
实验 S1d/S1e 实测：三角色实体上 `any/signing` 返回 SP、IdP、AA 三个角色的签名证书，
`any/encryption` 同样跨角色汇总。由于三个生产调用点全部使用 `"any"`（第 1 节），
实际验签时不存在角色边界——见第 4 节端到端证据 S6。

说明：这不是“把签名证书和加密证书混成一个池”。`use` 维度仍被严格区分
（S8 证实加密专用证书不会进入验签路径）；被打破的是**角色维度**。

### 3.3 已证实问题 P3：去重判断失效，同指纹证书重复进入候选列表

`mdstore.py:496-497`：

```python
if cert not in res:
    res.append((key_name_txt, cert))
```

`res` 的元素是 `(key_name_txt, cert)` 二元组，而 membership 测试拿裸字符串 `cert`
比较，条件恒为 True。实验 S3a 证实：同一描述符内两个完全相同的 KeyDescriptor
产生 2 条候选；S3b 证实：同一证书在 IdP/SP/AA 三个角色各出现一次（IdP 内再重复一次）时，
`any/signing` 返回 4 条记录、仅 1 个不同指纹。

影响：
- 正确性/可用性：`_check_signature` 对每个候选都生成临时 PEM 并调用一次 `xmlsec1`
  （`sigver.py:1494-1509`），重复指纹意味着重复的进程派生与临时文件；
  Redirect 验签的 `any(...)` 也会重复尝试（`request.py:113`）。
- 安全审计：候选列表长度不再能反映不同信任锚数量，监控/日志中难以区分“多密钥轮换”
  与“同一密钥重复粘贴”。

### 3.4 已证实问题 P4（健壮性）：缺少 X509Data 的 KeyInfo 触发 KeyError

`mdstore.py:494` 直接下标访问 `key_info["x509_data"]`，而 `key_info` 是
`key.get("key_info") or {}`（`mdstore.py:490`）。仅含 `KeyName` 的合法 KeyDescriptor
会让 `certs()` 直接抛出 `KeyError: 'x509_data'`（已离线复现，且因为遍历在
`extract_certs` 内部，第一个 KeyDescriptor 缺字段就会中断整个实体的证书枚举，
后续正常证书也无法返回）。

下游影响分两种，已分别验证：

- 直接调用方（如 `request.py:111` 的 Redirect 验签、`entity.py:642/661` 的加密选证）
  不捕获该异常，恶意构造的元数据可把对应消息处理打成 500/失败，构成拒绝服务面。
- `_check_signature` 路径上，`sigver.py:1373-1374` 的 `except KeyError`
  本意是兜底“issuer 未知”，但会**连带吞掉**这个来自 `certs()` 内部的 KeyError，
  把候选静默置空后改抛 `MissingKey`（实验 S9）。即错误被掩盖成“没有配置证书”，
  运维侧拿到的失败原因与真实原因不符，排障与告警会被误导。

---

## 4. 验签调用阶段

### 4.1 元数据优先、消息内嵌证书默认不被信任（明确安全）

`_check_signature`（`sigver.py:1355`）首先按 issuer 从元数据取证书
（`sigver.py:1370-1383`）；只有当元数据没有候选 **且**
`only_use_keys_in_metadata=False` 时才回退到消息自带 KeyInfo
（`sigver.py:1387-1392`）。该开关默认 `True`（`config.py:196`）。
实验 S6-neg 证实：用任何角色描述符中都不存在的密钥签名，在默认配置下被拒绝
（最终走 `MissingKey`，`sigver.py:1396-1397`）。

### 4.2 已证实问题 P2 的端到端证据：AA 密钥可验证任意角色消息（S6）

实验用仅出现在 `AttributeAuthorityDescriptor` 的密钥对一个 `samlp:Response`
（内含签名 Assertion）做真实 xmlsec1 签名，再以默认 `only_use_keys_in_metadata=True`
调用 `SecurityContext._check_signature()`。结果验签通过：候选池按
`spsso → idpsso → attribute_authority` 顺序尝试，前两个证书失败后第三个（AA）成功
（循环逻辑 `sigver.py:1494-1509`，成功即 `break`）。

含义：只要多角色实体中任一角色的签名密钥泄露或被滥用，攻击者就能以该实体的名义
伪造该实体名下**任何角色**的协议消息（IdP 响应、SP 的 AuthnRequest/Logout、
AA 的 AttributeQuery 响应等），接收方无法从验证路径上区分签名密钥被授权的角色。
缓解依赖部署方为不同角色使用不同密钥并分别保管（第 6 节），代码层面不强制。

Redirect 绑定同样如此：`_do_redirect_sig_check()` 直接对 `any/signing` 全池做
`any(verify_redirect_signature(...))`（`request.py:111-113`），无角色参数。

### 4.3 已证实问题 P5：元数据证书默认不做有效期/链校验

- 选择层：`certs()` 不调用 `active_cert()`。对比之下，消息内嵌证书路径
  `cert_from_key_info()` 默认带时效检查（`sigver.py:403`，
  `active_cert` 定义于 `sigver.py:366-384`），但元数据路径完全绕过它。
  实验 S5：一个已过期证书与一个有效证书并存时，`any/signing` 仍返回 2 个候选，
  xmlsec1 只验证“签名数学上是否成立”，过期证书同样可以通过。
- 验签后的证书校验：`sigver.py:1511-1513` 仅在 `verified or only_valid_cert` 时调用
  `CertHandler.verify_cert()`；而 `CertHandler` 的 `_verify_cert` 只有在
  `validate_certificate is True` 时才启用（`sigver.py:1088-1095`、`1125-1138`），
  配置默认 `None`（`config.py:224`，文档 `docs/howto/config.rst` 亦写明默认 False）。
  默认部署中 `verify_cert()` 直接 `return True`。
- IdP 侧 `want_authn_requests_only_with_valid_cert` 默认 false
  （`metadata.py:50`、`entity.py:1025-1028`），需要显式开启才会要求 AuthnRequest
  证书有效。

### 4.4 已证实安全的组合

| 组合 | 证据 |
| --- | --- |
| 指定具体角色描述符查询时，结果严格限定该角色 | S1a/S1b/S1c；`mdstore.py:510-512` |
| `use="encryption"` 的 KeyDescriptor 永远不进入签名验证池 | S8；`mdstore.py:493`，空池时 `sigver.py:1396` 抛 `MissingKey` |
| 省略 `use` 的 KeyDescriptor 对签名/加密两类查询都可见（符合规范） | S2a/S2b |
| 默认配置下消息内嵌、元数据中不存在的证书无法通过验签 | S6-neg；`sigver.py:1387`、`config.py:196` |
| 轮换重叠期新旧两枚有效签名证书同时保留、按元数据顺序尝试 | S4；`mdstore.py:485-499` + `sigver.py:1494-1504` |

### 4.5 密钥轮换重叠期（无需改动，仅确认行为）

多枚 `use="signing"` KeyDescriptor 会全部保留（S4），验签按列表顺序逐一尝试、
首个成功者通过（`sigver.py:1494-1504`）。因此“旧证书签名的在途消息 + 新证书签名的
新消息”在重叠期内都能验证，轮换功能本身可用。需要注意两点既有行为：
其一，列表顺序即 XML 中 KeyDescriptor 的文档顺序，库不做新旧排序；
其二，P3 的去重失效会让“新旧证书 + 同证书重复”场景产生更多无效 xmlsec1 调用，
但不改变最终验证结论。本审查不重做轮换机制。

### 4.6 加密方向的对应行为

`Entity._encrypt_assertion()` 在未显式传入 `encrypt_cert` 时同样以
`any/encryption` 跨角色取证书（`entity.py:658-661`；`has_encrypt_cert_in_metadata`
在 `entity.py:642`），并按顺序尝试加密、首个成功即返回（`entity.py:663-681`）。
即加密证书选择同样没有角色边界：IdP 可能选用同实体 SP 角色的加密证书加密 Assertion。
是否构成问题取决于部署拓扑，但与验签侧是同一根因（P2），且加密侧不存在
`only_use_keys_in_metadata` 式的回退开关，候选完全来自元数据。

---

## 5. 问题清单（按严重度）

| 编号 | 结论 | 位置 | 实验 |
| --- | --- | --- | --- |
| P1 | 未配置元数据签名证书/元数据未签名时静默加载，全部 KeyDescriptor 直接成为信任锚；TLS 校验默认关闭 | `mdstore.py:731-735`、`mdstore.py:1068-1069`、`config.py:186` | S7 |
| P2 | 三个生产调用点硬编码 `descriptor="any"`，角色维度无边界，AA/SP 密钥可验证任意角色消息 | `mdstore.py:501-509`、`sigver.py:1372`、`request.py:111`、`entity.py:642,661` | S1d/S1e/S6 |
| P3 | 去重条件比较类型不一致（字符串 vs 二元组），同指纹证书重复进入候选，放大 xmlsec1 调用并污染审计口径 | `mdstore.py:496-497` | S3a/S3b |
| P4 | 无 X509Data 的 KeyInfo 导致 `certs()` 抛 KeyError 并中断整实体证书枚举；直接调用方 DoS，验签路径被 `except KeyError` 误吞成 MissingKey | `mdstore.py:490,494`、`sigver.py:1373-1374`、`request.py:111` | S9 |
| P5 | 元数据证书默认无 notBefore/notAfter 过滤、无证书链校验，过期/自签证书可通过验签 | `mdstore.py:479-514`、`sigver.py:1511-1513`、`sigver.py:1095,1125-1138`、`config.py:224` | S5 |

---

## 6. 仍需部署方提供的信任材料与配置前提

pysaml2 无法自行推断下列材料，部署多角色实体前必须显式提供：

1. **元数据信任锚**：对远程/联邦元数据，在 metadata 配置中提供签发该元数据的
   签名证书（`MetaDataExtern`/MDQ 的 `cert` 参数，经 `imp()` 二元组第二项传入，
   `mdstore.py:1162-1163`），使 `parse_and_check_signature` 真正进入验签分支
   （`mdstore.py:737-773`）；对本地文件，保证文件分发通道本身的完整性。
2. **传输层信任**：远程元数据场景显式配置 CA  bundle 并开启证书校验
   （不要依赖 `verify_ssl_cert=False` 默认值，`config.py:186`）。
3. **角色密钥分权**：若要求角色边界，需为 IdP、SP、AA 分别签发独立证书并在元数据中
   分角色发布，同时在本地保管层面隔离对应私钥；库的 `any` 池不会替你做这层隔离。
   注意：仅在元数据里分角色放证书并不够，因为验证路径仍跨角色取证书（P2）。
4. **证书有效性策略**：需要时效/链校验时显式开启 `validate_certificate`
   （`config.py:224` → `sigver.py:1236`），IdP 侧按需开启
   `want_authn_requests_only_with_valid_cert`，并提供 `CertHandler` 所需的 CA 材料
   （`cert_file`/`key_file` 或 `cert_handler_extra_class`，`sigver.py:1125-1138`）。
5. **轮换计划**：重叠期内同时发布新旧两枚签名 KeyDescriptor，并在切换窗口结束后
   及时移除旧证书；元数据 `validUntil`/`cacheDuration` 的刷新周期要短于轮换窗口。

本审查**不建议**也未采用“把所有角色的证书汇成一个全局信任池”作为修复方向；
正确方向是让调用点按消息实际角色传入具体 descriptor（库已支持该参数），
并分别修复 P3–P5 的选择层缺陷。这些代码修改超出本次审查范围，本文仅给出
经实验证实的行为基线与部署约束。

---

## 7. 复现方式

```bash
# 独立运行（退出码 1 表示存在已证实问题，输出含逐项结论）
.venv/bin/python security-review/experiment_cert_selection.py

# 纳入 pytest（16 项，端到端用例调用本机 xmlsec1，无任何网络访问）
.venv/bin/python -m pytest security-review/ -q
```

实验生成的全部 RSA 密钥与自签证书仅存在于进程内存与 `$TMPDIR` 临时文件中，
不读取 `tests/keys` 等固定素材，指纹每次运行变化，结论不依赖特定密钥数据。
