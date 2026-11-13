# PySAML2 IdP 代理规则设计：不放大认证强度的代理

适用版本：pysaml2 7.5.5（本仓库 `src/saml2`）。
目标：代理位于上游企业 IdP 与内部 SP 之间，转发认证结果但**不得让下游以为发生了一次新的、更强的认证**。

交付物：

- `proxy_design/proxy_policy.py`：纯策略模块（不碰签名、不做 XML 改写以外的 I/O）。
- `proxy_design/proxy_experiment.py`：单进程内存实验，真实 xmlsec1 签名/验签，比较直接转发与受限重签。
- `proxy_design/test_proxy_policy.py`：11 个纯策略单元测试。

---

## 1. 现状代码盘点（带调用点）

### 1.1 断言生成侧

| 关注点 | 位置 | 现状 |
|---|---|---|
| AuthnStatement 构造 | `src/saml2/assertion.py:642` `authn_statement()` | `authn_instant` 缺省时取 `instant()`（即“现在”），`session_index=sid()` 每次新建，`session_not_on_or_after` 仅透传参数 |
| AuthnContext 构造 | `src/saml2/assertion.py:596` `_authn_context_class_ref()` | `authn_auth` 被写成**单个** `AuthenticatingAuthority`，不支持链式追加 |
| Assertion 组装 | `src/saml2/assertion.py:753` `Assertion.construct()`，调用点 `src/saml2/server.py:402/414/425` `Server.setup_assertion()` | Conditions 来自 `Policy.conditions()`（`assertion.py:572`），只生成 NotBefore/NotOnOrAfter + 本 SP 的 AudienceRestriction |
| 响应签发入口 | `src/saml2/server.py:773` `Server.create_authn_response()` → `_authn_response()`（`server.py:439`）→ `Entity._response()`（`src/saml2/entity.py:687`） | `sign_assertion=True` 时在 `server.py:574` 用 `pre_signature_part(assertion.id, self.sec.my_cert, 2, ...)` 预置签名后由 `SecurityContext.sign_assertion()`（`sigver.py:1692`）调 xmlsec1 |
| ProxyRestriction 数据模型 | `src/saml2/saml.py:635` `ProxyRestrictionType_`（`Count` 为 `nonNegativeInteger`，序列化为字符串）、`saml.py:1257` 挂到 `ConditionsType_` | 模型可解析、可构造，`ConditionsType_.verify()`（`saml.py:1285`）只校验其基数 ≤1 |

关键事实：**库内没有任何生产代码构造或消费 `ProxyRestriction`**（`grep` 全 `src/` 仅命中 `saml.py` 的类定义与测试夹具 `tests/saml2_data.py:202`）。

### 1.2 响应校验侧

SP 侧入口 `src/saml2/client_base.py:759` `Saml2Client.parse_authn_request_response()` → `AuthnResponse`（`src/saml2/response.py:482`）：

1. 签名校验：`response.py:360` `correctly_signed_response()`（`sigver.py:1634`）；断言级签名在 `response.py:792` `self.sec.check_signature(...)`。
2. AuthnStatement：`response.py:555` `authn_statement_ok()` 只检查数量=1 与 `SessionNotOnOrAfter`（`response.py:565`，经 `validate.py:94 validate_on_or_after`）。
3. Conditions：`response.py:575` `condition_ok()` 检查时间窗（`response.py:599-602`）和 AudienceRestriction（`response.py:610` 调 `for_me()`，定义在 `response.py:207`）。
4. 认证信息暴露：`response.py:1042` `authn_info()` 返回 `(class_ref, [authn_auth...], authn_instant)` 三元组。

**安全缺口**：`condition_ok()` 与整个 `response.py`/`entity.py`/`client_base.py` 从不读取 `conditions.proxy_restriction`。一个 `Count="0"` 或带严格 Audience 的断言，PySAML2 默认会照常接受并允许再次代理。本设计把这部分强制执行放在代理服务的显式策略层（`proxy_policy.evaluate_proxy`），而不是假装库已经做了。

### 1.3 签名语义边界

`sigver.py:1519 SecurityContext.check_signature()` 验证的是“这份 XML 由持有对应私钥的实体签发且未被篡改”。它**不**对断言内容的授权含义做任何判断：验签通过不等于代理可以改 ClassRef、刷新 AuthnInstant 或延长有效期。策略模块因此与 `SecurityContext` 完全解耦，并要求“先验签、后决策”。

---

## 2. 五个字段的组合语义

设上游断言 `A0`，代理拟签发下游断言 `A1`。

### 2.1 AuthnInstant（`saml.py:1312`，必填）

- 语义：用户**在上游实际完成认证**的时刻，不是断言签发时刻。
- 规则：`A1.AuthnStatement.AuthnInstant = A0.AuthnInstant`，原样复制。禁止用 `assertion.py:667` 的默认 `instant()` 重新取值，否则下游会把一次旧认证误读为代理时刻的新认证（变相“刷新”认证年龄）。
- 若下游 SP 要求最大认证年龄（RequestedAuthnContext 的业务策略），应拿 `A0.AuthnInstant` 与其比较；不满足就拒绝，而不是重写时间戳。

### 2.2 AuthenticatingAuthority（`saml.py:759`、`saml.py:1033`）

- 语义：参与认证的权威实体链，顺序即认证路径。
- 规则（`proxy_policy.chain_authenticating_authorities()`）：保留 `A0` 链上去重后的全部条目，再把代理实体 ID 追加到末尾；原始 IdP 始终是第一项。
- 注意 `assertion.py:604-609` 的工厂只接受单个 `authn_auth`；代理路径必须直接操作 `AuthnContext.authenticating_authority` 列表，不能走该工厂。
- Issuer 与该链的分工：`A1.Issuer = 代理`（这是代理作出的新声明），而 `AuthenticatingAuthority` 说明“认证最初由谁完成、经过谁代理”。实验输出可见 `idp -> proxy` 的链。

### 2.3 SessionNotOnOrAfter（`saml.py:1314`，可选）

- 语义：上游会话的失效上限，独立于 Conditions 的断言有效期。
- 规则（`proxy_policy._assertion_expiry()` 取 `Conditions.NotOnOrAfter` 与所有 `SessionNotOnOrAfter` 的**最小值**作为硬天花板；`downstream_time_bounds()` 用 `min()` 钳制）：
  - `A1.SessionNotOnOrAfter <= A0.SessionNotOnOrAfter`；
  - `A1.Conditions.NotOnOrAfter <= A0.Conditions.NotOnOrAfter`；
  - 两者都不得超过聚合天花板。只能缩短，不能延长；`apply_proxy_constraints()` 对延长请求直接抛 `ProxyRuleError`。
- `authn_statement_ok()`（`response.py:565`）已会校验该字段，因此钳制后的值下游能正常验。

### 2.4 AudienceRestriction（`saml.py:916/1179`，校验点 `response.py:207 for_me`）

- 语义：断言被投递给谁。上游断言的受众是**代理**；直接转发给下游 SP 会因受众不匹配被 `for_me()` 拒绝（实验已复现：`direct-forward rejected by SP: AudienceRestriction not satisfied`）。
- 规则：重签时**追加**（不删除上游条目）一条下游 SP 的 `AudienceRestriction`。删除上游条目会抹掉断言来源约束，追加则同时保留来源与新目标。
- 这与 ProxyRestriction 内嵌的 Audience 是两套机制：前者限制“断言可被谁消费”，后者限制“下一跳代理可以是谁”。

### 2.5 ProxyRestriction（`saml.py:635/956`）

- `Count` 缺席：不限制代理次数 -> 代理**不得凭空发明**一个 Count（`next_proxy_restriction()` 返回 `None`）。
- `Count=n (n>=1)`：允许至多 n 个后续代理方。每重签一次，`A1.Count = n-1`。
- `Count=0`：明确禁止再代理 -> 决策 `DENY_COUNT_EXHAUSTED`，连“重签给非代理角色的 SP”都要按上游策略谨慎处理；本设计采取最保守解释，直接拒绝进入代理签发流程。
- 嵌套 `<Audience>`：下一跳实体必须在列表内，否则 `DENY_AUDIENCE_OUT_OF_SCOPE`；列表为空时 Count 是唯一约束。
- 决策顺序（短路）：Count -> 代理受众 -> 有效期 -> 强度可比性，见 `evaluate_proxy()`。

### 2.6 强度不可比较（AuthnContextClassRef）

- 代理不执行认证，因此没有资格“升级”强度。`proxy_policy.DEFAULT_STRENGTH_ORDER` 给出一张**显式、封闭**的等级表（PPT=20、TLSClient/X509=30、REFEDS MFA=50 等）。
- 仅当上游 ClassRef 与下游请求的 ClassRef 都在表内、且上游级别 >= 请求级别时才 `ALLOW`；任一不在表内或级别不足 -> `DENY_STRENGTH_INCOMPARABLE`。未知等级宁可拒绝也不猜测顺序。
- 重签时 `AuthnContextClassRef` 原样复制；实验验证 PPT 上游遇到 MFA 请求时被拒，且不会通过改写 ClassRef 蒙混。

---

## 3. 代理决策表

调用入口统一为 `proxy_policy.evaluate_proxy(verified_assertion, downstream_sp, requested_class, now_epoch)`。前置条件：断言已通过 `AuthnResponse`/`check_signature` 验签与时间窗校验。

| # | 上游 ProxyRestriction | 下游 SP | 请求强度 vs 上游 | 有效期 | 决策 | 下游断言动作 |
|---|---|---|---|---|---|---|
| 1 | Count=2，Audience 含 SP | 在范围内 | PPT 请求 / PPT 上游（可比，满足） | 未过期 | `ALLOW` | Count->1，追加 SP 受众，时间钳制，链入代理，ClassRef 与 AuthnInstant 不变 |
| 2 | Count=1，Audience 含 SP | 在范围内 | 可比且满足 | 未过期 | `ALLOW` | Count->0（下游不得再代理），其余同上 |
| 3 | **Count=0** | 任意 | 任意 | 任意 | `DENY_COUNT_EXHAUSTED` | 不签发；`apply_proxy_constraints` 抛 `ProxyRuleError` |
| 4 | Count=1，Audience=[SP-A] | **SP-B 不在列表** | 任意 | 任意 | `DENY_AUDIENCE_OUT_OF_SCOPE` | 不签发 |
| 5 | Count=1，Audience 含 SP | 在范围内 | **MFA 请求 / PPT 上游**（不可比/不足） | 任意 | `DENY_STRENGTH_INCOMPARABLE` | 不签发，禁止改写 ClassRef |
| 6 | Count=1，Audience 含 SP | 在范围内 | 可比 | **Conditions 或 Session 已过期** | `DENY_EXPIRED` | 不签发，禁止延长有效期 |
| 7 | Count 缺席（无次数限制），无 Audience | 任意 | 可比且满足 | 未过期 | `ALLOW` | 不新增 ProxyRestriction，其余钳制规则不变 |
| 8 | Count 缺席但 Audience=[SP-A] | SP-B | 可比 | 未过期 | `DENY_AUDIENCE_OUT_OF_SCOPE` | Audience 约束独立于 Count 生效 |

实验实际输出（场景 1-6 全覆盖，另含寿命延长护栏）见 `proxy_experiment.py` 运行结果。

---

## 4. 两种实施方案对比

### 方案 A：直接转发（relay 原始字节）

- 做法：代理仅做验签 + `evaluate_proxy`，把上游签名的 Assertion/Response 原样传给 SP。
- 优点：上游签名完整；AuthnInstant/ClassRef/AuthenticatingAuthority 天然不被篡改；实现最少。
- 硬伤（实验已验证）：断言 AudienceRestriction 指向代理，下游 SP 的 `for_me()`（`response.py:207`）直接拒绝；NameID/SubjectConfirmation Recipient、属性发布策略也都指向上游<->代理这一跳。仅适用于“代理与 SP 共享同一实体 ID/受众”这类特殊拓扑，不能作为通用方案。
- 即便转发，代理仍须执行决策表：例如 Count=0 时不得把消息继续投给另一个代理角色。

### 方案 B：受限重新签发（推荐的通用方案）

- 做法：代理验签后按 §2 规则构造 `A1` 并用自己的密钥重签（实验中 `SecurityContext.sign_assertion`，真实 xmlsec1）。
- 必须满足的不变量（实验以断言形式固化）：
  1. `A1.AuthnInstant == A0.AuthnInstant`；
  2. `A1.AuthnContextClassRef == A0.AuthnContextClassRef`（不升级、不降级伪造）；
  3. `A1` 的 AuthenticatingAuthority = 去重后的 `A0` 链 + 代理自身；
  4. `A1.Count = A0.Count - 1`（无 Count 则不添加）；
  5. `A1` 的两个 NotOnOrAfter 均 <= 上游聚合天花板；
  6. 追加而非替换 AudienceRestriction；
  7. 重签前移除上游 enveloped Signature 并用 `pre_signature_part(..., sec.my_cert)` 预置代理证书，否则 xmlsec1 会复用旧 KeyInfo（实验中实际踩到的坑：内嵌证书仍是上游证书，验签报 SIGNATURE 失败）。
- 代价：下游信任锚从上游 IdP 变为代理（需要在 SP 元数据中登记代理签名证书）；代理成为可问责的签发点，必须保留 `A0` 与决策日志以备审计。

### 实验观测对照（happy path，Count=1）

| 字段 | A 直接转发 | B 重签 |
|---|---|---|
| Issuer | 上游 IdP | 代理 |
| AuthnInstant | 上游登录时刻（保留） | 同一时刻（保留） |
| ClassRef | PPT | PPT（未升级） |
| AuthenticatingAuthority | `[idp]` | `[idp, proxy]` |
| Conditions NotOnOrAfter | 上游值 | 钳制到上游天花板（请求 1h，实际 <=15min） |
| SessionNotOnOrAfter | 上游值（更晚） | 被钳制到与 Conditions 天花板一致 |
| ProxyRestriction Count | 1 | 0 |
| 下游验签 | 签名有效但 AudienceRestriction 拒绝 | 代理签名有效，受众匹配，通过 |

---

## 5. 落地调用点建议（不实现完整代理服务）

在代理的 ACS 处理流程中按序插入：

1. **接收验签**：复用 `client_base.py:759 parse_authn_request_response()` 或单独 `SecurityContext.check_signature()`（`sigver.py:1519`）；验签失败立即终止，签名通过不作为后续改写的授权。
2. **策略决策**：调用 `proxy_policy.evaluate_proxy(ar.assertion, downstream_sp_entity_id, requested_authn_class)`；非 ALLOW 映射为 SAML `Responder` 错误响应（`samlp.STATUS_RESPONDER`）并记录审计日志。
3. **重签构造**：ALLOW 时调用 `apply_proxy_constraints()` + `downstream_time_bounds()`，再走现有 `Server.create_authn_response()`（`server.py:773`）的签名路径，或直接 `sec.sign_assertion()`；注意 §4-B 第 7 条的签名模板处理。
4. **下游交付前自检**：用代理自己的 verifier 跑一次 `check_signature` + `for_me`/`validate_on_or_after`（实验 `verify_downstream()`），确保发出的消息可被 SP 接受。
5. **可选的库内加固**：若希望 SP 侧也强制 ProxyRestriction，可在 `response.py:575 condition_ok()` 内 `for_me()` 之后新增对 `conditions.proxy_restriction` 的检查（Count 与本实体角色判定），但该改动影响面大，建议先以代理侧策略层上线，再按联邦策略推进库级校验。

## 6. 运行方式

```bash
# 纯策略单测（无需网络，秒级）
.venv/bin/python -m pytest proxy_design/test_proxy_policy.py -q

# 内存实验：真实 xmlsec1 签名/验签，含决策表与护栏
.venv/bin/python proxy_design/proxy_experiment.py
```

实验需要本机 `xmlsec1`（仓库测试同样依赖），代理测试证书在运行时于 `$TMPDIR` 临时生成，不写入仓库。
