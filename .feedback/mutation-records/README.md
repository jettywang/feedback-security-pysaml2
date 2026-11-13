# SubjectConfirmation 安全回归测试 — 变异验证记录

被测实现：`src/saml2/response.py` 的 `AuthnResponse.get_subject()`
（Bearer/HoK 的同候选约束绑定）与 `_holder_of_key_confirmed()`。
测试文件：`tests/test_95_subject_confirmation.py`（经真实响应入口
`Saml2Client.parse_authn_request_response`，保留 xmlsec1 签名与确认检查，不做 mock）。

变异只临时施加于应用源码，验证后全部还原；正式提交不包含任何应用源码改动
（`git diff -- src/` 为空）。每个变异的原始 pytest 输出保存在同目录的
`mutation-*.txt`。

## 变异 1：Recipient 约束 OR 化（跨候选借用）

改动（`get_subject`）：删除循环内逐候选的 Recipient 校验，循环结束后改为
“任一 SubjectConfirmation 的 Recipient 合法即通过”。这等于允许把 A 候选的
Recipient 与 B 候选的其它约束拼接。

变红测试（1）：
- `test_keyless_hok_cannot_borrow_bearer_constraints`

记录：`mutation-1-recipient-or.txt`（1 failed, 17 passed）

## 变异 2：Recipient 与候选完全解耦

改动（`get_subject`）：直接移除逐候选的
`if not _recip or not self.verify_recipient(_recip): raise VerificationError`，
任何候选都不再因 Recipient 失败。

变红测试（2）：
- `test_bearer_missing_recipient_binding_is_rejected`
- `test_keyless_hok_cannot_borrow_bearer_constraints`

记录：`mutation-2-recipient-detached.txt`（2 failed, 16 passed）

## 变异 3：HoK 不再要求 KeyInfo

改动（`_holder_of_key_confirmed`）：只要 `SubjectConfirmationData` 存在即返回
True，跳过对 ds:KeyInfo 扩展元素的检查。

变红测试（3）：
- `test_one_bad_candidate_does_not_poison_a_complete_candidate`
- `test_holder_of_key_without_key_info_is_rejected`
- `test_broken_bearers_cannot_block_or_fake_a_complete_hok`

记录：`mutation-3-hok-keyinfo-dropped.txt`（3 failed, 15 passed）

## 还原确认

三次变异后均用备份覆盖还原 `src/saml2/response.py`，最终
`tests/test_95_subject_confirmation.py` 全绿（18 passed），且
`git status` 中 `src/` 无改动。
