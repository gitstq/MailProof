# 🤝 贡献指南 / Contributing

感谢你愿意让 MailProof 变得更好！🎉 本项目遵循 **零运行时依赖**、**离线优先**、**纯标准库** 三条底线，任何 PR 都请保持这一点。

## 🚀 本地开发环境

```bash
git clone https://github.com/gitstq/MailProof.git
cd MailProof
python -m pip install -e ".[dev]"     # 开发依赖仅 pytest / build，运行时依赖为 0
make test                            # 或: python -m unittest discover -s tests -v
```

> 💡 无需虚拟环境也能跑：`PYTHONPATH=. python -m mailproof audit --demo`

## ✅ 提交前检查清单

- [ ] `python -m unittest discover -s tests -v` 全部通过
- [ ] `python scripts/build.py` 可成功构建 wheel
- [ ] 新增规则同步补充 `tests/` 中的用例，并说明对应的 RFC 条款
- [ ] 新增的 CLI 参数在三个语言版本的 README 中都有说明
- [ ] 代码不含任何第三方 `import`（标准库以外的依赖一律拒绝）
- [ ] 不引入任何网络请求（MailProof 永不联网）

## 🧩 新增一条审计规则

1. 在 `mailproof/rules.py` 用 `@rule(...)` 注册，ID 按分组递增：
   - `MP0xx` SPF、`MP1xx` DMARC、`MP2xx` DKIM、`MP3xx` 关联/传输、`MP4xx` 基线。
2. 规则函数签名固定为 `(ctx: AuditContext) -> List[Finding]`，必须是**纯函数**，不修改 ctx。
3. 给出 `title` / `severity` / `category` / `description` / `reference`（RFC 或厂商文档链接）。
4. `Finding` 里务必填写可执行的 `recommendation`（不要只写"请修复"）。
5. 在 `tests/test_rules.py` 增加一条针对该规则的断言。

## 📝 提交信息规范（Angular Commit Convention）

```
feat:      新增功能
fix:       修复问题
docs:      文档更新
refactor:  代码重构（不改变行为）
test:      测试新增/修改
perf:      性能优化
chore:     构建、CI、依赖等杂项
```

示例：

```bash
git commit -m "feat: 新增 BIMI 记录存在性检查规则 MP307"
git commit -m "fix: 修正 a/24 CIDR 机制的参数解析"
git commit -m "docs: 补充 English README 的 CI 集成章节"
```

## 🐛 报告问题

提交 Issue 时请附上：

1. MailProof 版本（`mailproof --version`）与 Python 版本；
2. 一份**脱敏后**的 DNS 快照（可把真实域名替换为 `example.com`）；
3. 复现命令与期望行为。

> ⚠️ 请不要在 Issue 中粘贴真实私钥、API Token 或未脱敏的生产 DNS 记录。

## 🌍 文档翻译

README 必须包含 **简体中文 / 繁体中文 / English** 三个版本。修改功能时请同步更新三份文档，拒绝机翻式表达，保持母语级可读性。

## 📄 许可证

贡献即表示你同意以 [MIT License](LICENSE) 发布你的代码。
