# ⚡ Web3 Gas & Calldata Security Inspector (出海 Micro-SaaS 资产)

[English](#english) | [中文说明](#chinese)

---

<a name="english"></a>
## English Description

**Web3 Gas & Calldata Security Inspector** is a lightweight, zero-dependency, serverless EVM utility designed for Web3 traders, smart contract developers, and security auditors.

### 🌟 Key Features
1. **Zero-Server Operational Cost**: Pure client-side parsing + optional lightweight Python engine. Zero monthly hosting overhead (runs on Vercel, Cloudflare Pages, or GitHub Pages).
2. **EIP-2028 Gas Accuracy**: Calculates intrinsic gas for zero bytes (4 gas) and non-zero bytes (16 gas) with multi-chain pricing presets (BNB Smart Chain, Ethereum, Polygon, Arbitrum).
3. **Automated Security Risk Heuristics**:
   - Detects unlimited token allowances (`MAX_UINT256`).
   - Detects phishing signatures such as unverified off-chain `permit` calls (EIP-2612).
4. **Built-in Monetization & Crypto Tipjar**:
   - Integrates BEP20 donation address `0x322f38636bf6fa64d07af5f481bcb63bc3828731` for community support and decentralized sponsorships.

### 🚀 Quick Start
```bash
# Run unit tests
python test_inspector.py

# Launch local dashboard
python run_local.py
# Open http://localhost:8089 in your browser
```

---

<a name="chinese"></a>
## 中文说明

**Web3 交易 Gas 估算与 Calldata 逆向安全审计工具** 是面向出海开发者与 Web3 交易员打造的轻量级无服务器资产。

### 🌟 核心价值与商业模式
1. **零服务器维护成本**：纯前端 + 轻量 Python 双模运行，可直接挂载于 GitHub Pages、Vercel 等免费静态托管平台，不产生任何云服务器账单。
2. **EIP-2028 真实 Gas 精确测算**：精准计算零字节（4 gas/字节）与非零字节（16 gas/字节），支持 BSC、以太坊、Polygon、Arbitrum 实时估值。
3. **链上安全防钓鱼检测**：
   - 自动甄别无限授权风险（`MAX_UINT256 Approve`），防止钱包余额被清空。
   - 自动预警离线 `permit` 签名钓鱼（EIP-2612），保障链上资金安全。
4. **去中心化收款与打赏管道**：
   - 页面已深度内置老板专属 BSC (BEP20) 钱包地址 `0x322f38636bf6fa64d07af5f481bcb63bc3828731`，支持赞助与 Pro 功能打赏。

### 📁 项目结构
- `core_inspector.py`: EVM 字节码反编译与 Gas 算法核心模块
- `test_inspector.py`: 100% 通过的严密自动化回归测试套件 (6/6 Pass)
- `index.html`: 现代化 Web3 赛博暗黑风格独立交互界面
- `run_local.py`: 本地一键启动轻量 Web 服务器
