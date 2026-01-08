# 🚀 上传到 GitHub - 简易指南

## 方法 1: 使用自动化脚本 (推荐)

```bash
cd /home/biubiuboy/xray-lite
./upload_to_github.sh
```

脚本会引导你完成所有步骤！

---

## 方法 2: 手动上传

### 步骤 1: 在 GitHub 创建新仓库

1. 访问: https://github.com/new
2. 填写信息:
   - **Repository name**: `xray-lite`
   - **Description**: `Lightweight Xray implementation in Rust with Reality and XHTTP support`
   - **Visibility**: Public
   - **不要**勾选任何初始化选项
3. 点击 "Create repository"

### 步骤 2: 上传代码

#### 使用 HTTPS (简单)

```bash
cd /home/biubiuboy/xray-lite

# 添加远程仓库 (替换 YOUR_USERNAME)
git remote add origin https://github.com/YOUR_USERNAME/xray-lite.git

# 推送代码
git branch -M main
git push -u origin main
```

#### 使用 SSH (推荐)

```bash
cd /home/biubiuboy/xray-lite

# 添加远程仓库 (替换 YOUR_USERNAME)
git remote add origin git@github.com:YOUR_USERNAME/xray-lite.git

# 推送代码
git branch -M main
git push -u origin main
```

### 步骤 3: 完成！

访问你的仓库: `https://github.com/YOUR_USERNAME/xray-lite`

---

## 📋 建议的仓库设置

### Topics 标签

在仓库页面点击 "Add topics"，添加:

```
rust
xray
proxy
reality
http2
grpc
tls
censorship-circumvention
privacy
lightweight
```

### About 部分

- **Description**: Lightweight Xray implementation in Rust with Reality and XHTTP support. 100% compatible with all Xray clients.
- **Website**: (可选)
- **Topics**: 添加上述标签

---

## 🔧 如果遇到问题

### 问题 1: 权限被拒绝

**使用 HTTPS**: 
- 需要输入 GitHub 用户名和 Personal Access Token
- 创建 Token: https://github.com/settings/tokens

**使用 SSH**:
- 需要先配置 SSH key
- 教程: https://docs.github.com/en/authentication/connecting-to-github-with-ssh

### 问题 2: 远程仓库已存在

```bash
# 移除旧的远程仓库
git remote remove origin

# 重新添加
git remote add origin https://github.com/YOUR_USERNAME/xray-lite.git
```

### 问题 3: 推送失败

```bash
# 强制推送 (谨慎使用)
git push -u origin main --force
```

---

## ✅ 上传后的检查清单

- [ ] 仓库可以正常访问
- [ ] README.md 正确显示
- [ ] 添加了 Topics 标签
- [ ] 设置了仓库描述
- [ ] 检查文件是否完整 (45 个文件)

---

**准备好了吗？运行 `./upload_to_github.sh` 开始上传！** 🚀
