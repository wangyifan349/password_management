# 🔒 Password Management

一个简单的密码管理器，使用 Python 和 SQLite 实现，支持加密存储用户名、密码和备注。该项目使用 GPL-3.0 许可证，确保您的数据安全且完全离线存储，无需联网。

## 🌟 特性

- 🔑 使用 PBKDF2 算法和盐值生成密钥，确保主密码的安全性。
- ➕ 支持添加、删除、更新和搜索密码记录。
- 🔒 所有数据均经过加密存储，保护用户隐私。
- 📊 使用动态规划算法计算备注与关键字的最长公共子序列（LCS）匹配度。
- 🌐 完全离线，无需互联网连接，确保数据安全。

## 📥 安装

1. 确保您的系统上已安装 Python 3。
2. 克隆此仓库：

   ```bash
   git clone https://github.com/wangyifan349/password-management.git
   cd password-management
   ```

3. 安装所需的依赖库：

   ```bash
   pip install cryptography
   ```

## 🚀 使用

1. 运行程序：

   ```bash
   python password_manager.py
   ```

2. 按照提示输入主密码以访问密码管理器。
3. 使用菜单选项添加、删除、更新或搜索密码记录。

## 📜 许可证

本项目使用 [GPL-3.0](https://opensource.org/licenses/GPL-3.0) 许可证。有关详细信息，请参阅 LICENSE 文件。

## 🤝 贡献

欢迎任何形式的贡献！请提交问题或拉取请求。
