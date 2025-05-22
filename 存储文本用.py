#!/usr/bin/env python3
import sqlite3
import os
import base64
import getpass
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, kdf.pbkdf2
from cryptography.fernet import Fernet

DB_FILENAME = 'password_manager.db'
SALT_FILENAME = 'salt.bin'

def load_or_create_salt():
    """
    加载盐值文件。如果不存在，则生成新的 16 字节随机盐，
    存储到文件中后返回该盐值。
    """
    if os.path.exists(SALT_FILENAME):
        f = open(SALT_FILENAME, 'rb')
        salt = f.read()
        f.close()
    else:
        salt = os.urandom(16)
        f = open(SALT_FILENAME, 'wb')
        f.write(salt)
        f.close()
    return salt

def derive_key(master_password, salt):
    """
    根据用户输入的主密码和盐值，
    通过 PBKDF2HMAC 算法生成 32 字节密钥，
    并经过 URL-safe 的 Base64 编码后返回。
    """
    kdf_obj = kdf.pbkdf2.PBKDF2HMAC(
        algorithm = hashes.SHA256(),  # 使用 SHA-256 算法
        length = 32,                 # 生成32字节密钥
        salt = salt,                 # 使用传入盐值
        iterations = 100000,         # 迭代次数
        backend = default_backend()  # 后端
    )
    derived_key = kdf_obj.derive(master_password.encode())
    key = base64.urlsafe_b64encode(derived_key)
    return key

def get_fernet():
    """
    提示用户输入主密码，同时加载/生成盐值，
    派生出 Fernet 对称加密算法所需的密钥，
    并返回一个 Fernet 实例。
    """
    master_password = getpass.getpass("请输入主密码：")
    salt = load_or_create_salt()
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    return fernet

def initialize_db():
    """
    初始化数据库：
      - 如果数据库不存在，则新建一个名为 passwords 的数据表。
      - 表结构包括：id、modified_time、username、password、note。
      - 加密后的数据将使用 TEXT 存储，每个字段均不允许为空。
    """
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    
    # SQL 语句：创建 passwords 表
    #  - 如果表不存在，则创建表
    #  - id: 自增主键
    #  - modified_time: 默认使用当前时间
    #  - username, password, note: 使用 TEXT 存储加密后经过 Base64 编码的数据
    sql_create = (
        "CREATE TABLE IF NOT EXISTS passwords ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "           # 自增长主键
        "modified_time DATETIME DEFAULT CURRENT_TIMESTAMP, " # 默认修改时间为当前时间
        "username TEXT NOT NULL, "                           # 存储加密的用户名，不能为空
        "password TEXT NOT NULL, "                           # 存储加密的密码，不能为空
        "note TEXT NOT NULL"                                 # 存储加密的备注，不能为空
        ")"
    )
    cursor.execute(sql_create)
    conn.commit()
    conn.close()

def encrypt_and_encode(fernet, text):
    """
    对传入的文本进行加密后转换为 Base64 编码的字符串，
    以便存入数据库的 TEXT 字段。
    """
    encrypted_bytes = fernet.encrypt(text.encode())
    # 将加密后的字节串转换为字符串存储
    encoded_str = encrypted_bytes.decode()
    return encoded_str

def decode_and_decrypt(fernet, encoded_text):
    """
    将存储在数据库中的 Base64 格式的加密字符串，
    首先将其转换成字节，再调用 Fernet 解密返回解密后的明文字符串。
    """
    # 将字符串转换成字节串
    encrypted_bytes = encoded_text.encode()
    decrypted_bytes = fernet.decrypt(encrypted_bytes)
    decrypted_text = decrypted_bytes.decode()
    return decrypted_text

def add_entry(fernet, username, password, note):
    """
    添加一条记录：
      - 对用户名、密码和备注进行加密和编码
      - 将加密后的数据保存到数据库中
    """
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    
    # 加密并转换用户名、密码和备注为 Base64 编码的字符串
    enc_username = encrypt_and_encode(fernet, username)
    enc_password = encrypt_and_encode(fernet, password)
    enc_note = encrypt_and_encode(fernet, note)
    
    # SQL 语句：向 passwords 表中插入记录
    # 使用占位符 ? 防止 SQL 注入
    sql_insert = (
        "INSERT INTO passwords (username, password, note) "
        "VALUES (?, ?, ?)"
    )
    cursor.execute(sql_insert, (enc_username, enc_password, enc_note))
    conn.commit()
    conn.close()
    print("添加成功。")

def delete_entry(entry_id):
    """
    根据传入的记录 id 删除对应记录。
    """
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    
    # SQL 语句：删除指定 id 的记录
    sql_delete = "DELETE FROM passwords WHERE id = ?"
    cursor.execute(sql_delete, (entry_id,))
    conn.commit()
    conn.close()
    print("删除成功。")

def update_entry(fernet, entry_id, username=None, password=None, note=None):
    """
    更新一条记录：
      - 首先依据 id 查询记录是否存在
      - 对传入的不为空字段进行加密，并更新记录，同时更新 modified_time
    """
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    
    # SQL 语句：依据 id 查询记录中的用户名、密码和备注
    sql_select = "SELECT username, password, note FROM passwords WHERE id = ?"
    cursor.execute(sql_select, (entry_id,))
    record = cursor.fetchone()
    if record is None:
        print("记录不存在。")
        conn.close()
        return

    current_username = record[0]
    current_password = record[1]
    current_note = record[2]
    
    if username is not None:
        new_username = encrypt_and_encode(fernet, username)
    else:
        new_username = current_username
        
    if password is not None:
        new_password = encrypt_and_encode(fernet, password)
    else:
        new_password = current_password
        
    if note is not None:
        new_note = encrypt_and_encode(fernet, note)
    else:
        new_note = current_note

    # SQL 语句：更新记录
    # 同时将 modified_time 更新为当前时间（DATETIME('now')）
    sql_update = (
        "UPDATE passwords SET username = ?, password = ?, note = ?, "
        "modified_time = DATETIME('now') WHERE id = ?"
    )
    cursor.execute(sql_update, (new_username, new_password, new_note, entry_id))
    conn.commit()
    conn.close()
    print("更新成功。")

def lcs_length(s1, s2):
    """
    使用动态规划算法计算两个字符串 s1 和 s2 的最长公共子序列（LCS）的长度。
    不使用列表表达式和嵌套结构，采用 while 循环实现。
    """
    m = len(s1)
    n = len(s2)
    # 初始化一个 (m+1) x (n+1) 的二维数组，全部元素设为 0
    dp = []
    row_index = 0
    while row_index < m + 1:
        row = []
        col_index = 0
        while col_index < n + 1:
            row.append(0)
            col_index = col_index + 1
        dp.append(row)
        row_index = row_index + 1
        
    i = 0
    while i < m:
        j = 0
        while j < n:
            if s1[i] == s2[j]:
                dp[i+1][j+1] = dp[i][j] + 1
            else:
                if dp[i][j+1] > dp[i+1][j]:
                    dp[i+1][j+1] = dp[i][j+1]
                else:
                    dp[i+1][j+1] = dp[i+1][j]
            j = j + 1
        i = i + 1
    return dp[m][n]

def search_entries(fernet, keyword):
    """
    搜索记录：
      - 从数据库读取所有记录后，对每条记录进行解密
      - 利用 LCS 算法计算备注与搜索关键字之间的匹配长度
      - 返回匹配长度大于 0 的记录，并按匹配长度降序排序
    """
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    
    # SQL 语句：查询所有记录，读取 id, modified_time, username, password, note 字段
    sql_select_all = (
        "SELECT id, modified_time, username, password, note FROM passwords"
    )
    cursor.execute(sql_select_all)
    results = cursor.fetchall()
    conn.close()
    matches = []
    index = 0
    while index < len(results):
        row = results[index]
        try:
            dec_username = decode_and_decrypt(fernet, row[2])
            dec_password = decode_and_decrypt(fernet, row[3])
            dec_note = decode_and_decrypt(fernet, row[4])
        except Exception as e:
            dec_username = "解密失败"
            dec_password = "解密失败"
            dec_note = "解密失败"
        match_length = lcs_length(dec_note, keyword)
        if match_length > 0:
            match_dict = {}
            match_dict['id'] = row[0]
            match_dict['modified_time'] = row[1]
            match_dict['username'] = dec_username
            match_dict['password'] = dec_password
            match_dict['note'] = dec_note
            match_dict['match_length'] = match_length
            matches.append(match_dict)
        index = index + 1
        
    def sort_key(item):
        return item['match_length']
    matches.sort(key = sort_key, reverse = True)
    return matches

def list_all_entries(fernet):
    """
    列出所有记录：
      - 从数据库读取所有记录，
      - 对每条记录进行解密，将解密后的数据返回。
    """
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    
    # SQL 语句：查询所有记录的 id, modified_time, username, password, note 字段
    sql_select_all = (
        "SELECT id, modified_time, username, password, note FROM passwords"
    )
    cursor.execute(sql_select_all)
    results = cursor.fetchall()
    conn.close()
    decrypted_results = []
    index = 0
    while index < len(results):
        row = results[index]
        try:
            dec_username = decode_and_decrypt(fernet, row[2])
            dec_password = decode_and_decrypt(fernet, row[3])
            dec_note = decode_and_decrypt(fernet, row[4])
        except Exception as e:
            dec_username = "解密失败"
            dec_password = "解密失败"
            dec_note = "解密失败"
        entry = {}
        entry['id'] = row[0]
        entry['modified_time'] = row[1]
        entry['username'] = dec_username
        entry['password'] = dec_password
        entry['note'] = dec_note
        decrypted_results.append(entry)
        index = index + 1
    return decrypted_results

def main():
    """
    主函数：
      - 初始化数据库
      - 获取 Fernet 实例（密钥） 
      - 展示用户菜单，支持添加、删除、更新、搜索及显示所有记录
    """
    initialize_db()
    fernet = get_fernet()
    
    while True:
        print("\n--- 加密密码管理器 ---")
        print("1. 添加记录")
        print("2. 删除记录")
        print("3. 更新记录")
        print("4. 搜索记录（基于备注的 LCS 匹配）")
        print("5. 显示所有记录")
        print("0. 退出")
        
        choice = input("请输入选择： ")
        
        if choice == "1":
            print("\n【添加记录】")
            username = input("请输入用户名：")
            password = getpass.getpass("请输入密码：")
            note = input("请输入备注：")
            add_entry(fernet, username, password, note)
            
        elif choice == "2":
            print("\n【删除记录】")
            entry_id_input = input("请输入要删除的记录ID：")
            try:
                entry_id = int(entry_id_input)
                delete_entry(entry_id)
            except ValueError:
                print("无效的ID。")
                
        elif choice == "3":
            print("\n【更新记录】")
            entry_id_input = input("请输入要更新的记录ID：")
            try:
                entry_id = int(entry_id_input)
                print("如果不需要更新某项，请直接回车。")
                new_username = input("请输入新的用户名：")
                new_password = getpass.getpass("请输入新的密码：")
                new_note = input("请输入新的备注：")
                
                if new_username.strip() == "":
                    new_username = None
                if new_password.strip() == "":
                    new_password = None
                if new_note.strip() == "":
                    new_note = None
                update_entry(fernet, entry_id, new_username, new_password, new_note)
            except ValueError:
                print("无效的ID。")
        elif choice == "4":
            print("\n【搜索记录】")
            keyword = input("请输入搜索关键字：")
            results = search_entries(fernet, keyword)
            if len(results) > 0:
                print("搜索结果（按匹配的LCS长度排序）：")
                i = 0
                while i < len(results):
                    entry = results[i]
                    print("ID: " + str(entry['id']) + ", 修改时间: " + str(entry['modified_time']))
                    print("用户名: " + str(entry['username']))
                    print("密码: " + str(entry['password']))
                    print("备注: " + str(entry['note']))
                    print("匹配度（LCS长度）: " + str(entry['match_length']))
                    print("-------------")
                    i = i + 1
            else:
                print("未找到匹配的记录。")
        elif choice == "5":
            print("\n【所有记录】")
            results = list_all_entries(fernet)
            if len(results) > 0:
                i = 0
                while i < len(results):
                    entry = results[i]
                    print("ID: " + str(entry['id']) + ", 修改时间: " + str(entry['modified_time']))
                    print("用户名: " + str(entry['username']))
                    print("密码: " + str(entry['password']))
                    print("备注: " + str(entry['note']))
                    print("-------------")
                    i = i + 1
            else:
                print("没有记录。")
        elif choice == "0":
            print("退出程序。")
            break
        else:
            print("无效选择，请重新输入。")
if __name__ == '__main__':
    main()
