#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
结构说明：
    - id: 唯一自增主键
    - modified_time: 上次修改时间，默认 CURRENT_TIMESTAMP
    - username: 加密后存储的用户名（BLOB）
    - password: 加密后存储的密码（BLOB）
    - note: 加密后存储的备注（BLOB）
"""

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
    加载盐，如果文件不存在则新建一个随机盐值并保存到文件中。
    盐值用于密钥派生，有助于防止彩虹表攻击。
    """
    if os.path.exists(SALT_FILENAME):
        with open(SALT_FILENAME, 'rb') as f:
            salt = f.read()
    else:
        salt = os.urandom(16)
        with open(SALT_FILENAME, 'wb') as f:
            f.write(salt)
    return salt

def derive_key(master_password, salt):
    """
    通过 PBKDF2HMAC 算法，根据 master 密码与盐值生成 32 字节的密钥，
    并经过 URL-safe Base64 编码，从而生成 Fernet 使用的密钥。
    """
    kdf_obj = kdf.pbkdf2.PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf_obj.derive(master_password.encode()))
    return key

def get_fernet():
    """
    要求用户输入主密码，并返回一个 Fernet 实例。
    """
    master_password = getpass.getpass("请输入主密码：")
    salt = load_or_create_salt()
    key = derive_key(master_password, salt)
    return Fernet(key)

def initialize_db():
    """
    初始化数据库，创建数据表。
    表结构：
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        modified_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        username BLOB NOT NULL,
        password BLOB NOT NULL,
        note BLOB NOT NULL
    """
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            modified_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            username BLOB NOT NULL,
            password BLOB NOT NULL,
            note BLOB NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def add_entry(fernet, username, password, note):
    """
    添加一条记录，将用户名、密码和备注加密后存入数据库。
    """
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    enc_username = fernet.encrypt(username.encode())
    enc_password = fernet.encrypt(password.encode())
    enc_note = fernet.encrypt(note.encode())
    cursor.execute('''
        INSERT INTO passwords (username, password, note)
        VALUES (?, ?, ?)
    ''', (enc_username, enc_password, enc_note))
    conn.commit()
    conn.close()
    print("添加成功。")

def delete_entry(entry_id):
    """
    根据记录 id 删除对应记录。
    """
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM passwords WHERE id = ?', (entry_id,))
    conn.commit()
    conn.close()
    print("删除成功。")

def update_entry(fernet, entry_id, username=None, password=None, note=None):
    """
    更新记录，根据传入的非空字段进行更新。
    同时更新 modified_time 字段为当前时间。
    所有字段都存储为加密数据。
    """
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    # 检查记录是否存在
    cursor.execute('SELECT username, password, note FROM passwords WHERE id = ?', (entry_id,))
    record = cursor.fetchone()
    if not record:
        print("记录不存在。")
        conn.close()
        return

    current_username, current_password, current_note = record
    new_username = fernet.encrypt(username.encode()) if username is not None else current_username
    new_password = fernet.encrypt(password.encode()) if password is not None else current_password
    new_note = fernet.encrypt(note.encode()) if note is not None else current_note

    cursor.execute('''
        UPDATE passwords
        SET username = ?,
            password = ?,
            note = ?,
            modified_time = DATETIME('now')
        WHERE id = ?
    ''', (new_username, new_password, new_note, entry_id))
    conn.commit()
    conn.close()
    print("更新成功。")

def lcs_length(s1, s2):
    """
    计算 s1 与 s2 的最长公共子序列（LCS）的长度。
    动态规划实现。
    """
    m, n = len(s1), len(s2)
    dp = [[0]*(n+1) for _ in range(m+1)]
    for i in range(m):
        for j in range(n):
            if s1[i] == s2[j]:
                dp[i+1][j+1] = dp[i][j] + 1
            else:
                dp[i+1][j+1] = max(dp[i][j+1], dp[i+1][j])
    return dp[m][n]

def search_entries(fernet, keyword):
    """
    搜索记录。
    由于所有字段均为加密的，此处将先读取所有记录，再对解密后的 note 使用最长公共子序列算法
    计算与关键字的匹配长度，返回最接近的记录（匹配长度大于 0 的记录）。
    """
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, modified_time, username, password, note FROM passwords')
    results = cursor.fetchall()
    conn.close()

    matches = []
    for row in results:
        try:
            dec_username = fernet.decrypt(row[2]).decode()
            dec_password = fernet.decrypt(row[3]).decode()
            dec_note = fernet.decrypt(row[4]).decode()
        except Exception as e:
            dec_username = dec_password = dec_note = "解密失败"
        # 计算备注与关键字的最长公共子序列长度
        match_length = lcs_length(dec_note, keyword)
        if match_length > 0:
            matches.append({
                'id': row[0],
                'modified_time': row[1],
                'username': dec_username,
                'password': dec_password,
                'note': dec_note,
                'match_length': match_length
            })
    # 按匹配长度降序排序
    matches.sort(key=lambda x: x['match_length'], reverse=True)
    return matches

def list_all_entries(fernet):
    """
    列出所有记录，解密并返回所有字段。
    """
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, modified_time, username, password, note FROM passwords')
    results = cursor.fetchall()
    conn.close()

    decrypted_results = []
    for row in results:
        try:
            dec_username = fernet.decrypt(row[2]).decode()
            dec_password = fernet.decrypt(row[3]).decode()
            dec_note = fernet.decrypt(row[4]).decode()
        except Exception as e:
            dec_username = dec_password = dec_note = "解密失败"
        decrypted_results.append({
            'id': row[0],
            'modified_time': row[1],
            'username': dec_username,
            'password': dec_password,
            'note': dec_note
        })
    return decrypted_results

def main():
    # 初始化数据库（如果不存在则创建）
    initialize_db()
    # 启动时要求输入主密码，获得 Fernet 实例
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
            username = input("请输入用户名： ")
            password = getpass.getpass("请输入密码： ")
            note = input("请输入备注： ")
            add_entry(fernet, username, password, note)
        elif choice == "2":
            print("\n【删除记录】")
            try:
                entry_id = int(input("请输入要删除的记录ID： "))
                delete_entry(entry_id)
            except ValueError:
                print("无效的ID。")
        elif choice == "3":
            print("\n【更新记录】")
            try:
                entry_id = int(input("请输入要更新的记录ID： "))
                print("若不更新某项，请直接回车。")
                new_username = input("输入新的用户名： ")
                new_password = getpass.getpass("输入新的密码： ")
                new_note = input("输入新的备注： ")

                new_username = new_username if new_username.strip() != "" else None
                new_password = new_password if new_password.strip() != "" else None
                new_note = new_note if new_note.strip() != "" else None

                update_entry(fernet, entry_id, new_username, new_password, new_note)
            except ValueError:
                print("无效的ID。")
        elif choice == "4":
            print("\n【搜索记录】")
            keyword = input("请输入搜索关键字： ")
            results = search_entries(fernet, keyword)
            if results:
                print("搜索结果（按匹配的LCS长度排序）：")
                for entry in results:
                    print(f"ID: {entry['id']}, 修改时间: {entry['modified_time']}")
                    print(f"用户名: {entry['username']}")
                    print(f"密码: {entry['password']}")
                    print(f"备注: {entry['note']}")
                    print(f"匹配度（LCS长度）: {entry['match_length']}")
                    print("-------------")
            else:
                print("未找到匹配的记录。")
        elif choice == "5":
            print("\n【所有记录】")
            results = list_all_entries(fernet)
            if results:
                for entry in results:
                    print(f"ID: {entry['id']}, 修改时间: {entry['modified_time']}")
                    print(f"用户名: {entry['username']}")
                    print(f"密码: {entry['password']}")
                    print(f"备注: {entry['note']}")
                    print("-------------")
            else:
                print("没有记录。")
        elif choice == "0":
            print("退出程序。")
            break
        else:
            print("无效选择，请重新输入。")

if __name__ == '__main__':
    main()
