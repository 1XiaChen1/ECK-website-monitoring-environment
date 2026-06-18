# 載入作業系統讀取環境變數
import os
# 載入時間模組
import time

# Flask Web Framework 建立 Web API， request 取得使用者送來的資料、 redirect 頁面跳轉
from flask import Flask, request, redirect

# PostgreSQL 資料庫模組
import psycopg2
# PostgreSQL 捕捉資料庫連線失敗例外
from psycopg2 import OperationalError

# 引入 Python 內建 Log 機制與 Logstash 非同步處理器
import logging
from logstash_async.handler import AsynchronousLogstashHandler

# 引入你寫的加密模組（請確保你的檔名是 passwordhash.py，如果是 passwordhas.py 請將這裡改為 import passwordhas）
import passwordhash 

# 建立 Flask App網站服務
app = Flask(__name__)
# 初始化 Logstash 連線設定
# 'my_logstash' 是我們在公共網路定義的 Logstash 容器名稱，Port 是 5001
logstash_handler = AsynchronousLogstashHandler(
    host='host.docker.internal', # Docker 在你電腦上的固定對外橋接 IP：host.docker.internal ，或是可以直接寫本機的實體ip⚠️
    port=5044, 
    database_path=None
)
# 宣告一個叫做 'flask-backend' 的紀錄器
logger = logging.getLogger('flask-backend')
logger.setLevel(logging.INFO) # 設定最低以上紀錄等級：INFO 都會被記錄。
logger.addHandler(logstash_handler) #把 Log 送給：Logstash

# 同時讓 Log 印在 Python 本地的終端機畫面上，方便雙向除錯
stream_handler = logging.StreamHandler()
logger.addHandler(stream_handler) 

# 先找環境變數 "DB_xx"，如果沒有使用 “變數”
DB_HOST = os.environ.get("DB_HOST", "database") 
DB_USER = os.environ.get("DB_USER", "admin")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "secure_password123")
DB_NAME = os.environ.get("DB_NAME", "user_db")

def get_db_connection():
    """與 PostgreSQL 建立連線，加入重試機制以防資料庫啟動較慢"""
    retries = 5
    while retries > 0:
        try:
            conn = psycopg2.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                dbname=DB_NAME
            )
            return conn
        except OperationalError:
            print("資料庫尚未準備好，等待 2 秒後重試...")
            time.sleep(2)
            retries -= 1
    raise Exception("無法連線至資料庫") # 如果五次都失敗：顯示“無法連線至資料庫”

def init_db():
    """系統啟動時：自動建立 users 資料表，並塞入一筆測試帳號"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    # 建立資料表 (如果不存在的話)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(100) NOT NULL
        )
    ''')
    
    # 檢查是否已經有測試帳號
    cur.execute("SELECT * FROM users WHERE username = 'testuser'")
    if cur.fetchone() is None:
        # 使用你寫的 passwordhash.py 將密碼 '123456' 雜湊處理
        hashed_pw = passwordhash.hash_password("123456")
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
            ('testuser', hashed_pw)
        )
        print("已建立預設測試帳號: testuser / 123456")
        
    conn.commit()
    cur.close()
    conn.close()

# 啟動時執行資料庫初始化
with app.app_context():
    try:
        init_db()
    except Exception as e:
        print(f"初始化資料庫失敗: {e}")

# --- API 路由設定 ---

@app.route('/login', methods=['POST'])
def login():
    # 1. 取得前端表單傳來的帳號密碼
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password: # 檢查是否空白
        return "請輸入帳號與密碼", 400

    # 2. 連線資料庫尋找該使用者
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
    result = cur.fetchone()
    
    cur.close()
    conn.close()

    # 3. 驗證邏輯
    if result:
        hashed_password_from_db = result[0]
        # 呼叫你寫的驗證函式
        if passwordhash.verify_password(password, hashed_password_from_db):
            
            # 密碼正確，發送成功日誌給 Logstash
            logger.info(f"User login successful: {username}")

            # 登入成功！跳轉回前端 Nginx 提供的 dashboard01.html
            return redirect("http://localhost:8080/dashboard01.html")
        else:

            # 密碼錯誤，發送警告日誌給 Logstash
            logger.warning(f"Login failed for user: {username} - Invalid password")
            
            return "密碼錯誤，請回上一頁重試", 401
    else:

        # 找不到該使用者時，發送警告日誌給 Logstash
        logger.warning(f"Login failed: User {username} does not exist")

        return "找不到此使用者", 404

if __name__ == '__main__':
    # 啟動 Flask 伺服器，綁定在 0.0.0.0 以便容器外部(Nginx)可以存取
    app.run(host='0.0.0.0', port=5000) # Port 設定要注意 ⚠️