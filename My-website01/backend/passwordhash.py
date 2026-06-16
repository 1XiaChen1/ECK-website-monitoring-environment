# 安裝 bcrypt 加密函式庫，專門用來做密碼雜湊（Password Hash）
import bcrypt

def hash_password(plain_text_password: str) -> str:
    """
    註冊時使用：將使用者的明文密碼轉換為安全的雜湊值
    """
    # 1. 將字串轉換為 bytes 編碼
    password_bytes = plain_text_password.encode('utf-8')
    
    # 2. 產生隨機的「鹽（Salt）」
    # gensalt() 預設會進行 12 次的安全回合計算（Work Factor）
    salt = bcrypt.gensalt()
    
    # 3. 進行雜湊運算
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)
    
    # 4. 將 bytes 轉回字串，方便儲存到資料庫中
    return hashed_bytes.decode('utf-8')


def verify_password(plain_text_password: str, hashed_password_from_db: str) -> bool:
    """
    登入時使用：驗證使用者輸入的密碼是否與資料庫中的雜湊值吻合
    """
    # 將輸入的明文密碼與資料庫的雜湊值（皆轉為 bytes）進行比對
    # bcrypt 會自動從資料庫的雜湊值中提取當初的「鹽」來進行相同的運算
    return bcrypt.checkpw(
        plain_text_password.encode('utf-8'), 
        hashed_password_from_db.encode('utf-8')
    )

# --- 測試程式碼 ---
if __name__ == "__main__":
    user_password = "mySecretPassword123"
    
    # 模擬註冊：將密碼加密後存入資料庫
    db_record = hash_password(user_password)
    print(f"資料庫實際儲存的密碼長相：\n{db_record}\n")
    
    # 模擬登入成功的情況
    is_valid = verify_password("mySecretPassword123", db_record)
    print(f"輸入正確密碼，驗證結果：{is_valid}") # 應該輸出 True
    
    # 模擬登入失敗的情況
    is_invalid = verify_password("wrongPassword123", db_record)
    print(f"輸入錯誤密碼，驗證結果：{is_invalid}") # 應該輸出 False