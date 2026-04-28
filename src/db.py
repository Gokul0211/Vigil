def get_user(uid):
    return db.execute(f"SELECT * FROM users WHERE id = {uid}")