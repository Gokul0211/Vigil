def admin_delete(user_id):
    db.delete("users", user_id)