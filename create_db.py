from app import app, db, Users  

def print_users():
    with app.app_context(): 
        users = Users.query.all()
        for user in users:
            print(f"ID: {user.id}, Username: {user.username}, Email: {user.email}, Date Added: {user.date_added}")

if __name__ == "__main__":
    print_users()
