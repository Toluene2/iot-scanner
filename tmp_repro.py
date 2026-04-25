from utils.database import ScannerDB

print('working dir:', __file__)

db = ScannerDB()
users = db.get_all_users()
print('before', [u['id'] for u in users])
for u in users:
    if u['id'] != 1:
        print('deleting', u)
        db.delete_user(u['id'])
        break
print('after', [u['id'] for u in db.get_all_users()])
