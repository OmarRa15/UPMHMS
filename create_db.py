# from app import db, Users, Room
# from werkzeug.security import generate_password_hash
#
# db.create_all()
# # db.drop_all()
# db.session.commit()
#
# for floor in range(1, 5):
#     for room in range(1, 16):
#         roomNum = '0' + str(room) if room < 10 else str(room)
#         roomNum = int(str(floor) + str(roomNum))
#         roomRecord = Room(room_num=roomNum, floor_num=floor)
#         db.session.add(roomRecord)
#         db.session.commit()
#
# hashedPass = generate_password_hash('RAOM9920', method='sha256')
# newUser = Users(first_name='Omar', last_name='Mazen',
#                 username='Omar', email="omarhoms0@gmail.com", password=hashedPass, is_admin=True, is_confirmed=True)
#
# db.session.add(newUser)
# db.session.commit()
