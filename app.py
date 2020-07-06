from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from random import randint
from mysqldb import mydb
import bcrypt
import jwt
import datetime
from PIL import Image
import requests



app = Flask(__name__)
app.config['SECRET_KEY'] = 'L%\x90\xcet\xf4\xdc\x94\xab\x18\xd2Y>B]\xb8\xc1\xb8\x02\xeb\xf5h\xadA'
app.config['JSON_SORT_KEYS'] = False
api = Api(app)
cur = mydb.cursor(buffered=True)


def decodeJwt(token):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'])
    except jwt.ExpiredSignatureError as e:
        return {'error': e}


def crop_center(pil_img, crop_width, crop_height):
    img_width, img_height = pil_img.size
    return pil_img.crop(((img_width - crop_width) // 2,
                         (img_height - crop_height) // 2,
                         (img_width + crop_width) // 2,
                         (img_height + crop_height) // 2))


def crop_max_square(pil_img):
    return crop_center(pil_img, min(pil_img.size), min(pil_img.size))


def checkAuth(userId, token):
    qry = "SELECT * FROM auth WHERE uid = %s and token = %s"
    values = (userId, token)
    try:
        cur.execute(qry, values)
    except Exception as e:
        return e
    if cur.rowcount > 0:
        # print(cur.fetchall()[0][3])
        exp = datetime.datetime.fromisoformat(str(cur.fetchall()[0][3]))
        now = datetime.datetime.utcnow()
        if exp > now:
            return True
        else:
            qry = 'DELETE FROM auth WHERE token = %s'
            values = (token, )
            cur.execute(qry, values)
    return False



# -------------------------------------- ENDPOINTS ------------------------------------------


class Index(Resource):
    def get(self):
        return "Welcome to DocReg API"


class RegisterUser(Resource):
    def post(self):
        user_id = request.form['userId']
        password = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        city = request.form['city']
        state = request.form['state']
        otp = randint(100000, 999999)
        # email

        qry = "INSERT INTO `users`(`user_id`, `password`, `name`, `email`, `phone`, `city`, `state`, `otp`) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"
        values = (user_id, password, name, email, phone, city, state, otp)
        print(qry % values)
        try:
            cur.execute(qry, values)
        except Exception as e:
            return jsonify({
                'code': 300,    # user id exists
                'message': str(e)
            })
        return jsonify({
            'code': 200,
            'message': "user_created"
        })


class VerifyUser(Resource):
    def post(self):
        userId = request.form['userId']
        otp = request.form['otp']

        qry = "UPDATE users SET otp = 'verified' WHERE user_id = %s and otp = %s"
        values = (userId, otp)
        try:
            cur.execute(qry, values)
            mydb.commit()
        except Exception as e:
            return jsonify({
                'code': 400,
                'message': 'internal_server_error'
            })
        if cur.rowcount > 0:
            return jsonify({
                'code': 200,
                'otp': 'user_verified'
            })
        return jsonify({
            'code': 300,
            'otp': 'otp_incorrect'
        })


class UserLogin(Resource):
    def post(self):
        userId = request.form['userId']
        password = request.form['password']
        qry = "SELECT * FROM users WHERE user_id = %s"
        values = (userId, )
        cur.execute(qry, values)
        if cur.rowcount == 0:
            return jsonify({
                'code': 304,
                'message': 'no such user exist'
            })
        userData = cur.fetchall()[0]
        hashPw = userData[1]
        # todo: check verification
        if userData[8] != 'verified':
            return jsonify({
                'code': 302,
                'message': 'user_not_verified'
            })
        if bcrypt.checkpw(password.encode('utf-8'), hashPw.encode('utf-8')):
            exp = datetime.datetime.utcnow()+datetime.timedelta(days=7)
            token = jwt.encode({
                'user': userId,
                'exp': exp
            }, app.config['SECRET_KEY'])
            qry = 'INSERT INTO auth(uid, token, expiry, type) VALUES(%s,%s,%s,%s)'
            values = (userId, token.decode('utf-8'), exp, 'user')
            try:
                cur.execute(qry, values)
            except Exception as e:
                return jsonify({
                    'code': 303,
                    'message': str(e)
                })
            retjson = {
                'code': 200,
                'message': 'login_success',
                'user_id': userId,
                'token': token.decode('utf-8'),
                'token_expiry': exp,
                'name': userData[2],
                'email': userData[3],
                'phone': userData[4],
                'city': userData[5],
                'state': userData[6],
                'account_created': userData[7],
            }
            return jsonify(retjson)
        return jsonify({
            'code': 301,
            'message': 'invalid_credentials'
        })


class DocRegistration(Resource):
    def post(self):
        formdata = request.form
        token = formdata['auth']
        jwtresult = decodeJwt(token)
        if 'error' in jwtresult.keys():
            return jsonify({
                'code': 301,
                'message': jwtresult['error']
            })
        user_id = jwtresult['user']
        if not checkAuth(user_id, token):
            return jsonify({
                'code': 301,
                'message': 'auth_failed'
            })
        id = formdata['id']
        name = formdata['name']
        aadhaar = formdata['aadhaar_no']
        clinic_location = formdata['clinic_location']
        specialization = formdata['specialization']
        bio = formdata['bio']
        rating = formdata['rating']
        email = formdata['email']
        phone = formdata['phone']
        clinic_name = formdata['clinic_name']

        qry = "INSERT INTO `doctors`(`id`, `name`, `aadhaar_no`, `clinic_location`, `specialization`, `bio`, `rating`, `email`, `phone`, `clinic_name`, `reg_by`) " \
                            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        values = (id, name, aadhaar, clinic_location, specialization, bio, rating, email, phone, clinic_name, user_id )
        print(qry % values)
        try:
            cur.execute(qry, values)
        except Exception as e:
            return jsonify({
                'code': 300,  # user id exists
                'message': str(e)
            })
        return jsonify({
            'code': 200,
            'message': "doc_registered"
        })


class RegisterPatient(Resource):
    def post(self):
        try:
            formData = request.form
            token = formData['auth']
            jwtresult = decodeJwt(token)
            if 'error' in jwtresult.keys():
                return jsonify({
                    'code': 301,
                    'message': str(jwtresult['error'])
                })
            user_id = jwtresult['user']
            if not checkAuth(user_id, token):
                return jsonify({
                    'code': 302,
                    'message': 'auth_failed'
                })
            imgfile = Image.open(request.files.get("image"))
            imgfile = crop_max_square(imgfile)

            # code to send request to s3
            name = formData['name']
            aadhar = formData['aadhar'] if formData['aadhar'] != '' else None
            user_id = formData['user_id']
            age = formData['age']
            sex = formData['sex']
            address = formData['address']
            phone = formData['phone']
            height = formData['height'] if formData['height'] != '' else None
            weight = formData['weight'] if formData['weight'] != '' else None
            blood_group = formData['blood_group'] if formData['blood_group'] != '' else None
        except Exception as e:
            return jsonify({
                'code': 300,
                'message': 'request parameters incorrect',
                'error': str(e)
            })
        try:
            qry = "INSERT INTO `patients`(`name`, `aadhar`, `age`, `sex`, `address`, `phone`, `height`, `weight`, `blood_group`, `user_id`) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            values = (name, aadhar, age, sex, address, phone, height, weight, blood_group, user_id)
            cur.execute(qry, values)
        except Exception as e:
            return jsonify({
                'code': 303,
                'message': 'SQL Exception - MAYBE Duplecate entry',
                'error': str(e)
            })
        if cur.rowcount == 0:
            return jsonify({
                'code': 304,
                'message': 'request unsuccessful'
            })
        qry = "SELECT * FROM `patients` WHERE `name` = %s and `phone` = %s and `user_id` = %s"
        values = (name, phone, user_id)
        try:
            cur.execute(qry, values)
            patient_id = cur.fetchall()[0][0]
            # sending request
            url = "https://svs.virtualmist.com/wp-json/app-gateway/client-reg"
            payload = {'client_id': 'docreg',
                       'client_secret': '406eb9d6ce57c45a27b0a085fdcbe8bf',
                       'img_id': patient_id
                       }
            # imgByteArr = io.BytesIO()
            imgfile.save('./temp/temp.jpg', quality=95)

            files = [
                ('image', open('./temp/temp.jpg', 'rb'))
            ]
            headers = {}

            response = requests.request("POST", url, headers=headers, data=payload, files=files)
            # json_response = jsonify(str(response.text.encode('utf-8')))  # code 2000 - success
            # return json_response
            resBody = response.json()
            if resBody['code'] == 2000:
                return jsonify({
                    'code': 200,
                    'message': "registration successful"
                })
        except Exception as e:
            return jsonify({
                'code': 305,
                'message': 'something went wrong',
                'error': str(e)
            })


class RecognizePatient(Resource):
    def post(self):
        try:
            token = request.form['auth']
            img = Image.open(request.files.get("image"))
            jwtresult = decodeJwt(token)
            if 'error' in jwtresult.keys():
                return jsonify({
                    'code': 301,
                    'message': str(jwtresult['error'])
                })
        except Exception as e:
            return jsonify({
                'code': 302,
                'message': "request parameter incorrect"
            })
        try:
            qry = "SELECT patient_id FROM patients"
            cur.execute(qry)
            res = cur.fetchall()
            print(cur.rowcount)
            id_list = [i[0] for i in res]
            ids_param = ','.join([str(i) for i in id_list])
            print(ids_param)
        except Exception as e:
            return jsonify({
                'code': 303,
                'message': 'SQL Exception, please contact administrator'
            })
        # code to send request to s3 server
        try:
            url = "https://svs.virtualmist.com/wp-json/app-gateway/client-fetch"
            payload = {'client_id': 'docreg',
                       'client_secret': '406eb9d6ce57c45a27b0a085fdcbe8bf',
                       'source': ids_param}
            img.save('./temp/temp.jpg', quality=95)
            # imgByteArr = io.BytesIO()
            # img.save(imgByteArr, format='PNG')
            # imgByteArr = imgByteArr.getvalue()

            files = [
                ('image', open('./temp/temp.jpg', 'rb'))
                # ('image', imgByteAr)
            ]
            headers = {}
            response = requests.request("POST", url, headers=headers, data=payload, files=files)
            # TODO: implement code for decoding server response and encoding the response with patient details
            jsonres = response.json()
            if jsonres['code'] != 2000 or jsonres['message']['result'] is None:
                return jsonify({
                    'code': 305,
                    'message': 'No match found'
                })
            print(jsonres['message']['result'])
            result = jsonres['message']['result']
            response = []
            for i in result:
                qry = "SELECT * FROM `patients` WHERE `patient_id` = %s"
                cur.execute(qry % i['urn'])
                row = cur.fetchall()[0]
                response.append({
                    'id': row[0],
                    'image': i['image'],
                    'name': row[1],
                    'aadhar': row[2],
                    'age': row[3],
                    'sex': row[4],
                    'address': row[5],
                    'phone': row[6],
                    'height': row[7],
                    'weight': row[8],
                    'blood_group': row[9],
                    'registration_date': row[10],
                    'update_date': row[11],
                    'registered_by': row[12]
                })
            return jsonify({
                'code': 200,
                'resultset_size': len(response),
                'result': response
            })
        except Exception as e:
            return jsonify({
                'code': 304,
                'message': 'S3 error, please contact administrator',
                'error': str(e)
            })




# --------------------------------------X ENDPOINTS X------------------------------------------


api.add_resource(Index, '/')
api.add_resource(VerifyUser, '/verify-user')
api.add_resource(RegisterUser, '/register-new-user')
api.add_resource(UserLogin, '/user-login')
api.add_resource(DocRegistration, '/register-doctor')
api.add_resource(RegisterPatient, '/register-patient')
api.add_resource(RecognizePatient, '/recognize-patient')


if __name__ == "__main__":
    app.run(debug=True, port="5001", host="0.0.0.0")
