import pymysql
import base64
import json
pymysql.install_as_MySQLdb()


from flask import Flask, render_template, current_app, make_response, request
from flask_mail import Mail, Message
from flask_restx import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
from datetime import datetime

import jwt

app = Flask(__name__, template_folder='ui')
api = Api(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:GEDXcE4Xa4ZtlyomrIdi@containers-us-west-93.railway.app:7016/railway"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

app.config['JWT_SECRET_KEY'] = "Rahasia"
app.config['MAIL_SERVER'] = "smtp.googlemail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "laravell.it@gmail.com"
app.config['MAIL_PASSWORD'] = "dhlxbaygvultdqyu"

db = SQLAlchemy(app)

mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer(),primary_key=True,nullable=False)
    name = db.Column(db.String(255),nullable=False)
    email = db.Column(db.String(255),unique=True,nullable=False)
    password = db.Column(db.String(255),nullable=False)
    is_verify = db.Column(db.Integer(),nullable=False)

parser4SignUp = reqparse.RequestParser()
parser4SignUp.add_argument('name', type=str, help='Fullname', location='json', required=True)
parser4SignUp.add_argument('email', type=str, help='Email Address', location='json', required=True)
parser4SignUp.add_argument('password', type=str, help='Password', location='json', required=True)
parser4SignUp.add_argument('re_password', type=str, help='Retype Password', location='json', required=True)

@api.route('/user/signup')
class Registration(Resource):
    @api.expect(parser4SignUp)
    def post(self):
        args = parser4SignUp.parse_args()
        name = args['name']
        email = args['email']
        password = args['password']
        rePassword = args['re_password']

        if(password != rePassword):
            return {'message' : 'Password is not match'}, 400

        user = db.session.execute(db.select(User).filter_by(email=email)).first()

        if(user):
            return {'message' : 'Your email address has been used'}, 409

        try:
            user = User(email=email, name=name, password=generate_password_hash(password), is_verify=False)

            db.session.add(user)
            db.session.commit()

            datas = db.session.execute(db.select(User).filter_by(email=email)).first()
            user_id = datas[0].id
            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "Rahasia")

            email_token = jwt.encode({"id": user_id}, jwt_secret_key, algorithm="HS256")

            url = f"https://windy-eggs-production.up.railway.app/user/verify-account/{email_token}"

            data = {
                'name': name,
                'url': url
            }

            sender = "noreply@app.com"
            msg = Message(subject="Verify your email", sender=sender, recipients=[email])
            msg.html = render_template("verify-email.html", data=data)

            mail.send(msg)
            return {
                'message' : "Success create account, check email to verify account"
            }, 201
        except Exception as e:
            print(e)
            return {
                'message' : f"Error {e}"
            }, 500

parser4BasicSignIn = reqparse.RequestParser()
parser4BasicSignIn.add_argument('email', type=str, help='Email Address', location='json', required=True)
parser4BasicSignIn.add_argument('password', type=str, help='Password', location='json', required=True)

@api.route('/user/basic-signin')
class BasicLogin(Resource):
    @api.expect(parser4BasicSignIn)
    def post(self):
        args = parser4BasicSignIn.parse_args()
        email = args['email']
        password = args['password']

        if not email or not password :
            return { "message" : "Please type email and passowrd" }, 400

        user = db.session.execute(db.select(User).filter_by(email=email)).first()
        
        if not user :
            return { "message" : "User not found, please do register" }, 400

        if not user[0].is_verify :
            return { "message" : "Accunt not actived, check email to verify" }, 401

        if check_password_hash(user[0].password, password):
            payload = {
                'id' : user[0].id,
                'name' : user[0].name,
                'email' : user[0].email
            }

            payload_json = json.dumps(payload)
            message_bytes = payload_json.encode('ascii')
            base64_bytes = base64.b64encode(message_bytes)
            base64_message = base64_bytes.decode('ascii')

            return{ 'token' : base64_message }, 200
        else:
            return { "message" : "Wrong password, try again" }, 400


parser4Basic = reqparse.RequestParser()
parser4Basic.add_argument('Authorization', type=str, location='headers', required=True, help='Fill using token login')

@api.route('/user/basic-auth')
class BasicAuth(Resource):
    @api.expect(parser4Basic)
    def post(self):
        print(f"ljjksfad")
        args = parser4Basic.parse_args()
        basicAuth = args['Authorization']
        base64message = basicAuth[6:]
        
        msgBytes = base64message.encode('ascii')
        base64Bytes = base64.b64decode(msgBytes)
        pair = base64Bytes.decode('ascii')
        decoded_payload_obj = json.loads(pair)

        id = decoded_payload_obj['id']
        name = decoded_payload_obj['name']
        email = decoded_payload_obj['email']
        return {
            'id': id,
            'name': name,
            'email': email
        }

@api.route("/user/verify-account/<token>")
class VerifyAccount(Resource):
    def get(self, token):
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()[0]
            
            if not user:
                return {"message": "User not found"}, 404

            if user.is_verify:
                response = make_response(render_template('response.html', success=False, message='Account has been verified'), 400)
                response.headers['Content-Type'] = 'text/html'

                return response

            user.is_verify = True
            db.session.commit()

            response = make_response(render_template('response.html', success=True, message='Your account has been verified!'), 200)
            response.headers['Content-Type'] = 'text/html'

            return response

        except jwt.exceptions.ExpiredSignatureError:
            return {"message": "Token has expired."}, 401

        except (jwt.exceptions.InvalidTokenError, KeyError):
            return {"message": "Invalid token."}, 401

        except Exception as e:
            return {"message": f"Error {e}"}, 500


parser4SignIn = reqparse.RequestParser()
parser4SignIn.add_argument('email', type=str, help='Email Address', location='json', required=True)
parser4SignIn.add_argument('password', type=str, help='Password', location='json', required=True)

@api.route('/user/signin')
class Login(Resource):
    @api.expect(parser4SignIn)
    def post(self):
        args = parser4SignIn.parse_args()
        email = args['email']
        password = args['password']

        if not email or not password :
            return { "message" : "Please type email and passowrd" }, 400

        user = db.session.execute(db.select(User).filter_by(email=email)).first()
        
        if not user :
            return { "message" : "User not found, please do register" }, 401

        if not user[0].is_verify :
            return { "message" : "Accunt not actived, check email for verify" }, 402

        if check_password_hash(user[0].password, password):
            payload = {
                'id' : user[0].id,
                'name' : user[0].name,
                'email' : user[0].email
            }

            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "Rahasia")
            print(f"INFO {jwt_secret_key}")
            token = jwt.encode(payload, jwt_secret_key, algorithm="HS256")
            return{ 
                'token' : token }, 200

        else:
            return { "message" : "Wrong password" }, 403


@api.route('/user/current')
class WhoIsLogin(Resource):
    def get(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()
            
            if not user:
                return {'message': 'User not found'}, 404

            user = user[0]

            return {
                'status': "Success", 
                'data': {
                    'id': user.id,
                    'name': user.name,
                    'email': user.email
                }
            }, 200

        except jwt.ExpiredSignatureError:
            return {'message': 'Token is expired'}, 401

        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 401


user_parser = reqparse.RequestParser()
user_parser.add_argument('name', type=str, help='Fullname', location='json', required=False)
user_parser.add_argument('email', type=str, help='Email Address', location='json', required=False)

@api.route('/user/update')
class UpdateUser(Resource):
    def put(self):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()
            
            if not user:
                return {'message': 'User not found'}, 404

            user = user[0]

            args = user_parser.parse_args()
            name = args['name']
            email = args['email']
            if name is not None and name != "":
                user.name = name
            if email is not None and email !="":
                user.email = email

            db.session.commit()

            try:
                db.session.commit()
                return {'message': 'Profile updated successfully'}, 200
            except:
                db.session.rollback()
                return {'message': 'Profile update failed'}, 400

        except jwt.ExpiredSignatureError:
            return {'message': 'Token is expired'}, 401

        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 401




forgot_password_parser = reqparse.RequestParser()
forgot_password_parser.add_argument('email', type=str, help='Email Address', location='json', required=True)

@api.route('/user/forgot-password')
class ForgetPassword(Resource):
    def post(self):
        try:
            args = forgot_password_parser.parse_args()
            email = args['email']

            user = db.session.execute(db.select(User).filter_by(email=email)).first()

            if not user:
                return {'message': 'Email does not match any user'}, 404

            jwt_secret_key = current_app.config.get("JWT_SECRET_KEY", "Rahasia")

            email_token = jwt.encode({"id": user[0].id}, jwt_secret_key, algorithm="HS256")

            url = f"https://windy-eggs-production.up.railway.app/user/reset-password/{email_token}"

            sender = "noreply@app.com"
            msg = Message(subject="Reset your password", sender=sender, recipients=[email])
            msg.html = render_template("reset-password.html", url=url)

            mail.send(msg)
            return {'message' : "Success send request, check email to verify"}, 200

        except Exception as e:
            return {"message": f"Error {e}"}, 500


@api.route('/user/reset-password/<token>')
class ViewResetPassword(Resource):
    def get(self, token):
        try:
            decoded_token = jwt.decode(token, key="Rahasia", algorithms=["HS256"])
            user_id = decoded_token["id"]
            user = db.session.execute(db.select(User).filter_by(id=user_id)).first()
            
            if not user:
                return {"message": "User not found"}, 404

            response = make_response(render_template('form-reset-password.html', id=user[0].id), 200)
            response.headers['Content-Type'] = 'text/html'

            return response

        except jwt.exceptions.ExpiredSignatureError:
            return {"message": "Token has expired."}, 401

        except (jwt.exceptions.InvalidTokenError, KeyError):
            return {"message": "Invalid token."}, 401

        except Exception as e:
            return {"message": f"Error {e}"}, 500



reset_password_parser = reqparse.RequestParser()
reset_password_parser.add_argument('id', type=int, required=True, help='User ID is required')
reset_password_parser.add_argument('password', type=str, required=True, help='New password is required')
reset_password_parser.add_argument('confirmPassword', type=str, required=True, help='Confirm password is required')

@api.route('/user/reset-password', methods=['PUT', 'POST'])
class ResetPassword(Resource):
    def post(self):
        args = reset_password_parser.parse_args()
        password = args['password']

        user = db.session.execute(db.select(User).filter_by(id=args['id'])).first()
        if not user:
            return {'message': 'User not found'}, 404

        if password != args['confirmPassword']:
            return {'message': 'Passwords do not match'}, 400

        user[0].password = generate_password_hash(password)

        try:
            db.session.commit()
            response = make_response(render_template('response.html', success=True, message='Reset password successfully'), 200)
            response.headers['Content-Type'] = 'text/html'
            return response

        except:
            db.session.rollback()
            response = make_response(render_template('response.html', success=False, message='Reset password failed'), 400)
            response.headers['Content-Type'] = 'text/html'
            return response


class Makanan(db.Model):
    id = db.Column(db.Integer(),primary_key=True,nullable=False)
    nama = db.Column(db.String(255),nullable=False)
    kalori = db.Column(db.String(255),nullable=False)
    protein = db.Column(db.String(255),nullable=False)
    karbohidrat = db.Column(db.String(255),nullable=False)
    lemak = db.Column(db.String(255),nullable=False)
    deskripsi = db.Column(db.String(255),nullable=False)
    image = db.Column(db.String(255),nullable=True)
    def serialize(row):
        return {
            "id" : str(row.id),
            "nama" : row.nama,
            "kalori" : row.kalori,
            "protein" : row.protein,
            "karbohidrat" : row.karbohidrat,
            "lemak" : row.lemak,
            "deskripsi" : row.deskripsi,
            "image" : row.image,


        } 


parser4ListMakanan = reqparse.RequestParser()
parser4ListMakanan.add_argument('nama', type=str, help='nama', location='json', required=True)
parser4ListMakanan.add_argument('kalori', type=str, help='kalori', location='json', required=True)
parser4ListMakanan.add_argument('protein', type=str, help='protein', location='json', required=True)
parser4ListMakanan.add_argument('karbohidrat', type=str, help='karbohidrat', location='json', required=True)
parser4ListMakanan.add_argument('lemak', type=str, help='lemak', location='json', required=True)
parser4ListMakanan.add_argument('deskripsi', type=str, help='deskripsi', location='json', required=True)
parser4ListMakanan.add_argument('image', type=str, help='image', location='json', required=False)

@api.route('/list/makanan')
class NewMakanan(Resource):
    @api.expect(parser4ListMakanan)
    def post(self):
        args = parser4ListMakanan.parse_args()
        nama = args['nama']
        kalori = args['kalori']
        protein = args['protein']
        karbohidrat = args['karbohidrat']
        lemak = args['lemak']
        deskripsi = args['deskripsi']
        image = args['image']

        try:
            makanan = Makanan(nama=nama, kalori=kalori, protein=protein,karbohidrat=karbohidrat, lemak=lemak, deskripsi=deskripsi, image=image)

            db.session.add(makanan)
            db.session.commit()

            return {
                'message' : "bisa nambah um"
            }, 201
        except Exception as e:
            print(e)
            return {
                'message' : f"Error um {e}"
            }, 500

@api.route("/makanan")
class GetAllMakanan(Resource):
    def get(self):
        
        try:
            
            makanan = db.session.execute(db.select(Makanan)
            .order_by(Makanan.id))

            makanans = Makanan.query.all()
            makananx = [Makanan.serialize(x) for x in makanans]
            
            return make_response(
                {
                    "message":"Success",
                    "data": makananx
                },200
            )
               
        except Exception as e:
            print(f"{e}")
            return {'message': f'Failed {e}'}, 400


class Fitness(db.Model):
    id = db.Column(db.Integer(),primary_key=True,nullable=False)
    created_at = db.Column(db.String(255),nullable=False)
    pull_up = db.Column(db.String(255),nullable=False)
    push_up = db.Column(db.String(255),nullable=False)
    def serialize(row):
        return {
            "id" : str(row.id),
            "created_at" : row.created_at,
            "pull_up" : row.pull_up,
            "push_up" : row.push_up,

        } 


parser4ListFitness = reqparse.RequestParser()
parser4ListFitness.add_argument('pull_up', type=str, help='pull_up', location='json', required=True)
parser4ListFitness.add_argument('push_up', type=str, help='push_up', location='json', required=True)

@api.route('/list/fitness')
class NewFitness(Resource):
    @api.expect(parser4ListFitness)
    def post(self):
        args = parser4ListFitness.parse_args()
        pull_up = args['pull_up']
        push_up = args['push_up']
        try:
            current_time = datetime.now()
            fitness = Fitness(pull_up=pull_up, push_up=push_up, created_at=current_time)
            db.session.add(fitness)
            db.session.commit()

            return {
                'message' : "bisa nambah um"
            }, 201
        except Exception as e:
            print(e)
            return {
                'message' : f"Error um {e}"
            }, 500

@api.route("/fitness")
class GetAllFItness(Resource):
    def get(self):
        try:
            
            fitness = db.session.execute(db.select(Fitness)
            .order_by(Fitness.id))

            fitnesss = Fitness.query.all()
            fitnessx = [Fitness.serialize(x) for x in fitnesss]
            
            return make_response(
                {
                    "message":"Success",
                    "data": fitnessx
                },200
            )
               
        except Exception as e:
            print(f"{e}")
            return {'message': f'Failed {e}'}, 400



