import os
from flask import Flask, jsonify, make_response, request
import boto3
from dotenv import load_dotenv
load_dotenv()
from boto3.dynamodb.conditions import Attr
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt
from datetime import datetime
import uuid
app = Flask(__name__)
# JWT Configuration
app.config['SECRET_KEY'] = os.getenv('JWT_SESSION_SECRET_KEY')
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_TOKEN_LOCATION'] = ['headers']

# JWT Initialization
jwt = JWTManager(app)
# Bcrypt Initialization
bcrypt = Bcrypt(app)

# Tables
USERS_TABLE = os.getenv('USERS_TABLE')
EXPENDITURE_TABLE = os.getenv('EXPENDITURE_TABLE')
DONATION_TABLE = os.getenv('DONATION_TABLE')
OTHERS_TABLE = os.getenv('OTHERS_TABLE')

AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID1')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY1')
REGION_NAME = os.getenv('REGION_NAME1')

#DynamoDb configuration
dynamodb = boto3.resource('dynamodb',aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY,region_name=REGION_NAME)

user_table = dynamodb.Table(USERS_TABLE)
expenditure_table = dynamodb.Table(EXPENDITURE_TABLE)
donation_table =  dynamodb.Table(DONATION_TABLE)
other_table = dynamodb.Table(OTHERS_TABLE)

@app.route("/")
def hello_from_root():
    return jsonify(message='Hello from root!')


############################################################################
#                                  User                                    #
############################################################################

#Get all users
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    result = user_table.scan()
    data = result['Items']
    # data = {message:"Working"}
    # return make_response(jsonify(error='Working fine 100'), 200)
    if not result:
        return jsonify({'error': 'Could not find user with provided "userId"'}), 404
    return jsonify(
        data
    )
# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    result = user_table.scan(
        FilterExpression=Attr('email').eq(data['email'])
    )
    user = result['Items'][0]
    if user and bcrypt.check_password_hash(user['password'], data['password']):
        access_token = create_access_token(identity=user['email'])
        return jsonify({'message': 'Login Success', 'access_token': access_token})
    return jsonify(
        {
            "message":"Login Failed"
        }
    )
# Add user
@app.route('/create_user', methods=['POST'])
@jwt_required()
def create_user():
    data = request.get_json()
    data['created_at'] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    data['user_id'] = str(uuid.uuid4()).replace('-','')
    data['password'] = bcrypt.generate_password_hash (data['password']).decode('utf-8') 

    response = user_table.put_item(
        Item=data
    )
    return jsonify(
        {
            "message":"User Added"
        }
    )
# Change password
@app.route('/change_password', methods=['PUT'])
@jwt_required()
def change_password():
    data = request.get_json()
    data['email'] = get_jwt_identity()
    print(data)
    result = user_table.scan(
        FilterExpression=Attr('email').eq(data['email'])
    )
    user = result['Items'][0]
    if user and bcrypt.check_password_hash(user['password'], data['current_password']):
        user['password'] = bcrypt.generate_password_hash (data['new_password']).decode('utf-8') 
        response = user_table.put_item(
        Item=user
        )
        return jsonify({'message': 'Password change Success'})
    return jsonify(
        {
            "message":"Invalid request"
        }
    )




############################################################################
#                                  Expenditure                             #
############################################################################

# Get expenditures
@app.route('/expenditure',methods=['GET'])
@jwt_required()
def get_expenditure():
    year = request.args['year']
    # user_id = request.args.get['user_id']
    result = expenditure_table.scan(
        FilterExpression=Attr('created_at').begins_with(year)
    )
    data=result['Items']
    return jsonify(
        data
    )
# Add expenditure
@app.route('/expenditure',methods=['POST'])
@jwt_required()
def post_expenditure():
    data = request.get_json()
    result = expenditure_table.put_item(
                Item = data
            )
    return jsonify({'message': 'Expenditure added successfully'})

############################################################################
#                                  Donations                               #
############################################################################

# Get donations
@app.route('/donations',methods=['GET'])
@jwt_required()
def get_donations():
    year = request.args['year']
    # user_id = request.args.get['user_id']
    result = donation_table.scan(
        FilterExpression=Attr('created_at').begins_with(year)
    )
    return jsonify(
        result['Items']
    )
# Add donations
@app.route('/donations',methods=['POST'])
@jwt_required()
def post_donations():
    data = request.get_json()
    result = donation_table.put_item(
                Item = data
            )
    return jsonify({'message': 'Donation added successfully'})



############################################################################
#                                  Offerings                               #
############################################################################



############################################################################
#                                  Others                                  #
############################################################################

# Error handler
@app.errorhandler(404)
def resource_not_found(e):
    return make_response(jsonify(error='Not found!'), 404)


# Main function
if __name__ == "__main__":
    app.run(debug=True)