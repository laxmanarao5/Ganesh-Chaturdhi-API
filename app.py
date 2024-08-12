import os
from flask import Flask, jsonify, make_response
import boto3
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
USERS_TABLE = os.getenv('USERS_TABLE')
EXPENDITURE_TABLE = os.getenv('EXPENDITURE_TABLE')
DONATION_TABLE = os.getenv('DONATION_TABLE')
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID1')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY1')
REGION_NAME = os.getenv('REGION_NAME1')
dynamodb = boto3.resource('dynamodb',aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY,region_name=REGION_NAME)

user_table = dynamodb.Table(USERS_TABLE)
expenditure_table = dynamodb.Table(EXPENDITURE_TABLE)
donation_table =  dynamodb.Table(DONATION_TABLE)

@app.route("/")
def hello_from_root():
    return jsonify(message='Hello from root!')

@app.route('/users', methods=['GET'])
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

@app.route('/expenditure',methods=['GET'])
def get_expenditure():
    # year = request.args.get['year']
    # user_id = request.args.get['user_id']
    result = expenditure_table.scan()
    data=result['Items']
    if not data:
        return jsonify({'error': 'Could not find user with provided "userId"'}), 404
    return jsonify(
        data
    )

@app.route('/donations',methods=['GET'])
def get_donations():
    # year = request.args.get['year']
    # user_id = request.args.get['user_id']
    # category = request.args.get['category']
    result = donation_table.scan()
    data=result['Items']
    if not data:
        return jsonify({'error': 'Could not find user with provided "userId"'}), 404
    return jsonify(
        data
    )

@app.errorhandler(404)
def resource_not_found(e):
    return make_response(jsonify(error='Not found!'), 404)

if __name__ == "__main__":
    app.run(debug=True)