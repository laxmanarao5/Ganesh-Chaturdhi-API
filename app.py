import os
from flask import Flask, jsonify, make_response, request, send_file
from flask_cors import CORS
import boto3
from dotenv import load_dotenv
load_dotenv()
from boto3.dynamodb.conditions import Attr
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import uuid
import pandas as pd
from io import BytesIO
app = Flask(__name__)
# JWT Configuration
app.config['SECRET_KEY'] = os.getenv('JWT_SESSION_SECRET_KEY')
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

# Allow CORS for specific origins (localhost and CloudFront)
CORS(app, resources={r"/*": {"origins": ["http://localhost:5173", "https://d1gjegky4cxucv.cloudfront.net"]}})

# JWT Initialization
jwt = JWTManager(app)
# Bcrypt Initialization
bcrypt = Bcrypt(app)

# Tables
USERS_TABLE = os.getenv('USERS_TABLE')
EXPENDITURE_TABLE = os.getenv('EXPENDITURE_TABLE')
DONATION_TABLE = os.getenv('DONATION_TABLE')
OTHERS_TABLE = os.getenv('OTHERS_TABLE')
OFFERINGS_TABLE = os.getenv('OFFERINGS_TABLE')

AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID1')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY1')
REGION_NAME = os.getenv('REGION_NAME1')

#DynamoDb configuration
dynamodb = boto3.resource('dynamodb',aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY,region_name=REGION_NAME)

user_table = dynamodb.Table(USERS_TABLE)
expenditure_table = dynamodb.Table(EXPENDITURE_TABLE)
donation_table =  dynamodb.Table(DONATION_TABLE)
others_table = dynamodb.Table(OTHERS_TABLE)
offerings_table = dynamodb.Table(OFFERINGS_TABLE)

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
    result = user_table.scan(
        FilterExpression=(
        (Attr('deleted_at').not_exists() | Attr('deleted_at').eq('')) &
        (Attr('deleted_by').not_exists() | Attr('deleted_by').eq(''))
    )
    )
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
        del user['password']
        access_token = create_access_token(identity=user)
        return jsonify({'message': 'Login Successful', 'access_token': access_token, 'user':user})
    return make_response(jsonify({"error": "Unauthorized access"}), 401)

# Add/Edit/Delete user
@app.route('/user', methods=['POST','PUT'])
@jwt_required()
def create_user():
    data = request.get_json() 
    operation = request.args.get('operation')
    if operation =='delete':
        data['deleted_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['deleted_by'] = get_jwt_identity()['email']
    elif operation =='edit':
        data['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['updated_by'] = get_jwt_identity()['email']
    else:
        data['created_at'] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        data['created_by'] = get_jwt_identity()['email']
        data['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['updated_by'] = get_jwt_identity()['email']
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
    data['email'] = get_jwt_identity()['email']
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
    return make_response(jsonify({"error": "Unauthorized access"}), 401)




############################################################################
#                                  Expenditure                             #
############################################################################

# Get expenditures
@app.route('/expenditure',methods=['GET'])
@jwt_required()
def get_expenditure():
    year = request.args.get('year')
    category = request.args.get('category')
    user = request.args.get('user')
    # Start with the base filter expression for year and deleted flags
    filter_expression = (
        Attr('created_at').begins_with(year) &
        (Attr('deleted_at').not_exists() | Attr('deleted_at').eq('')) &
        (Attr('deleted_by').not_exists() | Attr('deleted_by').eq(''))
    )
    # Conditionally add the filter
    if category:
        filter_expression &= Attr('category').eq(category)
    if user:
        filter_expression &= Attr('created_by').eq(user)
    # Query Db
    result = expenditure_table.scan(
       FilterExpression=filter_expression
    )
    data=result['Items']
    return jsonify(
       { "message":"Expenditure details","data": data, "total": sum(int(item["amount"]) for item in data) }
    )

# Add, Edit and Delete expenditure
@app.route('/expenditure',methods=['POST','PUT'])
@jwt_required()
def edit_expenditure():
    data = request.get_json()
    operation = request.args.get('operation')
    if operation == 'delete':
        data['deleted_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['deleted_by'] = get_jwt_identity()['email']
    elif operation == 'edit':
        data['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['updated_by'] = get_jwt_identity()['email']
    else:
        data['created_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['created_by'] = get_jwt_identity()['email']
        data['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['updated_by'] = get_jwt_identity()['email']
        data['id'] = str(uuid.uuid4()).replace('-','')
    result = expenditure_table.put_item(
                Item = data
            )
    return jsonify({'message': f'Expenditure { 'edited' if operation == 'edit' else 'deleted' if operation == 'delete' else 'added'} successfully'})





############################################################################
#                                  Donations                               #
############################################################################
# Get expenditures
@app.route('/donations',methods=['GET'])
@jwt_required()
def get_donations():
    year = request.args.get('year')
    category = request.args.get('category')
    user = request.args.get('user')
    # Start with the base filter expression for year and deleted flags
    filter_expression = (
        Attr('created_at').begins_with(year) &
        (Attr('deleted_at').not_exists() | Attr('deleted_at').eq('')) &
        (Attr('deleted_by').not_exists() | Attr('deleted_by').eq(''))
    )
    # Conditionally add the filter
    if category:
        filter_expression &= Attr('category').eq(category)
    if user:
        filter_expression &= Attr('created_by').eq(user)
        # Query Db
    result = donation_table.scan(
       FilterExpression=filter_expression
    )
    data=result['Items']
    return jsonify(
        { "message":"Donation details","data": data, "total": sum(int(item["amount"]) for item in data) }
    )

# Add, Edit and Delete donation
@app.route('/donations',methods=['POST','PUT'])
@jwt_required()
def edit_donation():
    operation = request.args.get('operation')
    data = request.get_json()
    if operation == 'delete':
        data['deleted_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['deleted_by'] = get_jwt_identity()['email']
    elif operation == 'edit':
        data['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['updated_by'] = get_jwt_identity()['email']
    else:
        data['created_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['created_by'] = get_jwt_identity()['email']
        data['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['updated_by'] = get_jwt_identity()['email']
        data['id'] = str(uuid.uuid4()).replace('-','')
    result = donation_table.put_item(
                Item = data
            )
    return jsonify({'message': f'Donation { 'edited' if operation == 'edit' else 'deleted' if operation == 'delete' else 'added'} successfully'})


############################################################################
#                                  Offerings                               #
############################################################################

# Get offerings
@app.route('/offerings',methods=['GET'])
@jwt_required()
def get_offerings():
    year = request.args.get('year')
    category = request.args.get('category')
    user = request.args.get('user')
    # Start with the base filter expression for year and deleted flags
    filter_expression = (
        Attr('created_at').begins_with(year) &
        (Attr('deleted_at').not_exists() | Attr('deleted_at').eq('')) &
        (Attr('deleted_by').not_exists() | Attr('deleted_by').eq(''))
    )
    # Conditionally add the filter
    if category:
        filter_expression &= Attr('category').eq(category)
    if user:
        filter_expression &= Attr('created_by').eq(user)
        # Query Db
    result = offerings_table.scan(
        FilterExpression=filter_expression
    )
    data=result['Items']
    return jsonify(
        { "message":"Offerings details","data": data, "total": sum(int(item["amount"]) for item in data) }
    )

# Add, Edit and Delete offering
@app.route('/offering',methods=['PUT','POST'])
@jwt_required()
def edit_offering():
    operation = request.args.get('operation')
    data = request.get_json()
    if operation == 'delete':
        data['deleted_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['deleted_by'] = get_jwt_identity()['email']
    elif operation == 'edit':
        data['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['updated_by'] = get_jwt_identity()['email']
    else:
        data['created_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['created_by'] = get_jwt_identity()['email']
        data['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['updated_by'] = get_jwt_identity()['email']
        data['id'] = str(uuid.uuid4()).replace('-','')
    result = offerings_table.put_item(
                Item = data
            )
    return jsonify({'message': f'Expenditure { 'edited' if operation == 'edit' else 'deleted' if operation == 'delete' else 'added'} successfully'})





############################################################################
#                                  Others                                  #
############################################################################
# Get Others
@app.route('/others',methods=['GET'])
@jwt_required()
def get_others():
    year = request.args.get('year')
    category = request.args.get('category')
    user = request.args.get('user')
    # Start with the base filter expression for year and deleted flags
    filter_expression = (
        Attr('created_at').begins_with(year) &
        (Attr('deleted_at').not_exists() | Attr('deleted_at').eq('')) &
        (Attr('deleted_by').not_exists() | Attr('deleted_by').eq(''))
    )
    # Conditionally add the filter
    if category:
        filter_expression &= Attr('category').eq(category)
    if user:
        filter_expression &= Attr('created_by').eq(user)
        # Query Db
    result = others_table.scan(
       FilterExpression=filter_expression
    )
    data=result['Items']
    return jsonify(
        { "message":"Others details","data": data, "total": sum(int(item["amount"]) for item in data) }
    )

# Add, Edit and Delete others
@app.route('/others',methods=['PUT','POST'])
@jwt_required()
def edit_others():
    data = request.get_json()
    operation = request.args.get('operation')
    if operation == 'delete':
        data['deleted_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['deleted_by'] = get_jwt_identity()['email']
    elif operation == 'edit':
        data['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['updated_by'] = get_jwt_identity()['email']
    else:
        data['created_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['created_by'] = get_jwt_identity()['email']
        data['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['updated_by'] = get_jwt_identity()['email']
        data['id'] = str(uuid.uuid4()).replace('-','')
    result = others_table.put_item(
                Item = data
            )
    return jsonify({'message': f'Others { 'edited' if operation == 'edit' else 'deleted' if operation == 'delete' else 'added'} successfully'})


############################################################################
#                                  Reports                                 #
############################################################################
# Edit and Delete others
@app.route('/reports',methods=['GET'])
def get_reports():
    year = request.args['year']
    excel_data = []
    if request.args['type'] and request.args['type'] == 'expenditure':
        res = expenditure_table.scan(
           FilterExpression=(
        Attr('created_at').begins_with(year) & 
        (Attr('deleted_at').not_exists() | Attr('deleted_at').eq('')) &
        (Attr('deleted_by').not_exists() | Attr('deleted_by').eq(''))
        )
        )

    df = pd.DataFrame(res['Items'])

    # Convert 'created_at' to datetime format and extract the date
    df['created_at'] = pd.to_datetime(df['created_at'])
    df['date'] = df['created_at'].dt.date  # Extract only the date

    # Group the data by the date
    grouped = df.groupby('date')

    # Create an Excel file in memory
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        # Iterate through each date and create a new sheet
        for date, group in grouped:
            # Write the group (data for that date) to a new sheet
            group.drop(columns=['date'], inplace=True)  # Remove the 'date' column
            group.to_excel(writer, index=False, sheet_name=str(date))

    # Seek to the beginning of the file
    output.seek(0)

    # Send the file as a response
    return send_file(output, as_attachment=True, download_name='report_by_date.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')



@app.route('/home',methods=['GET'])
@jwt_required()
def get_home():
    year = request.args.get('year')
    result = expenditure_table.scan(
       FilterExpression=(
        Attr('created_at').begins_with(year) & 
        (Attr('deleted_at').not_exists() | Attr('deleted_at').eq('')) &
        (Attr('deleted_by').not_exists() | Attr('deleted_by').eq(''))
        )
    )
    data = result['Items']
    pooja_expenditure = [item for item in data if item.get('category') == 'Pooja']
    annadhanam_expenditure = [item for item in data if item.get('category') == 'Annadhanam']
    entertainment_expenditure = [item for item in data if item.get('category') == 'Entertainment']
    rent_expenditure = [item for item in data if item.get('category') == 'Rent']
    donations =  donation_table.scan(
       FilterExpression=(
        Attr('created_at').begins_with(year) & 
        (Attr('deleted_at').not_exists() | Attr('deleted_at').eq('')) &
        (Attr('deleted_by').not_exists() | Attr('deleted_by').eq(''))
        )
    )
    annadanam_donations = offerings_table.scan(
       FilterExpression=(
        Attr('created_at').begins_with(year) & 
        (Attr('deleted_at').not_exists() | Attr('deleted_at').eq('')) &
        (Attr('deleted_by').not_exists() | Attr('deleted_by').eq(''))
        )
    )
    others = others_table.scan(
       FilterExpression=(
        Attr('created_at').begins_with(year) & 
        (Attr('deleted_at').not_exists() | Attr('deleted_at').eq('')) &
        (Attr('deleted_by').not_exists() | Attr('deleted_by').eq(''))
        )
    )
    data = [
        {"header":"Pooja Expenditure" ,"value": sum(int(item.get('amount', 0)) for item in pooja_expenditure)},
        {"header":"Annadhanam Expenditure","value": sum(int(item.get('amount', 0)) for item in annadhanam_expenditure)},
        {"header":"Entertainment Expenditure","value": sum(int(item.get('amount', 0)) for item in entertainment_expenditure)},
        {"header":"Rent Expenditure","value": sum(int(item.get('amount', 0)) for item in rent_expenditure)},
        {"header":"Donations","value": sum(int(item.get('amount', 0)) for item in donations['Items'])},
        {"header":"Annadhanam Donations","value": sum(int(item.get('amount', 0)) for item in annadanam_donations['Items'])},
        {"header":"Other","value": sum(int(item.get('amount', 0)) for item in others['Items'])},
    ]
    return jsonify({'message': 'Home data fetched sucessfully', 'data' : data })

# Error handler
@app.errorhandler(404)
def resource_not_found(e):
    return make_response(jsonify(error=e), 404)


# Main function
if __name__ == "__main__":
    app.run(port=5002,debug=True)