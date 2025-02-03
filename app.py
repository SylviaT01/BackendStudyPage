from flask import Flask,make_response, jsonify, request, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from functools import wraps
import traceback
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token, get_jwt, verify_jwt_in_request, decode_token
from models import db, User, Expert, Service, ProjectRequest, ProjectType, Subject, Message as MessageModel, Conversation, Comment
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask_migrate import Migrate
from flask_restful import Resource,Api
from flask_mail import Mail, Message as MessageInstance 
from flask_socketio import SocketIO, emit
import cloudinary.uploader
from random import uniform, randint
from datetime import datetime
from flask import url_for
import os
import re
import random

import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
SECRET_KEY = os.urandom(24)

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
api = Api(app)
app.config["SECRET_KEY"] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///studypage.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = app.config['SECRET_KEY']
app.config['MAIL_SENDER'] = 'studypage001@gmail.com'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'studypage001@gmail.com'
app.config['MAIL_PASSWORD'] = 'hbib knho xqon emrw'  

UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), 'uploads'))
if not os.path.exists(UPLOAD_FOLDER): 
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def send_email_with_mime(subject, body, recipients, attachments=None):
    """
    Send an email using the MIME method.

    :param subject: Email subject
    :param body: Email body (text or HTML)
    :param recipients: List of recipient email addresses
    :param attachments: List of file paths for attachments
    """
    try:
        # SMTP server configuration
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        email_user = "studypage001@gmail.com"
        email_password = "hbib knho xqon emrw"

        # Create the email object
        msg = MIMEMultipart()
        msg['From'] = email_user
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = subject

        # Attach the email body
        msg.attach(MIMEText(body, 'plain'))  # Use 'html' for HTML content

        # Attach files if provided
        if attachments:
            for file_path in attachments:
                try:
                    # Open the file in binary mode
                    with open(file_path, 'rb') as file:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(file.read())
                    
                    # Encode the file in ASCII to send as email
                    encoders.encode_base64(part)

                    # Add header to the attachment
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename={file_path.split("/")[-1]}'
                    )
                    msg.attach(part)
                except Exception as e:
                    print(f"Failed to attach file {file_path}: {e}")

        # Connect to the SMTP server and send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(email_user, email_password)
            server.sendmail(email_user, recipients, msg.as_string())
        
        print("Email sent successfully!")
    
    except Exception as e:
        print(f"Failed to send email: {e}")

def send_email_with_mime(subject, body, recipients, attachments=None):
    """
    Send an email using the MIME method.

    :param subject: Email subject
    :param body: Email body (text or HTML)
    :param recipients: List of recipient email addresses
    :param attachments: List of file paths for attachments
    """
    try:
        # SMTP server configuration
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        email_user = "studypage001@gmail.com"
        email_password = "hbib knho xqon emrw"

        # Create the email object
        msg = MIMEMultipart()
        msg['From'] = email_user
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = subject

        # Attach the email body
        msg.attach(MIMEText(body, 'plain'))  # Use 'html' for HTML content

        # Attach files if provided
        if attachments:
            for file_path in attachments:
                try:
                    # Open the file in binary mode
                    with open(file_path, 'rb') as file:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(file.read())
                    
                    # Encode the file in ASCII to send as email
                    encoders.encode_base64(part)

                    # Add header to the attachment
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename={file_path.split("/")[-1]}'
                    )
                    msg.attach(part)
                except Exception as e:
                    print(f"Failed to attach file {file_path}: {e}")

        # Connect to the SMTP server and send the email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(email_user, email_password)
            server.sendmail(email_user, recipients, msg.as_string())
        
        print("Email sent successfully!")
    
    except Exception as e:
        print(f"Failed to send email: {e}")

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
mail = Mail(app) 
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
CORS(app,resources={r"/*": {"origins": "http://localhost:3001"}})

# PAYSTACK_SECRET_KEY ="sk_test_e43f7706b3578021e3dc09d1ad730bf60c2e33c8"
PAYSTACK_SECRET_KEY =os.environ.get('PAYSTACK_SECRET_KEY')
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    """
    Verify Paystack payment using the transaction reference.
    """
    data = request.json
    reference = data.get('reference')
    project_details = data.get('projectDetails') 

    if not reference:
        return jsonify({"success": False, "message": "Transaction reference is required"}), 400

    try:
        url = f"https://api.paystack.co/transaction/verify/{reference}"
        headers = {
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"
        }
        response = requests.get(url, headers=headers)
        response_data = response.json()

        if response_data['status'] and response_data['data']['status'] == "success":
            return jsonify({
                "success": True,
                "message": "Payment verified and project submitted!",
                "transaction_data": response_data['data']  
            }), 200

        else:
            return jsonify({
                "success": False,
                "message": "Payment verification failed. Please try again."
            }), 400

    except Exception as e:
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500

@app.route('/admin/update-expert-features', methods=['POST'])
def update_expert_features():
    try:
        experts = Expert.query.all()
        
        for expert in experts:
            expert.is_ai_free = random.random() < 0.6
        
        db.session.commit()
        return jsonify({'message': 'Expert features updated successfully'}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/experts/<int:expert_id>/comments', methods=['GET'])
def get_expert_comments(expert_id):
    comments = Comment.query.filter_by(expert_id=expert_id).order_by(Comment.created_at.desc()).all()
    return jsonify({
        'comments': [{
            'id': comment.id,
            'content': comment.content,
            'created_at': comment.created_at.isoformat(),
            # 'user_name': comment.user.username,
            'user_id': comment.user_id
        } for comment in comments]
    })

@app.route('/experts/<int:expert_id>/comments/<int:currentUser_id>', methods=['POST'])
# @jwt_required()
def add_expert_comment(expert_id,currentUser_id):
    data = request.get_json()
    comment = Comment(
        content=data['content'],
        expert_id=expert_id,
        user_id=currentUser_id
    )
    db.session.add(comment)
    db.session.commit()
    return jsonify({
        'message': 'Comment added successfully',
        'comment': {
            'id': comment.id,
            'content': comment.content,
            'created_at': comment.created_at.isoformat(),
            # 'user_name': comment.user.username,
            'user_id': comment.user_id
        }
    })

@app.route('/admin/update-expert-stats', methods=['POST'])
def update_expert_stats():
    try:
        experts = Expert.query.all()
        
        for expert in experts:
            expert.rating_avg = round(uniform(4.0, 5.0), 1)
            
            expert.total_reviews = randint(15, 50)
            
            expert.success_rate = round(uniform(92.0, 99.0), 1)
        
        db.session.commit()
        return jsonify({'message': 'Expert statistics updated successfully'}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/test', methods=['GET'])
def test():
    """A simple test endpoint to ensure the server is running."""
    return jsonify({"message": "Server is running!"})

# @app.route('/messages', methods=['GET'])
# def get_messages():
#     messages = Message.query.all()  # Get all messages from the database
#     message_list = [{'user': message.sender.username, 'message': message.content} for message in messages]
#     return {'messages': message_list}

@app.route('/auth/google', methods=['POST'])
def google_signup():
    data = request.json
    print(f"Received data: {data}")

    # Check if the required fields are present
    if 'username' not in data or 'email' not in data:
        print("Missing required fields")
        return jsonify({'error': 'Missing required fields'}), 400

    # Check if the user already exists
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        print("User with this email already exists. Logging in...")
        # Automatically log in the user
        session['user_id'] = existing_user.id
        access_token = create_access_token(identity=existing_user.id)
        return jsonify({
            'success': True,
            'authToken': access_token,
            'user_id': existing_user.id,
            'email': existing_user.email,
            'username': existing_user.username,
            'is_admin': existing_user.is_admin
        }), 200

    # If the user doesn't exist, create a new user
    placeholder_password = bcrypt.generate_password_hash('placeholder_password')
    new_user = User(
        username=data['username'],
        email=data['email'],
        password=placeholder_password,  
        is_admin=False,  
        phone_number=None  
    )

    # Add to session and commit to the database
    try:
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error committing to the database: {e}")
        return jsonify({'error': 'Failed to create user'}), 500

    # Send an email to set their password
    token = s.dumps(new_user.email, salt='password-reset-salt')
    reset_url = url_for('reset_password', token=token, _external=True)
    msg = Message('Set Your Password', sender=app.config['MAIL_SENDER'], recipients=[new_user.email])
    msg.body = f'Please click the following link to set your password: {reset_url.replace("http://127.0.0.1:5000", "http://localhost:3001")}'
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")
        return jsonify({'error': 'Failed to send email'}), 500

    # Automatically log in the new user
    session['user_id'] = new_user.id

    return jsonify({
        'success': True,  
        'user_id': new_user.id,
        'email': new_user.email,
        'username': new_user.username
    }), 201




@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Verify the token
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        return jsonify({'error': 'The token is expired'}), 400
    except BadTimeSignature:
        return jsonify({'error': 'Invalid token'}), 400

    if request.method == 'POST':
        # Get the new password from the request
        new_password = request.json.get('new_password')
        if not new_password:
            return jsonify({'error': 'Missing new password'}), 400

        # Find the user by email
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User  not found'}), 404

        # Update the user's password
        user.password = bcrypt.generate_password_hash(new_password)
        db.session.commit()

        return jsonify({'success': 'Password updated successfully'}), 200

    # For GET requests, return a 200 status with a message indicating the frontend handles the reset
    return '', 200

from flask import request, jsonify, url_for
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@app.route('/auth/forgot_password', methods=['POST'])
def forgot_password():
    """
    Handles user requests to reset their password.
    Sends an email with a reset link if the email exists in the database.
    """
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    # Check if the user exists
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'No user found with this email'}), 404

    # Generate a secure token
    token = s.dumps(user.email, salt='password-reset-salt')
    reset_url = url_for('reset_password', token=token, _external=True)

    # Prepare the email message
    msg = Message(
        'Reset Your Password',
        sender=app.config['MAIL_SENDER'],
        recipients=[user.email]
    )
    msg.body = f'''
    Hello {user.username},
    
    We received a request to reset your password. Click the link below to reset it:
    {reset_url.replace("http://127.0.0.1:5000", "http://localhost:3001")}

    If you didn't request this, you can ignore this email.

    Regards,
    Your App Team
    '''

    # Send the email
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")
        return jsonify({'error': 'Failed to send email'}), 500

    return jsonify({'success': 'Password reset link sent to your email'}), 200



# Admin Messages Route
@app.route('/adminmessages', methods=['GET'])
@jwt_required()  # Ensure the request is coming from a valid user (admin)
def get_admin_messages():
    # Get the current logged-in user (admin in this case)
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin user is not authenticated or found'}), 403

    # Fetch messages sent to the admin user
    messages = MessageModel.query.filter_by(receiver_id=current_user.id).all()
    messages = MessageModel.query.filter_by(receiver_id=current_user.id).all()

    if not messages:
        return jsonify({'message': 'No messages for admin'}), 404

    # Format the messages to return them as a list
    message_list = [{'user': message.sender.username, 'message': message.content} for message in messages]

    return jsonify({'messages': message_list}), 200

@app.route("/usermessages", methods=["GET"])
@jwt_required()  # Ensure the user is logged in
def get_user_messages():
    current_user_id = get_jwt_identity()  # Retrieve the current logged-in user's ID
    current_user = User.query.get(current_user_id)  # Fetch the user from the database

    if not current_user:
        return jsonify({"message": "User not found"}), 404

    # Retrieve messages that are sent to the current user
    messages = MessageModel.query.filter_by(receiver_id=current_user.id).all()
    messages = MessageModel.query.filter_by(receiver_id=current_user.id).all()

    # Format messages for the response
    message_list = [{'user': message.sender.username, 'message': message.content} for message in messages]

    return jsonify({'messages': message_list}), 200



# Create the folder if it doesn't exist
# if not os.path.exists(UPLOAD_FOLDER):
#     os.makedirs(UPLOAD_FOLDER)

# Define allowed file extensions (optional)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        user = User.query.filter_by(id=current_user).first()
        if not user.is_admin:
            return jsonify({'message': 'Admin access required'}), 403
        return fn(*args, **kwargs)
    return wrapper

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Check if the required fields are present
    if 'username' not in data or 'email' not in data or 'password' not in data or 'phone_number' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if the user already exists
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'error': 'User with this email already exists'}), 400
    
    # Hash the password
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    # Create a new user object
    new_user = User(
        username=data['username'],
        email=data['email'],
        password=hashed_password,
        is_admin=False,
        phone_number=data['phone_number']
    )

    # Add to the database and commit
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'success': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    # Query the user by email
    user = User.query.filter_by(email=email).first()

    # Check if the user exists and the password is correct
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        # Return tokens and the user's role
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "is_admin": user.is_admin  # Include the user's role
        })
    else:
        return jsonify({"message": "Invalid username or password"}), 401

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id)
    return jsonify({"access_token": new_access_token}), 200

@app.route("/current_user", methods=["GET"])
@jwt_required()
def get_current_user():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    if current_user:
        return jsonify({
            "id": current_user.id, 
            "username": current_user.username, 
            "email": current_user.email,
            "is_admin": current_user.is_admin
        }), 200
    else:
        return jsonify({"message": "User not found"}), 404



BLACKLIST = set()
# @jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, decrypted_token):
    jti = decrypted_token["jti"]
    return jti in BLACKLIST

@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    BLACKLIST.add(jti)
    return jsonify({"success":"Logged out successfully"}), 200

@app.route('/verify_password', methods=['POST'])
@jwt_required()
def verify_password():
    data = request.get_json()
    existing_password = data.get('existing_password', None)

    # Get the current user's ID from the JWT
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if not current_user:
        return jsonify({"success": False, "error": "User  not found"}), 404

    # Debugging: Log the current user's password hash and the existing password
    print(f"Current user's password hash: {current_user.password}")
    print(f"Existing password provided: {existing_password}")

    # Check if the existing password matches the stored password
    if existing_password and check_password_hash(current_user.password, existing_password):
        return jsonify({"success": True}), 200
    else:
        return jsonify({"success": False, "error": "Incorrect password"}), 401


@app.route('/update_profile', methods=['PUT'])
@jwt_required()
def update_profile():
    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if not current_user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()

    # Update username if provided
    if 'username' in data:
        current_user.username = data['username']

    if 'phone_number' in data:
        current_user.phone_number = data['phone_number']
    if 'email' in data:
        current_user.email = data['email']

    # Update password if provided
    if 'password' in data:
        new_password = data['password']
        if not re.match(r'(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-zA-Z]).{8,}', new_password):
            return jsonify({"error": "Password must be at least 8 characters long and include numbers and symbols."}), 400
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        current_user.password = hashed_password

    # Commit changes to the database
    try:
        db.session.commit()
        return jsonify({"success": "Profile updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to update profile"}), 500



@app.route('/admin/users', methods=['GET'])
@jwt_required()
@admin_required
def get_users():
    users = User.query.all()
    users_list = [{'id': user.id, 'username': user.username, 'email': user.email, 'is_admin': user.is_admin} for user in users]
    return jsonify({'users': users_list})

@app.route('/admin/users/<int:id>', methods=['PATCH'])
@jwt_required()
@admin_required
def update_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    data = request.get_json()
    is_admin = data.get('is_admin')
    
    if is_admin is not None:
        user.is_admin = is_admin
        db.session.commit()
        return jsonify({'message': 'User updated successfully'})
    return jsonify({'message': 'No updates provided'}), 400



@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user_id = get_jwt_identity()  # This retrieves the user ID
    current_user = User.query.get(current_user_id)  # Fetch the user object from the database

    if not current_user or not current_user.is_admin:
        return jsonify({'message': 'Admin access required'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User deleted successfully'})



@app.route('/admin/users', methods=['POST'])
@jwt_required()  # Ensure only authenticated users can access this route
def add_user():
    data = request.get_json()

    # Validate input data
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('is_admin', False)  # Default to False if not provided

    if not username or not email or not password:
        return jsonify({'message': 'Username, email, and password are required.'}), 400

    # Check if user already exists
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        return jsonify({'message': 'User with this username or email already exists.'}), 400

    # Hash the password using bcrypt before saving
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create the new user with hashed password
    new_user = User(username=username, email=email, password=hashed_password, is_admin=is_admin)

    # Add and commit the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully.', 'user_id': new_user.id}), 201

@app.route('/experts', methods=['GET'])
def get_experts():
    experts = Expert.query.all()  # Fetch all experts from the database
    output = []

    for expert in experts:
        success_rate_str = f"{expert.success_rate:.1f}%" if expert.success_rate is not None else "0.0%"
        comments = []
        for comment in expert.comments:
            comment_data = {
                'id': comment.id,
                'content': comment.content,
                'created_at': comment.created_at.isoformat(),
                # 'user_name': comment.user.username  
            }
            comments.append(comment_data)

        expert_data = {
            'id': expert.id,
            'name': expert.name,
            'title': expert.title,
            'expertise': expert.expertise,
            'description': expert.description,
            'biography': expert.biography,
            'education': expert.education,
            'languages': expert.languages,
            'projectType': expert.project_type.name if expert.project_type else None,  # Corrected to use `project_type`
            'subject': expert.subject.name if expert.subject else None,  # Corrected to use `subject`
            'profilePicture': expert.profile_picture,
            'rating': expert.rating_avg,
            'totalReviews': expert.total_reviews,
            'successRate': success_rate_str,
            'isAiFree': expert.is_ai_free,
            'comments': comments
        }
        output.append(expert_data)

    return jsonify({'experts': output})

@app.route('/comments/<int:comment_id>', methods=['PATCH'])
@jwt_required()
def update_comment(comment_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id) 
    if not current_user.is_admin:
        return jsonify({'message': 'Unauthorized'}), 403
        
    comment = Comment.query.get_or_404(comment_id)
    data = request.get_json()
    
    if 'content' in data:
        comment.content = data['content']
        db.session.commit()
        
    return jsonify({
        'id': comment.id,
        'content': comment.content,
        'created_at': comment.created_at.isoformat(),
        'user_name': comment.user.username
    })

@app.route('/comments/<int:comment_id>', methods=['DELETE'])
# @jwt_required()
def delete_comment(comment_id):
    # current_user_id = get_jwt_identity()
    # current_user = User.query.get(current_user_id) 
    # if not current_user.is_admin:
        # return jsonify({'message': 'Unauthorized'}), 403
        
    comment = Comment.query.get_or_404(comment_id)  
    db.session.delete(comment)
    db.session.commit()
    
    return '', 204

class Projects(Resource):
    @jwt_required()
    def get(self):
        projects = ProjectRequest.query.all()
        if projects:
            project_list = []
            for project in projects:
                user = User.query.filter_by(id=project.user_id).first()
                expert = Expert.query.filter_by(id=project.expert_id).first()

                project_list.append({
                    'client_name': user.username if user else "Unknown Client",
                    'expert_name': expert.name if expert else "Unknown Expert",
                    'project_title': project.project_title,
                    'project_description': project.project_description,
                    'status': project.status,
                    'deadline': project.deadline.strftime('%Y-%m-%d'),
                    'attachments': project.attachments,
                    'number_of_pages': project.number_of_pages,
                    'project_id': project.id
                })

            response = make_response(jsonify(project_list), 200)
        else:
            response = make_response(jsonify({'error': 'No projects found'}), 404)
        return response

@app.route('/projects/<int:project_id>', methods=['GET'])
@jwt_required()
def get_project_details(project_id):
    project = ProjectRequest.query.get_or_404(project_id)

    response = {
        'project_title': project.project_title,
        'project_description': project.project_description,
        'deadline': project.deadline.strftime('%Y-%m-%d'),
        'attachments': project.attachments,  # Ensure this is a URL or file reference
        'client_name': project.user.username if project.user else "Unknown",
    }
    return jsonify(response)

@app.route('/projects/<int:project_id>/submit', methods=['POST'])
@jwt_required()
def submit_project(project_id):
    project = ProjectRequest.query.get_or_404(project_id)

    # Parse form data for submission
    files = request.files.getlist('files')  # Multiple file uploads
    comments = request.form.get('comments')

    # Save files and handle logic
    for file in files:
        file.save(f"uploads/{file.filename}")

    project.status = 'Completed'
    db.session.commit()

    return jsonify({'message': 'Project submitted successfully'})

@app.route('/request_expert', methods=['POST'])
@jwt_required()
def request_expert():
    data = request.form
    files = request.files.getlist('attachments')

    deadline_str = data.get('deadline') 
    deadline_str = data.get('deadline') 
    try:
        deadline = datetime.strptime(deadline_str, "%Y-%m-%d")
    except ValueError:
        return jsonify({"error": "Invalid deadline format. Use YYYY-MM-DD."}), 400

    # Save the project request
    project = ProjectRequest(
        project_title=data.get('project_title'),
        project_description=data.get('project_description'),
        project_type_id=data.get('project_type'),
        subject_id=data.get('subject'),
        deadline=deadline,
        expert_id=data.get('expert_id'),
        user_id=get_jwt_identity(),
        number_of_pages=data.get('number_of_pages')
    )
    db.session.add(project)
    db.session.commit()

    attachments = []
    for file in files:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        file_url = url_for('serve_file', filename=filename, _external=True)
        attachments.append(file_url)
    project.attachments = ','.join(attachments)
    db.session.commit()

    conversation = Conversation.query.filter_by(
        
        client_id=get_jwt_identity(),
        expert_id=data.get('expert_id'),
    ).first()


    if not conversation:
        conversation = Conversation(
            client_id=get_jwt_identity(),
            expert_id=data.get('expert_id'),
            project_id=project.id
        )
        db.session.add(conversation)
        db.session.commit()

    message = MessageModel(
        conversation_id=conversation.id,
        sender_id=get_jwt_identity(),
        content=f"New project submitted: {project.project_title}\nDescription: {project.project_description}\nDeadline: {project.deadline.strftime('%Y-%m-%d')}",
        attachments=project.attachments,
        receiver_id=data.get('expert_id'),
        expert_id=data.get('expert_id')
    )
    db.session.add(message)
    db.session.commit()

    email_subject = "New Project Request Submitted"
    email_body = f"""
    A new project has been submitted with the following details:

    Title: {project.project_title}
    Description: {project.project_description}
    Deadline: {project.deadline.strftime('%Y-%m-%d')}
    Attachments: {', '.join(attachments)}
    """

    send_email_with_mime(
        subject=email_subject,
        body=email_body,
        recipients=['shadybett540@gmail.com', 'studypage001@gmail.com'],
        attachments=[os.path.join(app.config['UPLOAD_FOLDER'], filename) for filename in attachments]
    )
    return jsonify({'message': 'Project submitted successfully', 'conversation_id': conversation.id}), 201
@app.route('/conversationsadmin/<int:conversation_id>/messages', methods=['POST'])
@jwt_required()
def admn_send_message(conversation_id):
    try:
        sender_id = get_jwt_identity()

        conversation = Conversation.query.get_or_404(conversation_id)
        recievers_id = conversation.client_id
        receivers_email = User.query.get(recievers_id).email
        experts_id = conversation.expert_id
        experts_name = User.query.get(experts_id).username
        experts_email = User.query.get(experts_id).email

        content = request.form.get('content')
        files = request.files.getlist('attachments')

        if not content and not files:
            return jsonify({'error': 'Message content or attachments are required.'}), 400

        attachments = []
        if files:
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(filepath)
                    
                    # Convert server path to URL
                    file_url = url_for('serve_file', filename=filename, _external=True)
                    attachments.append(file_url)
                else:
                    return jsonify({'error': f'Invalid file type: {file.filename}'}), 400

        message = MessageModel(
            conversation_id=conversation_id,
            sender_id=sender_id,
            receiver_id=conversation.client_id if sender_id != conversation.client_id else conversation.expert_id,
            content=content,
            attachments=', '.join(attachments) if attachments else None
        )
        db.session.add(message)
        db.session.commit()

        sender = User.query.get(sender_id)
        email_subject = "New Message Notification"
        email_body = f"""
        A new message has been sent by expert {experts_name}.

        Sender: {experts_name} (Email: {experts_email})
        Content: {content or 'No content'}
        Attachments: {', '.join(attachments) if attachments else 'None'}

        Please log in to the website to respond.
        """

        attachment_paths = [url.replace(app.config['UPLOAD_FOLDER'], '') for url in attachments]

        send_email_with_mime(
            subject=email_subject,
            body=email_body,
            recipients=['shadrack.bett.92@gmail.com',receivers_email],
            attachments=attachment_paths
        )
        return jsonify(message.to_dict()), 201

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@app.route('/conversations', methods=['POST'])
@jwt_required()
def create_conversation():
    data = request.get_json()
    sender_id = get_jwt_identity()
    
    conversation = Conversation(
        client_id=sender_id,
        expert_id=data.get('expert_id'),
        project_id=data.get('project_id')
    )
    
    db.session.add(conversation)
    db.session.commit()
    
    return jsonify({
        'conversation_id': conversation.id,
        'client_id': conversation.client_id,
        'expert_id': conversation.expert_id
    }), 201

@app.route('/conversations/<conversation_id>/messages', methods=['POST'])
@jwt_required()
def send_message(conversation_id):
    try:
        sender_id = get_jwt_identity()
        content = request.form.get('content','').strip()
        files    = request.files.getlist('attachments')

        try:
            conversation_id = int(conversation_id)
        except ValueError:
            return jsonify({'error': 'Invalid conversation ID'}), 400
        
        if conversation_id == -1:
            expert_id = request.form.get('expert_id')
            if not expert_id:
                return jsonify({'error': 'Expert ID is required for new conversations'}), 400

            conversation = Conversation.query.filter_by(
                client_id=sender_id,
                expert_id=expert_id
            ).first()
            if not conversation:
                conversation = Conversation(
                    client_id=sender_id,
                    expert_id=expert_id
                )
                db.session.add(conversation)
                db.session.commit()
            conversation_id = conversation.id
            conversation = Conversation.query.get_or_404(conversation_id)
            return jsonify({'conversation_id': conversation_id}), 201
            # print(f"Creating message with: conversation_id={conversation_id}, sender_id={sender_id}, content='{content}', attachments={files}")
        else:
            conversation = Conversation.query.get_or_404(conversation_id)
            print(f"Creating message with: conversation_id={conversation_id}, sender_id={sender_id}, content='{content}', attachments={files}")

        content = request.form.get('content','').strip()
        files = request.files.getlist('attachments')

        if not content and not files:
            return jsonify({'error': 'Message content or attachments are required.'}), 400

        attachments = []
        if files:
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(filepath)
                    file_url = url_for('serve_file', filename=filename, _external=True)
                    attachments.append(file_url)
                else:
                    return jsonify({'error': f'Invalid file type: {file.filename}'}), 400

        message = MessageModel(
            conversation_id=conversation_id,
            sender_id=sender_id,
            receiver_id=conversation.client_id if sender_id != conversation.client_id else conversation.expert_id,
            content=content,
            attachments=', '.join(attachments) if attachments else None
        )
        db.session.add(message)
        db.session.commit()
        socketio.emit('new_message', {
            'conversation_id': conversation_id,
            'sender_id': sender_id,
            'receiver_id': message.receiver_id,
            'message': message.to_dict()
        })

        sender = User.query.get(sender_id)
        email_subject = "New Message Notification"
        email_body = f"""
        A new message has been sent by client {sender.username}.

        Sender: {sender.username} (Email: {sender.email})
        Content: {content or 'No content'}
        Attachments: {', '.join(attachments) if attachments else 'None'}

        Please log in to the website to respond.
        """

        attachment_paths = [url.replace(app.config['UPLOAD_FOLDER'], '') for url in attachments]

        send_email_with_mime(
            subject=email_subject,
            body=email_body,
            recipients=['shadrack.bett.92@gmail.com','studypage001@gmail.com'],
            attachments=attachment_paths
        )
        return jsonify(message.to_dict()), 201
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500
    
@app.route('/admin/conversations', methods=['GET'])
@jwt_required()
def admin_get_conversations():
    try:
        conversations = Conversation.query.all()
        
        data = []
        for conv in conversations:
            # Get the latest message
            latest_message = (MessageModel.query
                            .filter_by(conversation_id=conv.id)
                            .order_by(MessageModel.timestamp.desc())
                            .first())
            
            client = User.query.get(conv.client_id)
            expert = User.query.get(conv.expert_id)

            message_content = "No messages yet"
            if latest_message:
                if latest_message.attachments:
                    # Get number of attachments
                    num_attachments = len(latest_message.attachments.split(', '))
                    file_text = "files" if num_attachments > 1 else "file"
                    message_content = f"📎 Sent {num_attachments} {file_text}"
                    if latest_message.content:
                        message_content += f": {latest_message.content}"
                else:
                    message_content = latest_message.content
            
            conversation_data = {
                "conversation_id": conv.id,
                "client": client.username if client else "Unknown",
                "expert": expert.username if expert else "Unassigned",
                "last_message": message_content,
                "is_file": bool(latest_message and latest_message.file_path if hasattr(latest_message, 'file_path') else False),
                "last_timestamp": latest_message.timestamp.strftime('%Y-%m-%d %H:%M:%S') if latest_message else None,
                "created_at": conv.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            }
            data.append(conversation_data)
        
        # Sort by last_timestamp or created_at
        data.sort(key=lambda x: x['last_timestamp'] or x['created_at'], reverse=True)
        
        return jsonify(data), 200
    except Exception as e:
        print("Error fetching conversations:", e)
        return jsonify({"error": "Unable to fetch conversations"}), 500
# @app.route('/admin/conversations', methods=['GET'])
# @jwt_required()
# def admin_get_conversations():
#     try:
#         conversations = Conversation.query.all()

#         data = []
#         for conv in conversations:
#             client = User.query.get(conv.client_id)
#             expert = User.query.get(conv.expert_id)

#             conversation_data = {
#                 "conversation_id": conv.id,
#                 "client": client.username if client else "Unknown",
#                 "expert": expert.username if expert else "Unassigned",
#                 "last_message": conv.messages[-1].content if conv.messages else None,
#                 "last_timestamp": conv.messages[-1].timestamp.strftime('%Y-%m-%d %H:%M:%S') if conv.messages else None,
#                 "created_at": conv.created_at.strftime('%Y-%m-%d %H:%M:%S'),
#             }
#             data.append(conversation_data)

#         return jsonify(data), 200
#     except Exception as e:
#         print("Error fetching conversations:", e)
#         return jsonify({"error": "Unable to fetch conversations"}), 500

@app.route('/admin/conversations/<int:conversationId>/messages', methods=['GET'])
@jwt_required()
def get_conversation_messages(conversationId):
    try:
        conversation = Conversation.query.get_or_404(conversationId)
        messages = [message.to_dict() for message in conversation.messages]
        return jsonify(messages), 200
    except Exception as e:
        # Log the error for debugging
        app.logger.error(f"Error fetching messages: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500

@app.route('/admin/conversations/<int:conversation_id>/messages', methods=['POST'])
@jwt_required()
def send_admin_message(conversation_id):
    data = request.json
    content = data.get('content')
    attachments = data.get('attachments', [])
    
    if not content and not attachments:
        return jsonify({'error': 'Message content or attachments are required.'}), 400

    message = MessageModel(
        conversation_id=conversation_id,
        sender_id=get_jwt_identity(),  # Admin's ID
        content=content,
        attachments=', '.join(attachments) if attachments else None,
    )
    db.session.add(message)
    db.session.commit()
    return jsonify(message.to_dict()), 201


@app.route('/uploads/<filename>', methods=['GET'])
def serve_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404

@app.route('/my_requests', methods=['GET'])
@jwt_required()  # Ensure that the user is authenticated
def get_user_requests():
    try:
        # Get current user details using JWT identity
        current_user_id = get_jwt_identity()  # Get the current logged-in user ID
        current_user = User.query.get(current_user_id)
        
        if not current_user:
            return jsonify({'msg': 'User not found'}), 404

        # Query all project requests related to the current user
        user_requests = ProjectRequest.query.filter_by(user_id=current_user.id).all()

        # If no requests exist, return an empty response with a message
        if not user_requests:
            return jsonify({'msg': 'No project requests found for this user'}), 404

        # Prepare the data to return (you can filter fields based on what you need)
        requests_data = []
        for request in user_requests:
            requests_data.append({
                'project_title': request.project_title,
                'project_description': request.project_description,
                'project_type': request.project_type.name if request.project_type else None,
                'subject': request.subject.name if request.subject else None,
                'expert': request.expert.name if request.expert else None,
                'deadline': request.deadline.strftime('%Y-%m-%d'),
                'attachments': request.attachments.split(','),  # Assuming attachments are stored as a comma-separated string
                'number_of_pages': request.number_of_pages
            })

        return jsonify({'msg': 'Project requests fetched successfully', 'data': requests_data}), 200

    except Exception as e:
        print(f"Error occurred: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/conversations/<int:conversation_id>/messages', methods=['GET'])
@jwt_required()
def get_messages(conversation_id):
    try:
        conversation = Conversation.query.get_or_404(conversation_id)
        messages = [message.to_dict() for message in conversation.messages]
        return jsonify(messages), 200
    except Exception as e:
        # Log the error for debugging
        app.logger.error(f"Error fetching messages: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500

# @app.route('/conversations', methods=['GET'])
# @jwt_required()
# def get_conversations():
#     user_id = get_jwt_identity()

#     # Query conversations where the user is either a client or linked to an expert
#     conversations = Conversation.query.filter(
#         (Conversation.client_id == user_id) | (Conversation.expert_id == user_id)
#     ).all()

#     # Prepare response with related expert details
#     response = []
#     for conv in conversations:
#         expert = Expert.query.get(conv.expert_id)
#         response.append({
#             'id': conv.id,
#             'client_id': conv.client_id,
#             'expert_id': conv.expert_id,
#             'project_id': conv.project_id,
#             'created_at': conv.created_at.strftime('%Y-%m-%d %H:%M:%S'),
#             'expert': {
#                 'id': expert.id,
#                 'name': expert.name
#             } if expert else None
#         })

#     return jsonify(response), 200

@app.route('/conversations', methods=['GET'])
@jwt_required()
def get_conversations():
    user_id = get_jwt_identity()

    conversations = Conversation.query.filter(
        (Conversation.client_id == user_id) | (Conversation.expert_id == user_id)
    ).all()

    result = []
    for conversation in conversations:
        latest_message = MessageModel.query.filter_by(conversation_id=conversation.id).order_by(
            MessageModel.timestamp.desc()
        ).first()

        unread_count = MessageModel.query.filter_by(
            conversation_id=conversation.id,
            receiver_id=user_id,
            read=False
        ).count()

        message_content = "No messages yet"
        if latest_message:
            if latest_message.attachments:
                num_attachments = len(latest_message.attachments.split(', '))
                file_text = "files" if num_attachments > 1 else "file"
                message_content = f"📎 Sent {num_attachments} {file_text}"
                if latest_message.content:
                    message_content += f": {latest_message.content}"
            else:
                message_content = latest_message.content
        result.append({
            'id': conversation.id,
            'expert': {
                'id': conversation.expert_id,
                'expert_name': Expert.query.get(conversation.expert_id).name
            },
            'client': {
                'id': conversation.client_id,
                'client_name': User.query.get(conversation.client_id).username
            },
            'latest_message': message_content,
            'is_file': bool(latest_message and latest_message.file_path if hasattr(latest_message, 'file_path') else False),
            'timestamp': latest_message.timestamp.isoformat() if latest_message else None,
            'unread_count': unread_count,
        })

    result.sort(key=lambda x: x['timestamp'] if x['timestamp'] else '', reverse=True)
    return jsonify(result)

@app.route('/experts/<int:id>', methods=['GET'])
def get_expert(id):
    expert = Expert.query.get(id)
    if not expert:
        return jsonify({'message': 'Expert not found'}), 404

    expert_data = {
        'id': expert.id,
        'name': expert.name,
        'title': expert.title,
        'expertise': expert.expertise,
        'description': expert.description,
        'biography': expert.biography,
        'education': expert.education,
        'languages': expert.languages,
        'projectTypes': expert.project_types,
        'subjects': expert.subjects,
        'profilePicture': expert.profile_picture  
    }
    return jsonify({'expert': expert_data})

@app.route("/experts", methods=["POST"])
def add_expert():
    data = request.get_json()
    project_type_id = data.get("project_type_id")
    subject_id = data.get("subject_id")

    print(f"Received project_type_id: {project_type_id}, subject_id: {subject_id}")  # Debug log

    if len(project_type_id) > 5 or len(subject_id) > 5:
        return {"message": "You can select up to 5 project types and 5 subjects."}, 400
    
    profile_picture = data.get("profile_picture")
    if not profile_picture:
        return jsonify({"error": "Profile picture is required"}), 400

    project_type = ProjectType.query.get(project_type_id)
    subject = Subject.query.get(subject_id)

    if not project_type or not subject:
        return jsonify({"error": "Invalid project type or subject"}), 400
    
    # Create and save the expert
    new_expert = Expert(
        name=data["name"],
        title=data["title"],
        expertise=data["expertise"],
        description=data["description"],
        biography=data["biography"],
        education=data["education"],
        languages=data["languages"],
        profile_picture=profile_picture,
        project_type=project_type,
        subject=subject
    )

    db.session.add(new_expert)
    db.session.commit()

    return jsonify({"message": "Expert added successfully!"}), 201


@app.route('/experts/<int:id>', methods=['PATCH'])
@jwt_required()
def partial_update_expert(id):
    user_id = get_jwt_identity()
    
    # Query the user based on the ID returned by get_jwt_identity()
    user = User.query.get(user_id)
    
    # Check if the user exists and is an admin
    if not user or not user.is_admin:
        return jsonify({'message': 'Permission denied'}), 403

    expert = Expert.query.get(id)
    if not expert:
        return jsonify({'message': 'Expert not found'}), 404

    data = request.get_json()
    print(f"Incoming data for update: {data}")

    # Update expert fields based on the provided data
    if 'name' in data:
        expert.name = data['name']
    if 'title' in data:
        expert.title = data['title']
    if 'expertise' in data:
        expert.expertise = data['expertise']
    if 'description' in data:
        expert.description = data['description']
    if 'biography' in data:
        expert.biography = data['biography']
    if 'education' in data:
        expert.education = data['education']
    if 'languages' in data:
        expert.languages = data['languages']
    if 'project_type' in data:
        project_type = ProjectType.query.filter_by(name=data['project_type']).first()
        if project_type:
            expert.project_type = project_type
        else:
            return jsonify({'message': 'Project type not found'}), 404
    if 'subject' in data:
        # Fetch the Subject instance based on the provided subject name
        subject = Subject.query.filter_by(name=data['subject']).first()
        if subject:
            expert.subject = subject
        else:
            return jsonify({'message': 'Subject not found'}), 404
    if 'profilePicture' in data:
        expert.profile_picture = data['profilePicture']
    

    db.session.commit()
    # Return the updated expert data
    updated_expert = {
        'id': expert.id,
        'name': expert.name,
        'title': expert.title,
        'expertise': expert.expertise,
        'description': expert.description,
        'biography': expert.biography,
        'education': expert.education,
        'languages': expert.languages,
        'project_type': expert.project_type.name,
        'subject': expert.subject.name,
        'profile_picture': expert.profile_picture
    }
    
    return jsonify(updated_expert), 200

@app.route('/conversations/<int:conversation_id>/mark-read', methods=['POST'])
@jwt_required()
def mark_messages_read(conversation_id):
    try:
        user_id = get_jwt_identity()
        print(f"DEBUG - User ID: {user_id}, Conversation ID: {conversation_id}")
        
        # Check if conversation exists
        conversation = Conversation.query.get(conversation_id)
        if not conversation:
            print(f"DEBUG - Conversation {conversation_id} not found")
            return jsonify({'error': 'Conversation not found'}), 404

        unread_messages = MessageModel.query.filter_by(
            conversation_id=conversation_id,
            receiver_id=user_id,
            read=False
        ).all()
        
        print(f"DEBUG - Found {len(unread_messages)} unread messages")
        print(f"DEBUG - Messages: {unread_messages}")  # See the actual messages

        for message in unread_messages:
            print(f"DEBUG - Marking message {message.id} as read")
            message.read = True

        db.session.commit()
        return jsonify({'success': True}), 200

    except Exception as e:
        print(f"DEBUG - Error in mark_messages_read: {str(e)}")
        print(f"DEBUG - Error type: {type(e)}")
        import traceback
        print(f"DEBUG - Traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/experts/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_expert(id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({'message': 'User  not found'}), 404

    if not user.is_admin:
        return jsonify({'message': 'Permission denied'}), 403

    expert = Expert.query.get(id)
    if not expert:
        return jsonify({'message': 'Expert not found'}), 404

    try:
        db.session.delete(expert)
        db.session.commit()
        return jsonify({'message': 'Expert deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting expert: {e}")
        return jsonify({'message': 'Error deleting expert', 'error': str(e)}), 500

# @app.route('/services', methods=['GET'])
# def get_services():
#     services = Service.query.options(db.joinedload(Service.project_type)).all()  # Fetch all services with related project type
#     service_list = []

#     for service in services:
#         service_data = {
#             'id': service.id,
#             'title': service.title,
#             'description': service.description,
#             'price': service.price,
#             'project_type_name': service.project_type.name if service.project_type else None,  # Get project type name
#             'subject_name': service.subject.name if service.subject else None  # Get subject name, optional
#         }
#         service_list.append(service_data)

#     return jsonify({'services': service_list})
# @app.route('/services', methods=['GET'])
# def get_services():
#     services = Service.query.options(db.joinedload(Service.project_type)).all()  # Fetch all services with related project type
#     service_list = []

#     for service in services:
#         service_data = {
#             'id': service.id,
#             'title': service.title,
#             'description': service.description,
#             'price': service.price,
#             'project_type_name': service.project_type.name if service.project_type else None,  # Get project type name
#             'subject_name': service.subject.name if service.subject else None  # Get subject name, optional
#         }
#         service_list.append(service_data)

#     return jsonify({'services': service_list})
@app.route('/services', methods=['GET'])
def get_services():
    project_type_id = request.args.get('project_type', type=int)
    subject_id = request.args.get('subject', type=int)
    print(f"Received project_type_id: {project_type_id}, subject_id: {subject_id}")

    query = Service.query

    if project_type_id:
        query = query.filter_by(project_type_id=project_type_id)
    if subject_id:
        query = query.filter_by(subject_id=subject_id)

    print(f"Query: {query}")

    services = query.all()
    return jsonify({
        "services": [
            {
                'id': service.id,
                'title': service.title,
                'description': service.description,
                'base_price': service.base_price,
                'price_per_page': service.price_per_page,
                'project_type_id': service.project_type_id,
                'subject_id': service.subject_id
            } for service in services
        ] 
    }), 200

# @app.route('/services', methods=['POST'])
# def add_service():
#     if not request.is_json:
#         return jsonify({"message": "Invalid request. JSON data required."}), 400

#     data = request.get_json()

#     title = data.get('title')
#     description = data.get('description')
#     price = data.get('price')
#     project_type_id = data.get('project_type_id')  # Capture project_type_id
#     subject_id = data.get('subject_id')  # Capture subject_id

#     if not title or not description or price is None or project_type_id is None or subject_id is None:
#         return jsonify({"message": "Title, description, price, project type, and subject are required."}), 400
    project_type_id = request.args.get('project_type', type=int)
    subject_id = request.args.get('subject', type=int)
    print(f"Received project_type_id: {project_type_id}, subject_id: {subject_id}")

    query = Service.query

    if project_type_id:
        query = query.filter_by(project_type_id=project_type_id)
    if subject_id:
        query = query.filter_by(subject_id=subject_id)

    print(f"Query: {query}")

    services = query.all()
    return jsonify({
        "services": [
            {
                'id': service.id,
                'title': service.title,
                'description': service.description,
                'base_price': service.base_price,
                'price_per_page': service.price_per_page,
                'project_type_id': service.project_type_id,
                'subject_id': service.subject_id
            } for service in services
        ] 
    }), 200

# @app.route('/services', methods=['POST'])
# def add_service():
#     if not request.is_json:
#         return jsonify({"message": "Invalid request. JSON data required."}), 400

#     data = request.get_json()

#     title = data.get('title')
#     description = data.get('description')
#     price = data.get('price')
#     project_type_id = data.get('project_type_id')  # Capture project_type_id
#     subject_id = data.get('subject_id')  # Capture subject_id

#     if not title or not description or price is None or project_type_id is None or subject_id is None:
#         return jsonify({"message": "Title, description, price, project type, and subject are required."}), 400

#     new_service = Service(
#         title=title,
#         description=description,
#         price=price,
#         project_type_id=project_type_id,
#         subject_id=subject_id  # Include subject_id
#     )
#     new_service = Service(
#         title=title,
#         description=description,
#         price=price,
#         project_type_id=project_type_id,
#         subject_id=subject_id  # Include subject_id
#     )

#     try:
#         db.session.add(new_service)
#         db.session.commit()
#         return jsonify({"message": "Service added successfully!", "service": {
#             'id': new_service.id,
#             'title': new_service.title,
#             'description': new_service.description,
#             'price': new_service.price,
#             'project_type_id': new_service.project_type_id,
#             'subject_id': new_service.subject_id  # Include subject_id in the response
#         }}), 201
#     except Exception as e:
#         db.session.rollback()
#         print("Error adding service:", str(e))
#         return jsonify({"message": "Failed to add service.", "error": str(e)}), 500
#     try:
#         db.session.add(new_service)
#         db.session.commit()
#         return jsonify({"message": "Service added successfully!", "service": {
#             'id': new_service.id,
#             'title': new_service.title,
#             'description': new_service.description,
#             'price': new_service.price,
#             'project_type_id': new_service.project_type_id,
#             'subject_id': new_service.subject_id  # Include subject_id in the response
#         }}), 201
#     except Exception as e:
#         db.session.rollback()
#         print("Error adding service:", str(e))
#         return jsonify({"message": "Failed to add service.", "error": str(e)}), 500

@app.route('/services', methods=['POST'])
def add_service():
    if not request.is_json:
        return jsonify({"message": "Invalid request. JSON data required."}), 400

    data = request.get_json()

    title = data.get('title')
    description = data.get('description')
    base_price = data.get('base_price')  # Expecting base_price in the request
    price_per_page = data.get('price_per_page')  # Expecting price_per_page in the request
    base_price = data.get('base_price')  # Expecting base_price in the request
    price_per_page = data.get('price_per_page')  # Expecting price_per_page in the request
    project_type_id = data.get('project_type_id')  # Capture project_type_id
    subject_id = data.get('subject_id')  # Capture subject_id

    # Validate required fields
    if not title or base_price is None or price_per_page is None or project_type_id is None or subject_id is None:
        return jsonify({"message": "Title, base price, price per page, project type, and subject are required."}), 400
    # Validate required fields

    # Create a new Service instance
    # Create a new Service instance
    new_service = Service(
        title=title,
        description=description,
        base_price=base_price,
        price_per_page=price_per_page,
        project_type_id=project_type_id,
        subject_id=subject_id
    )

    try:
        db.session.add(new_service)
        db.session.commit()
        return jsonify({
            "message": "Service added successfully!",
            "service": {
                'id': new_service.id,
                'title': new_service.title,
                'description': new_service.description,
                'base_price': new_service.base_price,
                'price_per_page': new_service.price_per_page,
                'project_type_id': new_service.project_type_id,
                'subject_id': new_service.subject_id
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        print("Error adding service:", str(e))
        return jsonify({"message": "Failed to add service.", "error": str(e)}), 500


@app.route('/project-types', methods=['GET'])
def get_project_types():
    try:
        project_types = ProjectType.query.all()  
        return jsonify([project_type.to_dict() for project_type in project_types]), 200
    except Exception as e:
        print("Error occurred:", e)  
        return jsonify({'message': str(e)}), 500  


# POST route to create a new project type
@app.route('/project-types', methods=['POST'])
def create_project_type():
    try:
        data = request.get_json()
        new_project_type = ProjectType(name=data['name'])
        db.session.add(new_project_type)
        db.session.commit()
        return jsonify(new_project_type.to_dict()), 201
    except Exception as e:
        print("Error occurred:", e)
        return jsonify({'message': str(e)}), 500


# PUT route to update a project type
@app.route('/project-types/<int:id>', methods=['PUT'])
def update_project_type(id):
    try:
        data = request.get_json()
        project_type = ProjectType.query.get_or_404(id)
        project_type.name = data['name']
        db.session.commit()
        return jsonify(project_type.to_dict()), 200
    except Exception as e:
        print("Error occurred:", e)
        return jsonify({'message': str(e)}), 500

# DELETE route to delete a project type
@app.route('/project-types/<int:id>', methods=['DELETE'])
def delete_project_type(id):
    try:
        project_type = ProjectType.query.get_or_404(id)
        db.session.delete(project_type)
        db.session.commit()
        return jsonify({'message': 'Project type deleted successfully'}), 200
    except Exception as e:
        print("Error occurred:", e)
        return jsonify({'message': str(e)}), 500


@app.route('/subjects', methods=['GET'])
def get_subjects():
    try:
        subjects = Subject.query.all()  # Query all subjects from the database
        return jsonify([subject.to_dict() for subject in subjects]), 200  # Return as JSON
    except Exception as e:
        print(f"Error fetching subjects: {e}")
        return jsonify({'message': 'Failed to fetch subjects'}), 500


# POST route to create a new subject
@app.route('/subjects', methods=['POST'])
def create_subject():
    try:
        data = request.get_json()
        new_subject = Subject(name=data['name'])  # Assuming the Subject model has a 'name' field
        db.session.add(new_subject)
        db.session.commit()
        return jsonify(new_subject.to_dict()), 201  # Return the created subject
    except Exception as e:
        print(f"Error creating subject: {e}")
        return jsonify({'message': 'Failed to create subject'}), 500


# PUT route to update a subject by its ID
@app.route('/subjects/<int:id>', methods=['PUT'])
def update_subject(id):
    try:
        data = request.get_json()
        subject = Subject.query.get_or_404(id)
        subject.name = data['name']
        db.session.commit()
        return jsonify(subject.to_dict()), 200  # Return the updated subject
    except Exception as e:
        print(f"Error updating subject: {e}")
        return jsonify({'message': 'Failed to update subject'}), 500


# DELETE route to delete a subject by its ID
@app.route('/subjects/<int:id>', methods=['DELETE'])
def delete_subject(id):
    try:
        subject = Subject.query.get_or_404(id)
        db.session.delete(subject)
        db.session.commit()
        return jsonify({'message': 'Subject deleted successfully'}), 200
    except Exception as e:
        print(f"Error deleting subject: {e}")
        return jsonify({'message': 'Failed to delete subject'}), 500

# Route for admin to update services
@app.route('/services/<int:id>', methods=['PUT'])
@jwt_required()
def update_service(id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user.is_admin:
        return jsonify({'message': 'Admin privileges required!'}), 403

    service = Service.query.get(id)
    if service:
        data = request.json
        service.title = data['title']
        service.description = data['description']
        service.price = data['price']
        db.session.commit()
        return jsonify({'message': 'Service updated successfully!'})
    return jsonify({'message': 'Service not found!'}), 404

@app.route('/services/<int:service_id>', methods=['DELETE'])
def delete_service(service_id):
    # Find the service by ID
    service = Service.query.get(service_id)
    
    # If service is not found, return a 404 error
    if not service:
        return jsonify({"error": "Service not found"}), 404
    
    try:
        # Delete the service
        db.session.delete(service)
        db.session.commit()
        return jsonify({"message": "Service deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()  # Rollback the session in case of error
        print(f"Error deleting service: {e}")
        return jsonify({"error": "Could not delete service"}), 500


@app.route('/services/<int:id>', methods=['PATCH'])
@jwt_required()
def patch_service(id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user.is_admin:
        return jsonify({'message': 'Admin privileges required!'}), 403

    service = Service.query.get(id)
    if not service:
        return jsonify({'message': 'Service not found!'}), 404

    # Get data from the request body
    data = request.json
    print("Received data:", data)

    errors = []

    # Check for the fields and update the service accordingly
    if 'title' in data:
        service.title = data['title']
    if 'description' in data:
        service.description = data['description']
    if 'price' in data:
        if not isinstance(data['price'], (int, float)):
            errors.append("Price must be a number.")
        else:
            service.price = data['price']
    if 'subject_name' in data:
        service.subject_name = data['subject_name']
    if 'project_type_name' in data:
        service.project_type_name = data['project_type_name']

    # If there are validation errors, return them
    if errors:
        return jsonify({'errors': errors}), 422

   
    db.session.commit()

    return jsonify({'message': 'Service updated successfully!'})

api.add_resource(Projects, '/projects')

if __name__ == '__main__':
    # app.run(debug=True)
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
    
