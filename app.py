#qr asnd pdf works in databse but not dashboard 





from sqlite3 import IntegrityError
from flask import Flask, request,send_file, render_template, redirect, session, url_for, jsonify,flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
import logging
import json
import os
import qrcode  # Import QR code library
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from sqlalchemy import LargeBinary
import urllib.parse
from sqlalchemy import text

from datetime import datetime
import pyodbc
import traceback 
from flask_migrate import Migrate
from sqlalchemy import MetaData, Table, create_engine, inspect
from datetime import datetime

import random
import threading
import time

from sqlalchemy.sql import func
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, current_user
# Load environment variables from .env file


from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, Column, Integer, String, Float, Date

from sqlalchemy import Table, Column, Integer, String, DateTime, Float, MetaData


# Instantiate Flask application
app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'

Base = declarative_base()
# Define conversion table
conversion_table = {
    240: 8.875,
    234: 8.625,
    228: 8.375,
    222: 8.125,
    215: 7.875,
    209: 7.625,
    203: 7.375,
    197: 7.125,
    196: 7.125,
    190: 6.875,
    183: 6.625,
    177: 6.375,
    170: 6.125,
    164: 5.875,
    158: 5.625,
    151: 5.375,
    152: 5.375,
    144: 5.125,
    138: 4.875,
    131: 4.625,
    125: 4.375,
    118: 4.125,
    111: 3.875,
    105: 3.625,
    98: 3.375,
    91: 3.125,
    85: 2.875,
    78: 2.625,
    71: 2.375,
    70: 2.225,
    64: 2.125,
    57: 1.875,
    50: 1.625,
    51: 1.625,
    42: 1.375,
    35: 1.125,
    28: 0.875,
    21: 0.625,
    19: 0.696,
    14: 0.375,
    6: 0.125,
    0: 0,
    "Sensor Dead Band": 0,
}

class BaseModel(db.Model):
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime)
    full_addr = db.Column(db.String)
    sensor_data = db.Column(db.Float)
    vehicleno = db.Column(db.String)
    volume_liters = db.Column(db.Float, nullable=True)


def create_table_for_admin(adminname):
    metadata = MetaData()
    table_name = f'level_sensor_data_{adminname}'

    new_table = Table(
        table_name, metadata,
        Column('id', Integer, primary_key=True),
        Column('date', DateTime),
        Column('full_addr', String),
        Column('sensor_data', Float),
        Column('vehicleno', String),
        Column('volume_liters', Float, nullable=True)
    )

    new_table.create(db.engine)  # Create the table in the database



class AdminDashboard(db.Model):
    __tablename__ = 'admin_dashboards'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    dashboard_data = db.Column(db.Text, nullable=True, default='{}')  # JSON data for the dashboard
    admin = db.relationship('User', backref=db.backref('dashboard', uselist=False))






def reset_dashboard_data(admin_id):
    super_admin_email = 'admin@gmail.com'
    super_admin = User.query.filter_by(email=super_admin_email).first()
    admin = User.query.get(admin_id)  # Fetch the admin user
    admin_name = admin.name  # Get the admin's name

    if super_admin and super_admin.id == admin_id:
        return  # Skip resetting data for the super admin

    dashboard = AdminDashboard.query.filter_by(admin_id=admin_id).first()
    if not dashboard:
        # Create a new dashboard if it doesn't exist
        dashboard = AdminDashboard(admin_id=admin_id, dashboard_data=json.dumps({
            "cards": [],
            "tables": [],
            "charts": []
        }))
        db.session.add(dashboard)
    else:
        # Optionally, you can choose to reset the dashboard data if needed
        pass  # Do nothing to keep existing data

    db.session.commit()

    # No need to drop the existing table for non-super admins
    # Simply ensure the correct table is used

    create_sensor_data_table(f'level_sensor_data_{admin_name}')  # Ensure the table exists
    db.session.commit()





dynamic_models = {}

def create_sensor_data_table(table_name):
    class DynamicLevelSensorData(db.Model):
        __tablename__ = table_name
        __table_args__ = {'extend_existing': True}
        id = db.Column(db.Integer, primary_key=True)
        date = db.Column(db.DateTime)
        full_addr = db.Column(db.Integer)
        sensor_data = db.Column(db.Float)
        vehicleno = db.Column(db.String(50))
        volume_liters = db.Column(db.Float)
        qrcode = db.Column(db.LargeBinary)
        pdf = db.Column(db.LargeBinary)

        def __init__(self, date, full_addr, sensor_data, vehicleno, volume_liters):
            self.date = datetime.strptime(date, '%d/%m/%Y %H:%M:%S')
            self.full_addr = full_addr
            self.sensor_data = sensor_data
            self.vehicleno = vehicleno
            self.volume_liters = volume_liters
            self.qrcode = self.generate_qr_code()
            self.pdf = self.generate_pdf()


        def generate_qr_code(self):
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=4,
                border=4,
            )
            qr.add_data(self.to_dict())
            qr.make(fit=True)
            img = qr.make_image(fill='black', back_color='white')
            buf = BytesIO()
            img.save(buf, format='PNG')
            return buf.getvalue()

        def generate_pdf(self):
            buffer = BytesIO()
            c = canvas.Canvas(buffer, pagesize=letter)
            c.setFont("Helvetica-Bold", 14)
            c.drawString(100, 780, "Sensor Data Report")
            c.line(50, 770, 550, 770)
            c.setFont("Helvetica", 10)
            c.drawString(100, 750, f"Date: {self.date.strftime('%d/%m/%Y %H:%M:%S')}")
            c.drawString(100, 730, f"Full Address: {self.full_addr}")
            c.drawString(100, 710, f"Sensor Data: {self.sensor_data}")
            c.drawString(100, 690, f"Vehicle No: {self.vehicleno}")
            c.drawString(100, 670, f"Volume (liters): {self.volume_liters}")
            c.line(50, 660, 550, 660)
            c.showPage()
            c.save()
            buffer.seek(0)
            return buffer.getvalue()

        def to_dict(self):
            return {
                'date': self.date.strftime('%d/%m/%Y %H:%M:%S'),
                'full_addr': self.full_addr,
                'sensor_data': self.sensor_data,
                'vehicleno': self.vehicleno,
                'volume_liters': self.volume_liters
            }

    # Store the model in the global dictionary
    dynamic_models[table_name] = DynamicLevelSensorData
    db.create_all()
    DynamicLevelSensorData.__table__.create(db.engine, checkfirst=True)

    print(f"Model for table '{table_name}' created and stored.")  # Debugging line
    return DynamicLevelSensorData





def is_super_admin(user):
    return user.email == 'admin@gmail.com'


def create_dynamic_admin_route(admin_id):
    endpoint = f"/api/admin/{admin_id}/data"

    @app.route(endpoint, methods=['POST'])
    def dynamic_admin_data():
        data = request.json
        # Process the data specific to this admin
        # Store the data as needed in the database

        # Example response:
        return jsonify({"message": f"Data received for admin {admin_id}"}), 200

    return endpoint


class UserAccount(db.Model):
    __tablename__ = 'user_accounts'

    id = db.Column(db.Integer, primary_key=True)
    accountname = db.Column(db.String(100), nullable=False)
    accountemail = db.Column(db.String(100), unique=True, nullable=False)
    accountpassword = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    status = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    updated_at = db.Column(db.DateTime(timezone=True), onupdate=func.now(), server_default=func.now())


    # Method to set the hashed password
    def set_password(self, password):
        self.accountpassword = generate_password_hash(password)

    # Method to check the hashed password
    def check_password(self, password):
        return check_password_hash(self.accountpassword, password)
    
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    is_admin = db.Column(db.Integer)
    status = db.Column(db.Boolean, default=True)  # Add this line
    is_super_admin = db.Column(db.Boolean, default=False)  # New field for Super Admin

    def __init__(self, email, password, name, is_admin,status,  is_super_admin):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.is_admin = is_admin
        self.status = status  # Default status is True
        self. is_super_admin =  is_super_admin

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

class LevelSensorData(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    date = db.Column(db.DateTime)
    full_addr = db.Column(db.Integer)
    sensor_data = db.Column(db.Float)
    vehicleno = db.Column(db.String(50))
    volume_liters = db.Column(db.Float)
    qrcode = db.Column(db.LargeBinary)
    pdf = db.Column(db.LargeBinary)
   
    def __init__(self, date, full_addr, sensor_data, vehicleno, volume_liters):
        self.date = datetime.strptime(date, '%d/%m/%Y %H:%M:%S')
        self.full_addr = full_addr
        self.sensor_data = sensor_data
        self.vehicleno = vehicleno
        self.volume_liters = volume_liters
        self.qrcode = self.generate_qr_code()
        self.pdf = self.generate_pdf()

    def generate_qr_code(self):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=4,
            border=4,
        )
        qr.add_data(self.to_dict())  # Add full row data
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        buf = BytesIO()
        img.save(buf, format='PNG')
        return buf.getvalue()

    def generate_pdf(self):
        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(100, 780, "Sensor Data Report")
        c.line(50, 770, 550, 770)
        c.setFont("Helvetica", 10)
        c.drawString(100, 750, f"Date: {self.date.strftime('%d/%m/%Y %H:%M:%S')}")
        c.drawString(100, 730, f"Full Address: {self.full_addr}")
        c.drawString(100, 710, f"Sensor Data: {self.sensor_data}")
        c.drawString(100, 690, f"Vehicle No: {self.vehicleno}")
        c.drawString(100, 670, f"Volume (liters): {self.volume_liters}")
        c.line(50, 660, 550, 660)
        c.showPage()
        c.save()
        buffer.seek(0)
        return buffer.getvalue()

    def to_dict(self):
        return {
            'date': self.date.strftime('%d/%m/%Y %H:%M:%S'),
            'full_addr': self.full_addr,
            'sensor_data': self.sensor_data,
            'vehicleno': self.vehicleno,
            'volume_liters': self.volume_liters
        }

def create_admin_user():
    admin_email = 'admin@gmail.com'
    admin_password = 'admin'
    admin_name = 'Admin'
    status = True  # Set the default status to active
    
    existing_admin = User.query.filter_by(email=admin_email).first()
    if not existing_admin:
        admin_user = User(email=admin_email, password=admin_password, name=admin_name, is_admin=True, status=status, is_super_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        create_sensor_data_table(f'level_sensor_data_{admin_name}')  # Create table for super admin using their name
        print("Super Admin user created")
    else:
        print("Admin user already exists")












with app.app_context():
    db.create_all()
    create_admin_user()  # Call the function to create the admin user
    

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        is_admin = request.form.get('is_admin') == 'on'
        is_super_admin = False
        status = True

        new_user = User(name=name, email=email, password=password, is_admin=is_admin, status=status, is_super_admin=is_super_admin)
        db.session.add(new_user)
        db.session.commit()

        if is_admin:
            reset_dashboard_data(new_user.id)  # Reset dashboard for new admin

        flash('Signup successful!')
        return redirect(url_for('index'))
    
    return render_template('signup.html')




@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('is_admin')

    if not name or not email or not password:
        return jsonify({"message": "Please provide name, email, isAdmin and password"}), 400

    try:
        if User.query.filter_by(email=email).first():
            return jsonify({"message": "Email already registered"}), 400

        new_user = User(name=name, email=email, password=password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()

        if is_admin:
            # Create a blank dashboard for the new admin
            new_dashboard = AdminDashboard(admin_id=new_user.id)
            db.session.add(new_dashboard)
            db.session.commit()

        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500
        
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = user.email
            session['is_admin'] = user.is_admin
            session['admin_name'] = user.name  # Store admin name in session

            if user.is_admin and not is_super_admin(user):
                reset_dashboard_data(user.id)

            return redirect(url_for('admin_dashboard', adminname=user.name))  # Redirect to dynamic dashboard
        else:
            error = 'Invalid credentials. Please try again.'

    return render_template('login.html', error=error)








@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    email = data['email']
    password = data['password']
    is_admin = data['is_admin']

    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        session['email'] = user.email
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401










@app.route('/dashboard/<adminname>')
def admin_dashboard(adminname):
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()

        if user is None:
            return redirect('/login')

        if user.name != adminname:
            return redirect(url_for('admin_dashboard', adminname=user.name))

        # Set the table name dynamically based on adminname
        table_name = f'level_sensor_data_{adminname}'
        metadata = MetaData()
        table = Table(table_name, metadata, autoload_with=db.engine)

        filter_option = request.args.get('filter', 'latest')
        page = request.args.get('page', 1, type=int)
        search_query = request.args.get('query', '')

        query = db.session.query(table)

        if search_query:
            try:
                search_id = int(search_query)
                query = query.filter(
                    (table.c.id == search_id) |
                    (table.c.date.like(f'%{search_query}%')) |
                    (table.c.full_addr.like(f'%{search_query}%')) |
                    (table.c.sensor_data.like(f'%{search_query}%')) |
                    (table.c.vehicleno.like(f'%{search_query}%'))
                )
            except ValueError:
                query = query.filter(
                    (table.c.date.like(f'%{search_query}%')) |
                    (table.c.full_addr.like(f'%{search_query}%')) |
                    (table.c.sensor_data.like(f'%{search_query}%')) |
                    (table.c.vehicleno.like(f'%{search_query}%'))
                )

        if filter_option == 'oldest':
            query = query.order_by(table.c.date.asc())
        else:
            query = query.order_by(table.c.date.desc())

        sense_data_pagination = query.paginate(page=page, per_page=10)
        sense_data = []
        for row in sense_data_pagination.items:
            data_point = {col.name: getattr(row, col.name) for col in table.columns}
            data_point['volume_liters'] = get_volume(data_point['sensor_data'])
            sense_data.append(data_point)

        # Print the data for debugging
        print("Sense Data:", sense_data)
        print("Pagination Info:", sense_data_pagination)

        return render_template(
            'dashboard.html',
            user=user,
            sense_data=sense_data,
            filter_option=filter_option,
            pagination=sense_data_pagination,
            search_query=search_query
        )
    return redirect('/login')






@app.route('/api/admin/<adminname>/dashboard', methods=['GET'])
def get_dashboard_data(adminname):
    user = User.query.filter_by(name=adminname).first()
    if not user:
        return jsonify({"message": "Admin not found"}), 404

    table_name = f'level_sensor_data_{adminname}'
    metadata = MetaData()
    table = Table(table_name, metadata, autoload_with=db.engine)

    data = db.session.query(table).all()
    if not data:
        return jsonify({"message": f"No data found in {table_name}"}), 404

    result = []
    for row in data:
        result.append({
            "date": row.date,
            "address": row.full_addr,
            "data": row.sensor_data,
            "vehicle_no": row.vehicleno,
            "volume_liters": get_volume(row.sensor_data)
        })

    return jsonify(result), 200








@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()

        if user is None:
            user = UserAccount.query.filter_by(accountemail=session['email']).first()

        if user is None:
            # User not found, redirect to login or show an error message
            return redirect('/login')

        # Load the admin's dashboard data and reset if necessary
        if user.is_admin:
            dashboard_data = AdminDashboard.query.filter_by(admin_id=user.id).first()
            if dashboard_data:
                dashboard_content = json.loads(dashboard_data.dashboard_data)
            else:
                # Reset the dashboard for new admin
                dashboard_content = {
                    "cards": [],  # Reset cards to empty list
                    "tables": [],  # Reset tables to empty list
                    "charts": []   # Reset charts to empty list
                }
                # Save the reset state to the database
                new_dashboard_data = AdminDashboard(
                    admin_id=user.id,
                    dashboard_data=json.dumps(dashboard_content)
                )
                db.session.add(new_dashboard_data)
                db.session.commit()

        filter_option = request.args.get('filter', 'latest')
        page = request.args.get('page', 1, type=int)
        search_query = request.args.get('query', '')

        query = LevelSensorData.query

        if search_query:
            # Split search_query to handle numerical and textual searches
            try:
                search_id = int(search_query)
                query = query.filter(
                    (LevelSensorData.id == search_id) |
                    (LevelSensorData.date.like(f'%{search_query}%')) |
                    (LevelSensorData.full_addr.like(f'%{search_query}%')) |
                    (LevelSensorData.sensor_data.like(f'%{search_query}%')) |
                    (LevelSensorData.vehicleno.like(f'%{search_query}%'))
                )
            except ValueError:
                query = query.filter(
                    (LevelSensorData.date.like(f'%{search_query}%')) |
                    (LevelSensorData.full_addr.like(f'%{search_query}%')) |
                    (LevelSensorData.sensor_data.like(f'%{search_query}%')) |
                    (LevelSensorData.vehicleno.like(f'%{search_query}%'))
                )

        if filter_option == 'oldest':
            query = query.order_by(LevelSensorData.date.asc())
        else:
            query = query.order_by(LevelSensorData.date.desc())

        sense_data_pagination = query.paginate(page=page, per_page=10)
        sense_data = sense_data_pagination.items

        for data_point in sense_data:
            data_point.volume_liters = get_volume(data_point.sensor_data)

        # Check if the user is an instance of UserAccount and pass the appropriate role
        user_role = user.is_admin if isinstance(user, UserAccount) else user.is_super_admin

        return render_template(
            'dashboard.html',
            user=user,
            user_role=user_role,  # Pass user role to template
            sense_data=sense_data,
            filter_option=filter_option,
            pagination=sense_data_pagination,
            search_query=search_query,
            dashboard_content=dashboard_content  # Pass the reset or existing dashboard content
        )
    return redirect('/login')





@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.pop('email', None)
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/api/user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"}), 200
    else:
        return jsonify({"message": "User not found"}), 404

logging.basicConfig(filename='log.txt', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

api_logger = logging.getLogger('api_logger')
api_handler = logging.FileHandler('apilog.txt')
api_handler.setLevel(logging.INFO)
api_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
api_logger.addHandler(api_handler)


@app.route('/level_sensor_data', methods=['POST'])
def receive_level_sensor_data():
    if request.method == 'POST':
        try:
            if not request.is_json:
                api_logger.error("Request content type is not JSON")
                return jsonify({'status': 'failure', 'message': 'Request content type is not JSON'}), 400
            request_data = request.get_json()
            modbus_test_data = request_data.get('level_sensor_data', '{}')
            try:
                sense_data = json.loads(modbus_test_data)
            except json.JSONDecodeError:
                api_logger.error("Invalid JSON format in modbus_TEST")
                return jsonify({'status': 'failure', 'message': 'Invalid JSON format in modbus_TEST'}), 400

            api_logger.info("API called with data: %s", sense_data)

            # Extracting data from JSON
            date = sense_data.get('D', '')
            full_addr = sense_data.get('address', 0)
            sensor_data = sense_data.get('data', [])
            vehicleno = sense_data.get('Vehicle no', '')

            if not all([date, full_addr, sensor_data, vehicleno]):
                api_logger.error("Missing required data fields")
                return jsonify({'status': 'failure', 'message': 'Missing required data fields'}), 400

            # Ensure sensor_data is a list and extract the first element
            if isinstance(sensor_data, list) and sensor_data:
                sensor_data = sensor_data[0]
            else:
                api_logger.error("Invalid sensor data format")
                return jsonify({'status': 'failure', 'message': 'Invalid sensor data format'}), 400

            # Convert sensor_data to float
            try:
                sensor_data = float(sensor_data)
            except ValueError:
                api_logger.error("Invalid sensor data format")
                return jsonify({'status': 'failure', 'message': 'Invalid sensor data format'}), 400

            # Fetch volume from conversion table
            volume_liters = get_volume(sensor_data)
            if volume_liters is None:
                api_logger.error("Failed to convert sensor data to volume")
                return jsonify({'status': 'failure', 'message': 'Failed to convert sensor data to volume'}), 400

            # Create a new LevelSensorData object with volume_liters and add it to the database
            new_data = LevelSensorData(date=date, full_addr=full_addr, sensor_data=sensor_data, vehicleno=vehicleno, volume_liters=volume_liters)
            db.session.add(new_data)
            db.session.commit()

            # Log success
            api_logger.info("Data stored successfully: %s", json.dumps(sense_data))

            # Return a response
            response = {'status': 'success', 'message': 'Data received and stored successfully'}
            return jsonify(response), 200

        except Exception as e:
            # Log failure
            api_logger.error("Failed to store data: %s", e)
            return jsonify({'status': 'failure', 'message': 'Failed to store data'}), 500

    api_logger.info("Received non-POST request at /level_sensor_data, redirecting to /dashboard")
    return redirect('/dashboard')


@app.route('/api/<adminname>/device_entries_logged', methods=['GET'])
def get_device_entries_logged(adminname):
    try:
        # Check if the admin exists
        user = User.query.filter_by(name=adminname).first()
        if not user:
            return jsonify({"message": "Admin not found"}), 404

        table_name = f'level_sensor_data_{adminname}'
        
        # Check if the model exists in the dynamic_models dictionary
        if table_name not in dynamic_models:
            create_sensor_data_table(table_name)

        DynamicLevelSensorData = dynamic_models[table_name]

        # Count total entries in the admin's dynamic table
        device_entries_logged = db.session.query(DynamicLevelSensorData).count()

        return jsonify({"device_entries_logged": device_entries_logged}), 200

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@app.route('/api/<adminname>/no_of_devices_active', methods=['GET'])
def get_no_of_devices_active(adminname):
    try:
        # Check if the admin exists
        user = User.query.filter_by(name=adminname).first()
        if not user:
            return jsonify({"message": "Admin not found"}), 404

        table_name = f'level_sensor_data_{adminname}'
        
        # Check if the model exists in the dynamic_models dictionary
        if table_name not in dynamic_models:
            create_sensor_data_table(table_name)

        DynamicLevelSensorData = dynamic_models[table_name]

        # Count distinct vehicle numbers
        no_of_devices_active = db.session.query(DynamicLevelSensorData.vehicleno.distinct()).count()

        return jsonify({"no_of_devices_active": no_of_devices_active}), 200

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@app.route('/search', methods=['GET'])
def search_sensor_data():
    query = request.args.get('query', '')
    page = request.args.get('page', 1, type=int)

    query_obj = LevelSensorData.query

    if query:
        # Split search_query to handle numerical and textual searches
        try:
            search_id = int(query)
            query_obj = query_obj.filter(
                (LevelSensorData.id == search_id) |
                (LevelSensorData.date.like(f'%{query}%')) |
                (LevelSensorData.full_addr.like(f'%{query}%')) |
                (LevelSensorData.sensor_data.like(f'%{query}%')) |
                (LevelSensorData.vehicleno.like(f'%{query}%'))
            )
        except ValueError:
            query_obj = query_obj.filter(
                (LevelSensorData.date.like(f'%{query}%')) |
                (LevelSensorData.full_addr.like(f'%{query}%')) |
                (LevelSensorData.sensor_data.like(f'%{query}%')) |
                (LevelSensorData.vehicleno.like(f'%{query}%'))
            )
    
    # Ensure an ORDER BY clause is applied
    query_obj = query_obj.order_by(LevelSensorData.date.desc())

    sense_data_pagination = query_obj.paginate(page=page, per_page=10)
    sense_data = sense_data_pagination.items

    user = User.query.filter_by(email=session.get('email')).first()

    return render_template(
        'dashboard.html',
        user=user,
        sense_data=sense_data,
        pagination=sense_data_pagination,
        search_query=query
    )


# Fetch the volume from the conversion table
def get_volume(sensor_data):
    if sensor_data in conversion_table:
        return conversion_table[sensor_data]
    else:
        numeric_keys = [key for key in conversion_table if isinstance(key, int)]
        lower_key = max(key for key in numeric_keys if key <= sensor_data)
        upper_keys = [key for key in numeric_keys if key > sensor_data]
        if upper_keys:
            upper_key = min(upper_keys)
            return interpolate(lower_key, conversion_table[lower_key], upper_key, conversion_table[upper_key], sensor_data)
        return None

def interpolate(x1, y1, x2, y2, x):
    return round(y1 + ((y2 - y1) / (x2 - x1)) * (x - x1), 3)


@app.route('/api/sensor_data/<string:admin_name>', methods=['GET'])
def get_sensor_data(admin_name):
    try:
        # Assuming you have a function to get data specific to the admin
        sensor_data = LevelSensorData.query.filter_by(admin_name=admin_name).all()
        if not sensor_data:
            return jsonify(error='No data available'), 404

        labels = [data.date.strftime('%d/%m/%Y %H:%M:%S') for data in sensor_data]
        sensor_values = [data.sensor_data for data in sensor_data]
        volume_liters = [data.volume_liters for data in sensor_data]

        return jsonify(labels=labels, sensorData=sensor_values, volumeLiters=volume_liters)
    except Exception as e:
        print(f"Error fetching sensor data: {str(e)}")
        return jsonify(error='Internal server error'), 500
    
from flask import Response
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
 
# QR and PDF generation routes
@app.route('/generate_pdf/<int:id>', methods=['GET'])
def generate_pdf(id):
    current_admin_name = session.get('admin_name')  # Retrieve admin name from session
    
    if not current_admin_name:
        return jsonify({"message": "Admin not logged in."}), 403

    table_name = f'level_sensor_data_{current_admin_name}'
    DynamicLevelSensorData = dynamic_models.get(table_name)

    if not DynamicLevelSensorData:
        return jsonify({"message": "Data model not found."}), 404

    # Query for the specific record by ID
    record = DynamicLevelSensorData.query.get(id)
    if not record:
        return jsonify({"message": "Record not found."}), 404

    # Create the PDF
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, 780, "Sensor Data Report")
    p.line(50, 770, 550, 770)
    p.setFont("Helvetica", 10)
    p.drawString(100, 750, f"Date: {record.date.strftime('%d/%m/%Y %H:%M:%S')}")
    p.drawString(100, 730, f"Full Address: {record.full_addr}")
    p.drawString(100, 710, f"Sensor Data: {record.sensor_data}")
    p.drawString(100, 690, f"Vehicle No: {record.vehicleno}")
    p.drawString(100, 670, f"Volume (liters): {record.volume_liters}")
    p.line(50, 660, 550, 660)
    p.showPage()
    p.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"record_{id}.pdf",
        mimetype='application/pdf'
    )



@app.route('/generate_qr/<int:id>')
def generate_qr(id):
    pdf_url = url_for('generate_pdf', id=id, _external=True)  # Generate PDF route URL

    # Create QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=4,
        border=2,
    )
    qr.add_data(pdf_url)  # Encode PDF URL in the QR code
    qr.make(fit=True)
    
    img = qr.make_image(fill='black', back_color='white')
    img_io = io.BytesIO()
    img.save(img_io, format='PNG')
    img_io.seek(0)
    
    return send_file(img_io, mimetype='image/png')

# Create a route to handle redirection from QR code to PDF
@app.route('/scan_qr/<vehicleno>', methods=['GET'])
def scan_qr(vehicleno):
    record = LevelSensorData.query.filter_by(vehicleno=vehicleno).first_or_404()
    return redirect(url_for('generate_pdf', id=record.id))




#create a simulation button

simulation_thread = None
simulation_running = False


def run_simulation():
    global simulation_running
    while simulation_running:
        # Simulation logic: generate random data
        test_data = {
            'D': datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            'address': '400001', 
            'data': [random.randint(50, 200)],  # Random data between 50 and 200
            'Vehicle no': '0448'
        }
        # Send test data to your existing endpoint
        with app.test_client() as client:
            response = client.post('/level_sensor_data', json={'level_sensor_data': json.dumps(test_data)})
            print(f'Simulation data sent: {response.json}')
        time.sleep(60)  # Adjust the interval as needed

@app.route('/start_simulation', methods=['POST'])
def start_simulation():
    global simulation_thread, simulation_running
    if simulation_running:
        return jsonify({'message': 'Simulation already running'}), 400

    simulation_running = True
    simulation_thread = threading.Thread(target=run_simulation)
    simulation_thread.start()
    return jsonify({'message': 'Simulation started successfully'}), 200

@app.route('/stop_simulation', methods=['POST'])
def stop_simulation():
    global simulation_running
    if not simulation_running:
        return jsonify({'message': 'No simulation running'}), 400

    simulation_running = False
    simulation_thread.join()
    return jsonify({'message': 'Simulation stopped successfully'}), 200


#settings butoon for column 

@app.route('/settings')
def settings():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        if user.is_admin:
            return render_template('settings.html', title="Settings")
        else:
            return redirect('/dashboard')  # Redirect to dashboard or another page
    return redirect('/login')
  

@app.route('/client-onboarding')
def client_onboarding():
    return render_template('client_onboarding.html')

@app.route('/access-onboarding')
def access_onboarding():
    return render_template('access_onboarding.html')



#to display table 
@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    user_list = []
    for user in users:
        user_list.append({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'status': user.status,
            'is_admin': user.is_admin
        })
    return jsonify(user_list)



@app.route('/api/counts', methods=['GET'])
def get_counts():
    total_clients = User.query.filter_by(is_admin=0).count()
    total_companies = User.query.filter_by(is_admin=1).count()  # Adjust this if necessary
    return jsonify({
        'totalClients': total_clients,
        'totalCompanies': total_companies
    })


  
@app.route('/api/users/<int:user_id>/status', methods=['POST'])
def update_user_status(user_id):
    user = User.query.get(user_id)
    if user:
        status = request.json.get('status')
        user.status = status
        db.session.commit()
        return jsonify({'message': 'User status updated successfully'})
    else:
        return jsonify({'message': 'User not found'}), 404



    
@app.route('/api/users/<int:user_id>/role', methods=['POST'])
def update_user_role(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    data = request.json
    is_admin = data.get('is_admin')

    if is_admin is not None:
        user.is_admin = is_admin
        db.session.commit()
        return jsonify({"message": "User role updated successfully"}), 200
    else:
        return jsonify({"error": "Invalid data"}), 400
    
# Ensure that only logged-in admins can access the route
@app.route('/admin/add-user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return "Unauthorized", 403

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        is_admin = request.form.get('is_admin', 0)  # Defaults to 0 if not provided

        new_user = User(name=name, email=email, password=password, is_admin=int(is_admin))
        db.session.add(new_user)
        db.session.commit()
        return redirect('/admin/add-user')

    return render_template('add_user.html')  # This should be the path to your form template


#add users from user pov

@app.route('/add_user_account', methods=['POST'])
def add_user_account():
    accountname = request.form['accountname']
    accountemail = request.form['accountemail']
    accountpassword = request.form['accountpassword']
    accountrole = request.form['accountrole']
    
    

    # Create new user account in the database
    new_account = UserAccount(
        accountname=accountname,
        accountemail=accountemail,
        accountpassword=accountpassword,  # Ensure to hash passwords in a real application
        is_admin=True if accountrole == '1' else False
    )
    
    # Set the password using the method to hash it
    new_account.set_password(accountpassword)
    
    db.session.add(new_account)
    db.session.commit()

    return jsonify({'message': 'User account added successfully'}), 201


@app.route('/api/user_accounts', methods=['GET'])
def get_user_accounts():
    users = UserAccount.query.all()
    user_list = [
        {
            'id': user.id,
            'accountname': user.accountname,
            'accountemail': user.accountemail,
            'is_admin': user.is_admin,
            'status': user.status
        }
        for user in users
    ]
    return jsonify(user_list)


@app.route('/api/user_accounts/<int:account_id>/status', methods=['POST'])
def update_user_account_status(account_id):
    user = UserAccount.query.get(account_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    status = request.json.get('status')
    user.status = status
    db.session.commit()
    return jsonify({'message': 'User status updated successfully'})

@app.route('/api/user_accounts/<int:account_id>/role', methods=['POST'])
def update_role(account_id):
    user = User.query.get(account_id)
    new_role = request.json.get('role')
    
    if user:
        user.is_admin = new_role == 'admin'
        user.is_super_admin = user.email == 'admin@gmail.com'
        
        if user.is_admin:
            create_sensor_data_table(f'level_sensor_data_{user.name}')
        
        try:
            db.session.commit()
            return jsonify({'message': 'Role updated successfully!'}), 200
        except IntegrityError:
            db.session.rollback()
            return jsonify({'message': 'Error updating role.'}), 500
    else:
        return jsonify({'message': 'User not found.'}), 404

@app.route('/api/account_counts', methods=['GET'])
def get_account_counts():
    total_accounts = UserAccount.query.filter_by(is_admin=False).count()
    active_accounts = UserAccount.query.filter_by(status=True).count()
    return jsonify({
        'totalAccounts': total_accounts,
        'activeAccounts': active_accounts
    })



@app.route('/api/admin/<adminname>/sensor_data', methods=['GET', 'POST'])
def add_sensor_data(adminname):
    try:
        user = User.query.filter_by(name=adminname).first()
        if not user:
            return jsonify({"message": "Admin not found"}), 404

        table_name = f'level_sensor_data_{adminname}'

        # Check if the model exists in the dynamic_models dictionary
        if table_name not in dynamic_models:
            print(f"Model for {table_name} not found. Attempting to create it.")  # Debugging line
            create_sensor_data_table(table_name)

        DynamicLevelSensorData = dynamic_models[table_name]

        if request.method == 'POST':
            # Handling POST request to add sensor data
            data = request.json.get('level_sensor_data')
            if not data:
                return jsonify({"message": "Invalid data"}), 400

            parsed_data = json.loads(data)
            date_str = parsed_data.get('D')
            date_obj = datetime.strptime(date_str, "%d/%m/%Y %H:%M:%S")
            full_addr = parsed_data.get('address')
            sensor_data = parsed_data.get('data')[0]
            vehicleno = parsed_data.get('Vehicle no')
            volume_liters = get_volume(sensor_data)

            # Create a new entry
            sensor_data_entry = DynamicLevelSensorData(
                date=date_str,
                full_addr=full_addr,
                sensor_data=sensor_data,
                vehicleno=vehicleno,
                volume_liters=volume_liters
            )

            db.session.add(sensor_data_entry)
            db.session.commit()

            return jsonify({"message": f"Data added to {table_name}"}), 201

        elif request.method == 'GET':
            # Fetching volume_liters data for the chart
            sensor_data = DynamicLevelSensorData.query.all()

            if not sensor_data:
                return jsonify({"message": "No data found"}), 404

            # Return date and volume_liters as a JSON response
            result = [{"date": entry.date, "volume_liters": entry.volume_liters} for entry in sensor_data]

            return jsonify(result), 200

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@app.route('/api/get_current_admin', methods=['GET'])
def get_current_admin():
    admin_name = session.get('admin_name')
    if admin_name:
        return jsonify({"admin_name": admin_name}), 200
    else:
        return jsonify({"message": "No admin logged in"}), 404



if __name__ == '__main__':
    
    app.run(debug=True)