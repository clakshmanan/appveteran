
import streamlit as st
from streamlit_option_menu import option_menu
import sqlite3  # Changed from mysql.connector
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import Row
import traceback
import io
import pandas as pd
import base64
from datetime import datetime
from PIL import Image
import os
from dotenv import load_dotenv
import bcrypt
import hashlib
import toml
from functools import wraps


# ==============================================
# INITIAL SETUP AND CONFIGURATION
# ==============================================

# Set page config - MUST BE FIRST STREAMLIT COMMAND
st.set_page_config(
    page_title="icgvwa",
    page_icon="🌀",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load environment variables
load_dotenv()

# ==============================================
# CUSTOM CSS STYLING
# ==============================================

def inject_custom_css():
    st.markdown("""
    <style>
        /* Main container styling */
        .stApp {
            background-color: #f8f9fa;
        }
        
        /* Sidebar styling */
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #52b5f7, #112f8f) !important;
            color: white;
        }
        
        .sidebar .sidebar-content {
            color: white;
        }
        
        /* Sidebar navigation items */
        [data-testid="stSidebarNavItems"] {
            padding-top: 20px;
        }
        
        [data-testid="stSidebarNavItems"] > div > div {
            color: white !important;
            margin-bottom: 10px;
            border-radius: 5px;
            padding: 8px 12px;
            transition: all 0.3s ease;
        }
        
        [data-testid="stSidebarNavItems"] > div > div:hover {
            background-color: rgba(255, 255, 255, 0.1);
        }
        
        [data-testid="stSidebarNavItems"] > div > div[aria-selected="true"] {
            background-color: #3b82f6 !important;
            color: white !important;
            font-weight: bold;
        }
        
        /* Form styling */
        .stForm {
            background-color: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
        
        .stForm h3 {
            color: #1e40af;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        
        /* Button styling */
        .stButton>button {
            background-color: #3b82f6;
            color: white;
            border-radius: 5px;
            border: none;
            padding: 8px 16px;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .stButton>button:hover {
            background-color: #2563eb;
            transform: translateY(-1px);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
        
        /* Input field styling */
        .stTextInput>div>div>input, 
        .stTextArea>div>div>textarea,
        .stNumberInput>div>div>input,
        .stDateInput>div>div>input,
        .stSelectbox>div>div>select {
            border-radius: 5px;
            border: 1px solid #d1d5db;
            padding: 8px 12px;
        }
        
        /* Card styling for dashboard elements */
        .card {
            background-color: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
        
        /* Dataframe styling */
        .stDataFrame {
            border-radius: 10px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
        
        /* Success/error message styling */
        .stAlert {
            border-radius: 8px;
        }
        
        /* Title styling */
        h1 {
            color: #1e40af;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 10px;
        }
        
        /* Section header styling */
        h2 {
            color: #1e40af;
            margin-top: 1.5em;
        }
        
        /* Logo styling */
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .logo h1 {
            color: white;
            font-size: 24px;
            margin-top: 10px;
        }
        
        /* Responsive adjustments */
        @media (max-width: 768px) {
            .stForm {
                padding: 15px;
            }
        }
    </style>
    """, unsafe_allow_html=True)

# Inject custom CSS
inject_custom_css()

# ==============================================
# DATABASE CONFIGURATION (SQLite)
# ==============================================

# SQLite database file path
DB_FILE = os.getenv('DB_FILE', 'veteran_db.sqlite')

# Create SQLite engine
try:
    DATABASE_URL = f"sqlite:///{DB_FILE}"
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    
    # Create tables if they don't exist (initial setup)
    def initialize_database():
        with engine.connect() as conn:
            # Create SuperAdmin table
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS SuperAdmin (
                    superadmin_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            
            # Create StateAdmin table
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS StateAdmin (
                    stateadmin_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    superadmin_id INTEGER,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email TEXT NOT NULL,
                    state_name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (superadmin_id) REFERENCES SuperAdmin(superadmin_id)
                )
            """))
            
            # Create Users table
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS Users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    stateadmin_id INTEGER,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (stateadmin_id) REFERENCES StateAdmin(stateadmin_id)
                )
            """))
            
            # Create Personal_Details table
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS Personal_Details (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    asnid INTEGER,
                    name TEXT,
                    exrank TEXT,
                    number TEXT,
                    branch TEXT,
                    dob DATE,
                    blood_group TEXT,
                    med_cat TEXT,
                    category_details TEXT,
                    living_city TEXT,
                    qualification TEXT,
                    re_employed BOOLEAN DEFAULT 0,
                    company_name TEXT,
                    position TEXT,
                    passport_size_photo BLOB,
                    FOREIGN KEY (user_id) REFERENCES Users(user_id)
                )
            """))
            
            # Create Family_Details table
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS Family_Details (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    spouse_name TEXT,
                    spouse_contact_no TEXT,
                    address TEXT,
                    living_city TEXT,
                    spouse_photo BLOB,
                    spouse_dob DATE,
                    spouse_blood_group TEXT,
                    spouse_qualification TEXT,
                    if_employed BOOLEAN DEFAULT 0,
                    first_child_name TEXT,
                    first_child_dob DATE,
                    first_child_qualification TEXT,
                    first_child_married BOOLEAN DEFAULT 0,
                    first_child_employed BOOLEAN DEFAULT 0,
                    first_child_photo BLOB,
                    second_child_name TEXT,
                    second_child_dob DATE,
                    second_child_qualification TEXT,
                    second_child_married BOOLEAN DEFAULT 0,
                    second_child_employed BOOLEAN DEFAULT 0,
                    second_child_photo BLOB,
                    third_child_name TEXT,
                    third_child_dob DATE,
                    third_child_qualification TEXT,
                    third_child_married BOOLEAN DEFAULT 0,
                    third_child_employed BOOLEAN DEFAULT 0,
                    third_child_photo BLOB,
                    FOREIGN KEY (user_id) REFERENCES Users(user_id)
                )
            """))
            
            # Create Documents table
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS Documents (
                    document_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    particular TEXT NOT NULL,
                    document_name TEXT NOT NULL,
                    issued_by TEXT NOT NULL,
                    with_effect_from DATE NOT NULL,
                    remarks TEXT,
                    document_data BLOB NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES Users(user_id)
                )
            """))
            
            # Create Subscriptions table
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS Subscriptions (
                    subscription_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asnid INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    exrank TEXT NOT NULL,
                    number TEXT,
                    branch TEXT,
                    paid_date DATE NOT NULL,
                    due_date DATE NOT NULL,
                    payment_mode TEXT NOT NULL,
                    transaction_id TEXT,
                    amount REAL NOT NULL
                )
            """))
            
            # Create Master_Veteran_View as a virtual table (SQLite doesn't support views like MySQL)
            # We'll handle this in the code when needed
            
            conn.commit()
    
    initialize_database()
    
except Exception as e:
    st.error(f"❌ Database connection failed: {str(e)}")
    st.stop()

# ==============================================
# SESSION STATE INITIALIZATION
# ==============================================

if 'user' not in st.session_state:
    st.session_state.user = None
if 'role' not in st.session_state:
    st.session_state.role = None
if 'state' not in st.session_state:
    st.session_state.state = None

# ==============================================
# SECURITY UTILITIES
# ==============================================

def validate_password(password: str) -> bool:
    """Check password meets complexity requirements"""
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in '!@#$%^&*' for c in password):
        return False
    return True

def hash_password(password: str) -> str:
    """Securely hash password with bcrypt"""
    if not password:
        raise ValueError("Password cannot be empty")
    if not validate_password(password):
        raise ValueError("Password must be 8+ chars with uppercase, number, and special character")
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against stored hash"""
    if not all([plain_password, hashed_password]):
        return False
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

def get_db_connection():
    try:
        return sqlite3.connect(DB_FILE)
    except sqlite3.Error as err:
        st.error(f"Database connection failed: {err}")
        return None

# ==============================================
# AUTHENTICATION DECORATORS
# ==============================================

def superadmin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if st.session_state.role != 'superadmin':
            st.warning("⛔ You need SuperAdmin privileges to access this page")
            return
        return func(*args, **kwargs)
    return wrapper

def stateadmin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if st.session_state.role != 'stateadmin':
            st.warning("⛔ You need StateAdmin privileges to access this page")
            return
        return func(*args, **kwargs)
    return wrapper

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not st.session_state.user:
            st.warning("🔒 Please login to access this page")
            return
        return func(*args, **kwargs)
    return wrapper

# ==============================================
# DATABASE OPERATIONS
# ==============================================

def create_user(username: str, password: str, email: str, role: str, state: str = None) -> bool:
    """Create a new user with proper validation"""
    if not all([username, password, email, role]):
        st.error("All fields are required")
        return False
    
    try:
        if not validate_password(password):
            st.error("Password must be 8+ chars with uppercase, number, and special character")
            return False
            
        hashed_pw = hash_password(password)
        with Session() as session:
            if role == 'superadmin':
                session.execute(
                    text("""
                        INSERT INTO SuperAdmin (username, password_hash, email) 
                        VALUES (:username, :password, :email)
                    """),
                    {'username': username, 'password': hashed_pw, 'email': email}
                )
            elif role == 'stateadmin':
                if not state:
                    st.error("State is required for stateadmin")
                    return False
                # Get first superadmin as default
                superadmin_id = session.execute(text("SELECT superadmin_id FROM SuperAdmin LIMIT 1")).scalar()
                if not superadmin_id:
                    st.error("No SuperAdmin exists to assign this StateAdmin")
                    return False
                
                session.execute(
                    text("""
                        INSERT INTO StateAdmin (superadmin_id, username, password_hash, email, state_name) 
                        VALUES (:superadmin_id, :username, :password, :email, :state)
                    """),
                    {'superadmin_id': superadmin_id, 'username': username, 'password': hashed_pw, 'email': email, 'state': state}
                )
            elif role == 'user':
                # Get first stateadmin as default (or current stateadmin if logged in)
                stateadmin_id = 1
                if st.session_state.role == 'stateadmin':
                    stateadmin_id = st.session_state.user.get('stateadmin_id', 1)
                
                session.execute(
                    text("""
                        INSERT INTO Users (stateadmin_id, username, password_hash, email) 
                        VALUES (:stateadmin_id, :username, :password, :email)
                    """),
                    {'stateadmin_id': stateadmin_id, 'username': username, 'password': hashed_pw, 'email': email}
                )
            session.commit()
            return True
    except Exception as e:
        st.error(f"Error creating user: {str(e)}")
        return False

# ---------------------------------------------------------------------
def verify_user(username: str, password: str) -> tuple:
    """Verify user credentials across all tables"""
    if not username or not password:
        return None, None
    
    try:
        with Session() as session:
            # Check SuperAdmin
            result = session.execute(
                text("SELECT * FROM SuperAdmin WHERE username = :username"),
                {'username': username}
            ).mappings().first()
            role = 'superadmin'
            
            if not result:
                # Check StateAdmin
                result = session.execute(
                    text("SELECT * FROM StateAdmin WHERE username = :username"),
                    {'username': username}
                ).mappings().first()
                role = 'stateadmin'
                
            if not result:
                # Check Users
                result = session.execute(
                    text("SELECT * FROM Users WHERE username = :username"),
                    {'username': username}
                ).mappings().first()
                role = 'user'
            
            if result and verify_password(password, result['password_hash']):
                return dict(result), role
    except Exception as e:
        st.error(f"Login error: {str(e)}")
        st.error(traceback.format_exc())
    
    return None, None

# ==============================================
# INITIAL SETUP FUNCTIONS
# ==============================================

def initialize_first_superadmin():
    """Create default admin account if none exists (dev only)"""
    if os.getenv('ENVIRONMENT') != 'development':
        return
        
    try:
        with Session() as session:
            count = session.execute(text("SELECT COUNT(*) FROM SuperAdmin")).scalar()
            if count == 0:
                default_username = "admin"
                default_password = "Admin@123!"  # Change after first login
                default_email = "lakshmananmailbag@gmail.com"
                
                hashed_pw = hash_password(default_password)
                session.execute(
                    text("""
                        INSERT INTO SuperAdmin (username, password_hash, email)
                        VALUES (:username, :password, :email)
                    """),
                    {
                        'username': default_username,
                        'password': hashed_pw,
                        'email': default_email
                    }
                )
                session.commit()
                st.warning(f"""
                    ⚠️ Default Admin Created (Development Only) ⚠️
                    Username: {default_username}
                    Password: {default_password}
                    Please change this password immediately!
                """)
    except Exception as e:
        st.error(f"Initialization error: {str(e)}")

# Run initialization
initialize_first_superadmin()

# ==============================================
# UI COMPONENTS
# ==============================================

def login_form():
    """Login form with validation"""
    with st.sidebar:
        st.markdown("""
        <div class="logo">
            <h1>Veteran Menu</h1>
        </div>
        """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        with st.container():
            st.markdown("""
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #1e40af;">Welcome to ICGVWA</h1>
                <p style="color: #1e40af">Please login to access your account</p>
            </div>
            """, unsafe_allow_html=True)
            
            with st.form("Login", clear_on_submit=True):
                st.text_input("Username", key="login_username", placeholder="Enter your username")
                st.text_input("Password", type="password", key="login_password", placeholder="Enter your password")
                
                if st.form_submit_button("Login", use_container_width=True):
                    username = st.session_state.login_username
                    password = st.session_state.login_password
                    if not username or not password:
                        st.error("Please enter both username and password")
                    else:
                        user, role = verify_user(username, password)
                        if user:
                            st.session_state.user = user
                            st.session_state.role = role
                            if role == 'stateadmin':
                                st.session_state.state = user.get('state_name')
                            st.success("Login successful!")
                            st.rerun()
                        else:
                            st.error("Invalid credentials")

def logout_button():
    """Secure logout with session clearing"""
    if st.sidebar.button("Logout", use_container_width=True):
        st.session_state.clear()
        st.success("You have been logged out")
        st.rerun()

# ==============================================
# APPLICATION PAGES
# ==============================================

def home_page():
    st.title("Veteran Dashboard")
    
    with st.container():
        st.markdown("""
        <div class="card">
            <h3>Welcome to the Veteran Database Management System</h3>
            <p>This portal provides comprehensive services for veterans including:</p>
            <ul>
                <li>📝 Veteran record management</li>
                <li>🏛️ State-wise administration</li>
                <li>💼 Job seeking portal</li>
                <li>💑 Matrimonial services</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    if st.session_state.role == 'superadmin':
        st.success("You are logged in as SuperAdmin")
    elif st.session_state.role == 'stateadmin':
        st.success(f"You are logged in as StateAdmin for {st.session_state.state}")
    elif st.session_state.role == 'user':
        st.success("You are logged in as a Veteran User")

@login_required
def personal_details_form(user_id=None):
    with st.form("Personal Details", clear_on_submit=False):
        st.subheader("Personal Details")
        
        col1, col2 = st.columns(2)
        with col1:
            asnid = st.number_input("ASN ID", min_value=100000, max_value=999999, step=1, value=100000)
            name = st.text_input("Full Name", value="")
            exrank = st.selectbox("Rank", ["Select", "PradhanAdhikari", "Pradhan Sahayak Engineer","Uttham_Adhikari","Uttham_Sahayak_Engineer" ,"Adhikari", "Pradhan_Navik", "Uttham_Navik","Uttham_Yantrik","Navik","Yantrik"])
            number = st.text_input("Contact Number", value="")
            branch = st.selectbox("Branch", ["RP", "SA", "AE", "AP","SE"])
            dob = st.date_input("Date of Birth", value=datetime(1980, 1, 1))
        
        with col2:
            blood_group = st.selectbox("Blood Group", ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"])
            med_cat = st.selectbox("Medical Category", ["A1", "A2", "A3", "B1", "B2", "C", "D", "E"])
            category_details = st.text_area("Category Details", value="")
            living_city = st.text_input("Current City", value="")
            qualification = st.text_input("Highest Qualification", value="")
            re_employed = st.checkbox("Currently Re-employed?", value=False)
        
        company_name = ""
        position = ""
        if re_employed:
            company_name = st.text_input("Company Name", value="")
            position = st.text_input("Position", value="")
        
        passport_photo = st.file_uploader("Passport Size Photo", type=["jpg", "jpeg", "png"])
        
        submitted = st.form_submit_button("Save Details")
        
        if submitted:
            try:
                photo_bytes = None
                if passport_photo:
                    try:
                        img = Image.open(passport_photo)
                        photo_bytes = io.BytesIO()
                        img.save(photo_bytes, format='PNG')
                        photo_bytes = photo_bytes.getvalue()
                    except Exception as e:
                        st.warning(f"Couldn't process image: {e}")

                with Session() as session:
                    params = {
                        'user_id': st.session_state.user.get('user_id'),
                        'asnid': asnid,
                        'name': name or None,
                        'exrank': exrank or None,
                        'number': number or None,
                        'branch': branch or None,
                        'dob': dob,
                        'blood_group': blood_group or None,
                        'med_cat': med_cat or None,
                        'category_details': category_details or None,
                        'living_city': living_city or None,
                        'qualification': qualification or None,
                        're_employed': 1 if re_employed else 0,
                        'company_name': company_name or None,
                        'position': position or None,
                        'passport_size_photo': photo_bytes
                    }

                    if user_id:
                        query = text("""
                            UPDATE Personal_Details SET 
                            asnid=:asnid, name=:name, exrank=:exrank, number=:number, branch=:branch, 
                            dob=:dob, blood_group=:blood_group, med_cat=:med_cat, category_details=:category_details,
                            living_city=:living_city, qualification=:qualification, re_employed=:re_employed,
                            company_name=:company_name, position=:position, passport_size_photo=:passport_size_photo
                            WHERE user_id=:user_id
                        """)
                    else:
                        query = text("""
                            INSERT INTO Personal_Details (
                                user_id, asnid, name, exrank, number, branch, dob, blood_group, med_cat, 
                                category_details, living_city, qualification, re_employed, company_name, 
                                position, passport_size_photo
                            ) VALUES (
                                :user_id, :asnid, :name, :exrank, :number, :branch, :dob, :blood_group, 
                                :med_cat, :category_details, :living_city, :qualification, :re_employed, 
                                :company_name, :position, :passport_size_photo
                            )
                        """)
                    
                    session.execute(query, params)
                    session.commit()
                
                st.success("Personal details saved successfully!")
                st.rerun()
                
            except Exception as e:
                st.error(f"Error saving details: {str(e)}")
                st.error(f"Full error: {traceback.format_exc()}")

@login_required
def family_details_form(user_id=None):
    with st.form("Family Details", clear_on_submit=False):
        st.subheader("Family Details")
        
        st.markdown("### Spouse Details")
        col1, col2 = st.columns(2)
        with col1:
            spouse_name = st.text_input("Spouse Name", value="")
            spouse_contact_no = st.text_input("Spouse Contact Number", value="")
            address = st.text_area("Address", value="")
            living_city = st.text_input("Current City", value="")
            spouse_dob = st.date_input("Spouse Date of Birth", value=datetime(1980, 1, 1))
        
        with col2:
            spouse_blood_group = st.selectbox("Spouse Blood Group", ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"])
            spouse_qualification = st.text_input("Spouse Qualification", value="")
            if_employed = st.checkbox("Is Spouse Employed?", value=False)
            spouse_photo = st.file_uploader("Spouse Photo", type=["jpg", "jpeg", "png"])
        
        st.markdown("### Children Details")
        children = st.selectbox("Number of Children", [0, 1, 2, 3])
        
        child_details = []
        for i in range(children):
            st.markdown(f"#### Child {i+1} Details")
            c_col1, c_col2 = st.columns(2)
            with c_col1:
                child_name = st.text_input(f"Child {i+1} Name", key=f"child_{i}_name")
                child_dob = st.date_input(f"Child {i+1} DOB", value=datetime(2000, 1, 1), key=f"child_{i}_dob")
                child_qualification = st.text_input(f"Child {i+1} Qualification", key=f"child_{i}_qualification")
            with c_col2:
                child_married = st.checkbox(f"Is Child {i+1} Married?", key=f"child_{i}_married")
                child_employed = st.checkbox(f"Is Child {i+1} Employed?", key=f"child_{i}_employed")
                child_photo = st.file_uploader(f"Child {i+1} Photo", type=["jpg", "jpeg", "png"], key=f"child_{i}_photo")
            
            child_details.append({
                'name': child_name,
                'dob': child_dob,
                'qualification': child_qualification,
                'married': child_married,
                'employed': child_employed,
                'photo': child_photo
            })
        
        submitted = st.form_submit_button("Save Family Details")
        
        if submitted:
            try:
                spouse_photo_bytes = None
                if spouse_photo:
                    try:
                        img = Image.open(spouse_photo)
                        spouse_photo_bytes = io.BytesIO()
                        img.save(spouse_photo_bytes, format='PNG')
                        spouse_photo_bytes = spouse_photo_bytes.getvalue()
                    except Exception as e:
                        st.warning(f"Couldn't process spouse image: {e}")

                data = {
                    'user_id': st.session_state.user.get('user_id'),
                    'spouse_name': spouse_name or None,
                    'spouse_contact_no': spouse_contact_no or None,
                    'address': address or None,
                    'living_city': living_city or None,
                    'spouse_photo': spouse_photo_bytes,
                    'spouse_dob': spouse_dob,
                    'spouse_blood_group': spouse_blood_group or None,
                    'spouse_qualification': spouse_qualification or None,
                    'if_employed': 1 if if_employed else 0
                }
                
                for i in range(3):
                    if i < len(child_details):
                        child = child_details[i]
                        child_photo_bytes = None
                        if child['photo']:
                            try:
                                img = Image.open(child['photo'])
                                child_photo_bytes = io.BytesIO()
                                img.save(child_photo_bytes, format='PNG')
                                child_photo_bytes = child_photo_bytes.getvalue()
                            except Exception as e:
                                st.warning(f"Couldn't process child {i+1} image: {e}")
                        
                        data.update({
                            f'child{i+1}_name': child['name'] or None,
                            f'child{i+1}_dob': child['dob'],
                            f'child{i+1}_qualification': child['qualification'] or None,
                            f'child{i+1}_married': 1 if child['married'] else 0,
                            f'child{i+1}_employed': 1 if child['employed'] else 0,
                            f'child{i+1}_photo': child_photo_bytes
                        })
                    else:
                        data.update({
                            f'child{i+1}_name': None,
                            f'child{i+1}_dob': None,
                            f'child{i+1}_qualification': None,
                            f'child{i+1}_married': 0,
                            f'child{i+1}_employed': 0,
                            f'child{i+1}_photo': None
                        })
                
                with Session() as session:
                    if user_id:
                        query = text("""
                            UPDATE Family_Details SET 
                            spouse_name=:spouse_name, spouse_contact_no=:spouse_contact_no, address=:address,
                            living_city=:living_city, spouse_photo=:spouse_photo, spouse_dob=:spouse_dob,
                            spouse_blood_group=:spouse_blood_group, spouse_qualification=:spouse_qualification,
                            if_employed=:if_employed,
                            first_child_name=:child1_name, first_child_dob=:child1_dob, first_child_qualification=:child1_qualification,
                            first_child_married=:child1_married, first_child_employed=:child1_employed, first_child_photo=:child1_photo,
                            second_child_name=:child2_name, second_child_dob=:child2_dob, second_child_qualification=:child2_qualification,
                            second_child_married=:child2_married, second_child_employed=:child2_employed, second_child_photo=:child2_photo,
                            third_child_name=:child3_name, third_child_dob=:child3_dob, third_child_qualification=:child3_qualification,
                            third_child_married=:child3_married, third_child_employed=:child3_employed, third_child_photo=:child3_photo
                            WHERE user_id=:user_id
                        """)
                    else:
                        query = text("""
                            INSERT INTO Family_Details (
                                user_id, spouse_name, spouse_contact_no, address, living_city, spouse_photo,
                                spouse_dob, spouse_blood_group, spouse_qualification, if_employed,
                                first_child_name, first_child_dob, first_child_qualification, first_child_married,
                                first_child_employed, first_child_photo, second_child_name, second_child_dob,
                                second_child_qualification, second_child_married, second_child_employed, second_child_photo,
                                third_child_name, third_child_dob, third_child_qualification, third_child_married,
                                third_child_employed, third_child_photo
                            ) VALUES (
                                :user_id, :spouse_name, :spouse_contact_no, :address, :living_city, :spouse_photo,
                                :spouse_dob, :spouse_blood_group, :spouse_qualification, :if_employed,
                                :child1_name, :child1_dob, :child1_qualification, :child1_married,
                                :child1_employed, :child1_photo, :child2_name, :child2_dob,
                                :child2_qualification, :child2_married, :child2_employed, :child2_photo,
                                :child3_name, :child3_dob, :child3_qualification, :child3_married,
                                :child3_employed, :child3_photo
                            )
                        """)
                    
                    session.execute(query, data)
                    session.commit()
                
                st.success("Family details saved successfully!")
                st.rerun()
                
            except Exception as e:
                st.error(f"Error saving family details: {str(e)}")
                st.error(f"Full error: {traceback.format_exc()}")

@superadmin_required
def superadmin_dashboard():
    st.title("SuperAdmin Dashboard")
    
    menu = option_menu(
        menu_title=None,
        options=["User Management", "View All Data", "Reports"],
        icons=["people", "database", "bar-chart"],
        orientation="horizontal",
        styles={
            "container": {"padding": "0!important", "background-color": "#f8f9fa"},
            "icon": {"color": "orange", "font-size": "18px"}, 
            "nav-link": {"font-size": "16px", "text-align": "left", "margin":"0px", "--hover-color": "#eee"},
            "nav-link-selected": {"background-color": "#3b82f6"},
        }
    )
    
    if menu == "User Management":
        st.subheader("User Management")
        
        tab1, tab2 = st.tabs(["Create StateAdmin", "Create User"])
        
        with tab1:
            with st.form("Create StateAdmin"):
                st.markdown("### Create New State Admin")
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                email = st.text_input("Email")
                state = st.text_input("State")
                
                if st.form_submit_button("Create StateAdmin"):
                    if create_user(username, password, email, 'stateadmin', state):
                        st.success("StateAdmin created successfully!")
        
        with tab2:
            with st.form("Create User"):
                st.markdown("### Create New User")
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                email = st.text_input("Email")
                
                if st.form_submit_button("Create User"):
                    if create_user(username, password, email, 'user'):
                        st.success("User created successfully!")
    
    elif menu == "View All Data":
        st.subheader("All Veteran Data")
    
        try:
            with Session() as session:
                # SQLite doesn't support views like MySQL, so we'll create a query that joins all tables
                result = session.execute(text("""
                    SELECT 
                        u.user_id, u.username, u.email,
                        pd.asnid, pd.name, pd.exrank, pd.number, pd.branch, pd.dob,
                        pd.blood_group, pd.med_cat, pd.living_city, pd.qualification,
                        sa.state_name,
                        fd.spouse_name, fd.spouse_contact_no, fd.address,
                        fd.first_child_name, fd.second_child_name, fd.third_child_name
                    FROM Users u
                    LEFT JOIN Personal_Details pd ON u.user_id = pd.user_id
                    LEFT JOIN StateAdmin sa ON u.stateadmin_id = sa.stateadmin_id
                    LEFT JOIN Family_Details fd ON u.user_id = fd.user_id
                """))
                df = pd.DataFrame(result.fetchall())
            
            st.dataframe(df)
        except Exception as e:
            st.error(f"Error loading data: {str(e)}")

    elif menu == "Reports":
        st.subheader("Reports")
        st.write("Reporting functionality will be implemented here")

@stateadmin_required
def stateadmin_dashboard():
    st.title(f"{st.session_state.state} State Admin Dashboard")

    menu = option_menu(
    menu_title=None,
    options=["View State Data", "User Management", "Reports"],
    icons=["database", "people", "bar-chart"],
    orientation="horizontal",
    styles={
        "container": {"padding": "0!important", "background-color": "#f8f9fa"},
        "icon": {"color": "orange", "font-size": "18px"}, 
        "nav-link": {"font-size": "16px", "text-align": "left", "margin":"0px", "--hover-color": "#eee"},
        "nav-link-selected": {"background-color": "#3b82f6"},
        }
    )

    if menu == "View State Data":
        st.subheader(f"Veteran Data for {st.session_state.state}")
        
        try:
            with Session() as session:
                query = text("""
                    SELECT pd.* FROM Personal_Details pd
                    JOIN Users u ON pd.user_id = u.user_id
                    JOIN StateAdmin sa ON u.stateadmin_id = sa.stateadmin_id
                    WHERE sa.state_name = :state
                """)
                result = session.execute(query, {'state': st.session_state.state})
                df = pd.DataFrame(result.fetchall())
            
            st.dataframe(df)
        except Exception as e:
            st.error(f"Error loading state data: {str(e)}")

    elif menu == "User Management":
        st.subheader("User Management")
        
        with st.form("Create User"):
            st.markdown("### Create New User")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            email = st.text_input("Email")
            
            if st.form_submit_button("Create User"):
                if create_user(username, password, email, 'user'):
                    st.success("User created successfully!")

    elif menu == "Reports":
        st.subheader("Reports")
        st.write("State-level reports will be implemented here")

@login_required
def job_portal():
    st.title("Job Seeking Portal")
    with st.container():
        st.markdown("""
        <div class="card">
            <h3>Find Job Opportunities</h3>
            <p>Browse through available job postings suitable for veterans.</p>
        </div>
        """, unsafe_allow_html=True)

    try:
        with Session() as session:
            result = session.execute(text("""
                SELECT pd.user_id, pd.name, pd.exrank, pd.branch, pd.qualification, 
                    pd.re_employed, pd.company_name, pd.position, pd.living_city
                FROM Personal_Details pd
            """))
            jobs_df = pd.DataFrame(result.fetchall())
        
        st.dataframe(jobs_df)
        
        st.subheader("Search Jobs")
        search_term = st.text_input("Search by skills, location, etc.")
        if search_term:
            filtered_df = jobs_df[jobs_df.apply(lambda row: row.astype(str).str.contains(search_term, case=False).any(), axis=1)]
            st.dataframe(filtered_df)
    except Exception as e:
        st.error(f"Error loading job data: {str(e)}")

@login_required
def matrimonial_portal():
    st.title("Matrimonial Portal")
    with st.container():
        st.markdown("""
        <div class="card">
            <h3>Find Matches</h3>
            <p>Browse through profiles for matrimonial matches.</p>
        </div>
        """, unsafe_allow_html=True)

    try:
        with Session() as session:
            result = session.execute(text("""
                SELECT pd.user_id, pd.name, pd.exrank, pd.branch, pd.living_city,
                    fd.first_child_name, fd.first_child_dob, fd.first_child_qualification,
                    fd.first_child_married, fd.first_child_employed
                FROM Personal_Details pd
                JOIN Family_Details fd ON pd.user_id = fd.user_id
                WHERE fd.first_child_name IS NOT NULL
            """))
            matrimonial_df = pd.DataFrame(result.fetchall())
        
        st.dataframe(matrimonial_df)
        
        st.subheader("Search Profiles")
        search_term = st.text_input("Search by location, qualification, etc.")
        if search_term:
            filtered_df = matrimonial_df[matrimonial_df.apply(lambda row: row.astype(str).str.contains(search_term, case=False).any(), axis=1)]
            st.dataframe(filtered_df)
    except Exception as e:
        st.error(f"Error loading matrimonial data: {str(e)}")

# ======================================
# DOCUMENT MANAGEMENT FUNCTIONS
# =======================================

@login_required
def document_management():
    st.title("Document Management System")
    menu = option_menu(
    menu_title=None,
    options=["Upload Document", "View Documents", "Search Documents"],
    icons=["upload", "folder", "search"],
    orientation="horizontal",
    styles={
        "container": {"padding": "0!important", "background-color": "#f8f9fa"},
        "icon": {"color": "orange", "font-size": "18px"}, 
        "nav-link": {"font-size": "16px", "text-align": "left", "margin":"0px", "--hover-color": "#eee"},
        "nav-link-selected": {"background-color": "#3b82f6"},
        }
    )

    if menu == "Upload Document":
        with st.form("Upload Document", clear_on_submit=True):
            st.subheader("Upload New Document")
            
            col1, col2 = st.columns(2)
            with col1:
                particular = st.text_input("Particular*", help="Brief description of the document")
                document_name = st.text_input("Document Name*")
                issued_by = st.text_input("Issued By*", help="Organization/authority that issued this document")
            
            with col2:
                with_effect_from = st.date_input("With Effect From*", value=datetime.today())
                remarks = st.text_area("Remarks")
            
            uploaded_file = st.file_uploader("Upload PDF Document*", type=["pdf"])
            
            submitted = st.form_submit_button("Save Document")
            
            if submitted:
                if not all([particular, document_name, issued_by, uploaded_file]):
                    st.error("Please fill all required fields (marked with *)")
                else:
                    try:
                        pdf_bytes = uploaded_file.getvalue()
                        
                        with Session() as session:
                            session.execute(
                                text("""
                                    INSERT INTO Documents (
                                        user_id, particular, document_name, issued_by, 
                                        with_effect_from, remarks, document_data
                                    ) VALUES (
                                        :user_id, :particular, :document_name, :issued_by,
                                        :with_effect_from, :remarks, :document_data
                                    )
                                """),
                                {
                                    'user_id': st.session_state.user.get('user_id'),
                                    'particular': particular,
                                    'document_name': document_name,
                                    'issued_by': issued_by,
                                    'with_effect_from': with_effect_from,
                                    'remarks': remarks or None,
                                    'document_data': pdf_bytes
                                }
                            )
                            session.commit()
                        st.success("Document uploaded successfully!")
                    except Exception as e:
                        st.error(f"Error uploading document: {str(e)}")

    elif menu == "View Documents":
        st.subheader("Your Documents")
        try:
            with Session() as session:
                result = session.execute(
                    text("""
                        SELECT 
                            document_id, particular, document_name, issued_by,
                            with_effect_from, remarks
                        FROM Documents
                        WHERE user_id = :user_id
                        ORDER BY with_effect_from DESC
                    """),
                    {'user_id': st.session_state.user.get('user_id')}
                )
                documents = result.fetchall()
                
                if documents:
                    df = pd.DataFrame(
                        documents,
                        columns=["ID", "Particular", "Document Name", "Issued By", "Effective From", "Remarks"]
                    )
                    st.dataframe(df)
                    
                    # Add download option for each document
                    selected_id = st.selectbox("Select Document to Download", df['ID'])
                    
                    if st.button("Download Selected Document"):
                        doc_result = session.execute(
                            text("SELECT document_name, document_data FROM Documents WHERE document_id = :doc_id"),
                            {'doc_id': selected_id}
                        ).fetchone()
                        
                        if doc_result:
                            st.download_button(
                                label="Click to Download",
                                data=doc_result[1],
                                file_name=doc_result[0] + ".pdf",
                                mime="application/pdf"
                            )
                        else:
                            st.warning("Document not found")
                else:
                    st.info("No documents found in your records")
        except Exception as e:
            st.error(f"Error loading documents: {str(e)}")

    elif menu == "Search Documents":
        st.subheader("Search Documents")
        search_query = st.text_input("Search by Particular, Document Name, or Issued By")
        
        if search_query:
            try:
                with Session() as session:
                    result = session.execute(
                        text("""
                            SELECT 
                                document_id, particular, document_name, issued_by,
                                with_effect_from, remarks
                            FROM Documents
                            WHERE user_id = :user_id
                            AND (particular LIKE :query 
                                OR document_name LIKE :query 
                                OR issued_by LIKE :query)
                            ORDER BY with_effect_from DESC
                        """),
                        {
                            'user_id': st.session_state.user.get('user_id'),
                            'query': f"%{search_query}%"
                        }
                    )
                    documents = result.fetchall()
                    
                    if documents:
                        df = pd.DataFrame(
                            documents,
                            columns=["ID", "Particular", "Document Name", "Issued By", "Effective From", "Remarks"]
                        )
                        st.dataframe(df)
                    else:
                        st.info("No matching documents found")
            except Exception as e:
                st.error(f"Error searching documents: {str(e)}")
        else:
            st.info("Enter search terms to find documents")
# ==============================================
# ANNUAL SUBSCRIPTION MANAGEMENT
# ==============================================
@login_required
def subscription_management():
    st.title("Annual Subscription Management")
    with st.container():
        st.markdown("""
        <div class="card">
            <h3>Veteran Subscription Portal</h3>
            <p>Manage annual subscriptions for veterans</p>
        </div>
        """, unsafe_allow_html=True)

    try:
        with Session() as session:
            # Get veteran's basic details
            veteran = session.execute(
                text("""
                    SELECT asnid, name, exrank, number, branch 
                    FROM Personal_Details 
                    WHERE user_id = :user_id
                """),
                {'user_id': st.session_state.user.get('user_id')}
            ).fetchone()
            
            if not veteran:
                st.error("Personal details not found. Please complete your profile first.")
                return
                
            # Get existing subscription if any
            subscription = session.execute(
                text("""
                    SELECT * FROM Subscriptions 
                    WHERE asnid = :asnid 
                    ORDER BY paid_date DESC LIMIT 1
                """),
                {'asnid': veteran.asnid}
            ).fetchone()
            
            # Display current status
            st.subheader("Current Subscription Status")
            cols = st.columns(3)
            with cols[0]:
                st.metric("ASN ID", veteran.asnid)
            with cols[1]:
                st.metric("Rank", veteran.exrank)
            with cols[2]:
                st.metric("Branch", veteran.branch)
            
            if subscription:
                st.success(f"✅ Last subscription paid on: {subscription.paid_date}")
                st.info(f"🔄 Next due on: {subscription.due_date}")
            else:
                st.warning("❌ No active subscription found")
            
            # Subscription form
            with st.form("Subscription Payment"):
                st.subheader("New Subscription Payment")
                
                paid_date = st.date_input("Payment Date*", value=datetime.today())
                payment_mode = st.selectbox("Payment Mode*", ["Online", "Bank Transfer", "Cash"])
                transaction_id = st.text_input("Transaction/Reference ID")
                amount = st.number_input("Amount (₹)*", min_value=100, value=500)
                
                if st.form_submit_button("Record Payment"):
                    if not all([paid_date, payment_mode, amount]):
                        st.error("Please fill all required fields (*)")
                    else:
                        due_date = paid_date + pd.DateOffset(years=1)
                        
                        session.execute(
                            text("""
                                INSERT INTO Subscriptions (
                                    asnid, name, exrank, number, branch,
                                    paid_date, due_date, payment_mode, 
                                    transaction_id, amount
                                ) VALUES (
                                    :asnid, :name, :exrank, :number, :branch,
                                    :paid_date, :due_date, :payment_mode,
                                    :transaction_id, :amount
                                )
                            """),
                            {
                                'asnid': veteran.asnid,
                                'name': veteran.name,
                                'exrank': veteran.exrank,
                                'number': veteran.number,
                                'branch': veteran.branch,
                                'paid_date': paid_date,
                                'due_date': due_date,
                                'payment_mode': payment_mode,
                                'transaction_id': transaction_id or None,
                                'amount': amount
                            }
                        )
                        session.commit()
                        st.success("Subscription recorded successfully!")
                        st.rerun()
                        
    except Exception as e:
        st.error(f"Error processing subscription: {str(e)}")
        st.error(traceback.format_exc())

# ==============================================
# MAIN APPLICATION
# ==============================================

def main():
    if not st.session_state.user:
        login_form()
    else:
    # Sidebar navigation
        with st.sidebar:
            st.markdown("""
            <div class="logo">
            <h1>Veteran Database</h1>
            </div>
            """, unsafe_allow_html=True)
        
            if st.session_state.role == 'superadmin':
                menu = option_menu(
                    menu_title=None,
                    options=["Dashboard", "User Management", "View All Data", "Reports","Documents", "Logout"],
                    icons=["speedometer2", "people", "database", "bar-chart", "file-earmark", "box-arrow-right"],
                    menu_icon="cast",
                    default_index=0,
                    styles={
                        "container": {"padding": "0!important", "background-color": "transparent"},
                        "icon": {"color": "white", "font-size": "16px"}, 
                        "nav-link": {"font-size": "16px", "text-align": "left", "margin":"0px", "--hover-color": "#3b82f6"},
                        "nav-link-selected": {"background-color": "#3b82f6"},
                    }
                )
            elif st.session_state.role == 'stateadmin':
                menu = option_menu(
                    menu_title=None,
                    options=["Dashboard", "View State Data", "User Management", "Reports", "Documents", "Logout"],
                    icons=["speedometer2", "database", "people", "bar-chart", "file-earmark", "box-arrow-right"],
                    menu_icon="cast",
                    default_index=0,
                    styles={
                        "container": {"padding": "0!important", "background-color": "transparent"},
                        "icon": {"color": "white", "font-size": "16px"}, 
                        "nav-link": {"font-size": "16px", "text-align": "left", "margin":"0px", "--hover-color": "#3b82f6"},
                        "nav-link-selected": {"background-color": "#3b82f6"},
                    }
                )
            else:
                menu = option_menu(
                    menu_title=None,
                    options=["Home", "Personal Details", "Family Details", "Job Portal", "Matrimonial","Documents", "Subscription","Logout"],
                    icons=["house", "person", "people", "briefcase", "heart", "file-earmark", "credit-card", "box-arrow-right"],
                    menu_icon="cast",
                    default_index=0,
                    styles={
                        "container": {"padding": "0!important", "background-color": "transparent"},
                        "icon": {"color": "white", "font-size": "16px"}, 
                        "nav-link": {"font-size": "16px", "text-align": "left", "margin":"0px", "--hover-color": "#3b82f6"},
                        "nav-link-selected": {"background-color": "#3b82f6"},
                    }
                )
        
        # Main content area
        if st.session_state.role == 'superadmin':
            if menu == "Dashboard":
                home_page()
            elif menu == "User Management":
                superadmin_dashboard()
            elif menu == "Documents":
                document_management()
            elif menu == "View All Data":
                st.title("All Veteran Data")
            
                try:
                    with Session() as session:
                        # SQLite doesn't support views like MySQL, so we'll create a query that joins all tables
                        result = session.execute(text("""
                            SELECT 
                                u.user_id, u.username, u.email,
                                pd.asnid, pd.name, pd.exrank, pd.number, pd.branch, pd.dob,
                                pd.blood_group, pd.med_cat, pd.living_city, pd.qualification,
                                sa.state_name,
                                fd.spouse_name, fd.spouse_contact_no, fd.address,
                                fd.first_child_name, fd.second_child_name, fd.third_child_name
                            FROM Users u
                            LEFT JOIN Personal_Details pd ON u.user_id = pd.user_id
                            LEFT JOIN StateAdmin sa ON u.stateadmin_id = sa.stateadmin_id
                            LEFT JOIN Family_Details fd ON u.user_id = fd.user_id
                        """))
                        df = pd.DataFrame(result.fetchall())
                    st.dataframe(df)
                except Exception as e:
                    st.error(f"Error loading data: {str(e)}")
            elif menu == "Reports":
                st.title("Reports")
                st.write("Reporting functionality will be implemented here")
            elif menu == "Logout":
                logout_button()
        elif st.session_state.role == 'stateadmin':
            if menu == "Dashboard":
                home_page()
            elif menu == "View State Data":
                stateadmin_dashboard()
            elif menu == "User Management":
                stateadmin_dashboard()
            elif menu == "Documents":
                document_management()
            elif menu == "Reports":
                st.title("Reports")
                st.write("State-level reports will be implemented here")
            elif menu == "Logout":
                logout_button()
        else:
            if menu == "Home":
                home_page()
            elif menu == "Personal Details":
                personal_details_form()
            elif menu == "Family Details":
                family_details_form()
            elif menu == "Documents":
                document_management()
            elif menu == "Job Portal":
                job_portal()
            elif menu == "Matrimonial":
                matrimonial_portal()
            elif menu == "Subscription":
                subscription_management()
            elif menu == "Logout":
                logout_button()
if __name__ == "__main__":
    main()
