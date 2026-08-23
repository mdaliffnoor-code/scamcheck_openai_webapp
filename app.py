import base64
import os
import uuid
import requests
import json

from flask import Flask, json, render_template, request, redirect, url_for, flash
from pathlib import Path
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash

from dotenv import load_dotenv

from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, ContentSettings

from openai import OpenAI

from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone


load_dotenv()

#=======================================================
#Phone Number Scanner API Key
#=======================================================
ABSTRACT_PHONE_API_KEY = os.getenv("ABSTRACT_PHONE_API_KEY")

app = Flask(__name__)


#======================================================
# Public Service Announcements (PSA) for scam awareness
#======================================================

PSA_ALERTS = [
    "Beware of impersonation scams requesting OTPs or urgent transfers.",
    "Never share banking credentials or OTPs with anyone.",
    "Verify suspicious requests through official channels."
]
#=======================================================
#SQL Setup
#=======================================================

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///scamcheck.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = "login"

# User table for authentication and role management
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(255),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="user"
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

# Define the ScanHistory model to store scan results

class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    scan_type = db.Column(
        db.String(30),
        nullable=False
    )

    input_value = db.Column(
        db.String(1000),
        nullable=True
    )

    risk_level = db.Column(
        db.String(30),
        nullable=True
    )

    result_summary = db.Column(
        db.Text,
        nullable=True
    )

    suspicious_indicators = db.Column(
        db.Text,
        nullable=True
    )

    recommended_action = db.Column(
        db.Text,
        nullable=True
    )

    blob_name = db.Column(
        db.String(500),
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

# Define the FlaggedPhoneNumber model to store flagged phone numbers
class FlaggedPhoneNumber(db.Model):

    __tablename__ = "flagged_phone_numbers"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    phone_number = db.Column(
        db.String(30),
        unique=True,
        nullable=False,
        index=True
    )

    risk_level = db.Column(
        db.String(30),
        nullable=False,
        default="HIGH RISK"
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    source = db.Column(
        db.String(100),
        nullable=True
    )

    is_active = db.Column(
        db.Boolean,
        default=True,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

#user loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

#Create the database tables if they don't exist
with app.app_context():
    db.create_all()


# Define the User model
AZURE_STORAGE_ACCOUNT_URL = os.getenv(
    "AZURE_STORAGE_ACCOUNT_URL"
)

AZURE_STORAGE_CONTAINER = os.getenv(
    "AZURE_STORAGE_CONTAINER",
    "screenshots"
)

GOOGLE_SAFE_BROWSING_API_KEY = os.getenv(
    "GOOGLE_SAFE_BROWSING_API_KEY"
)

azure_credential = DefaultAzureCredential()

blob_service_client = BlobServiceClient(
    account_url=AZURE_STORAGE_ACCOUNT_URL,
    credential=azure_credential
)

openai_client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

app.config['SECRET_KEY'] = 'change-this-before-production'

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / 'uploads'
UPLOAD_FOLDER.mkdir(exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Utility function to normalize URLs
def normalize_url(url):

    url = url.strip()

    if not url.startswith(
        ("http://", "https://")
    ):
        url = "https://" + url

    return url

# Check if a URL is safe using Google Safe Browsing API
def check_safe_browsing(url):

    api_url = (
        "https://safebrowsing.googleapis.com/"
        "v4/threatMatches:find"
    )

    params = {
        "key": GOOGLE_SAFE_BROWSING_API_KEY
    }

    payload = {
        "client": {
            "clientId": "scamcheck-capstone",
            "clientVersion": "1.0"
        },

        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],

            "platformTypes": [
                "ANY_PLATFORM"
            ],

            "threatEntryTypes": [
                "URL"
            ],

            "threatEntries": [
                {
                    "url": url
                }
            ]
        }
    }

    response = requests.post(
        api_url,
        params=params,
        json=payload,
        timeout=10
    )

    response.raise_for_status()

    return response.json()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def upload_to_blob(file_bytes, filename, content_type):

    unique_filename = f"{uuid.uuid4()}-{filename}"

    blob_client = blob_service_client.get_blob_client(
        container=AZURE_STORAGE_CONTAINER,
        blob=unique_filename
    )

    blob_client.upload_blob(
        file_bytes,
        overwrite=False,
        content_settings=ContentSettings(
            content_type=content_type
        )
    )

    return unique_filename


def analyse_screenshot(image_bytes, content_type):

    encoded_image = base64.b64encode(
        image_bytes
    ).decode("utf-8")

    image_data_url = (
        f"data:{content_type};base64,{encoded_image}"
    )

    prompt = """
You are assisting a scam-awareness application called ScamCheck.

Analyse this screenshot for possible scam indicators.

Look for:
- urgent or threatening wording
- requests for money or payment
- requests for passwords or OTPs
- suspicious URLs
- impersonation of banks, government agencies or companies
- prize or investment claims
- requests for personal information

Do not claim with certainty that the message is a scam.

Return ONLY valid JSON using exactly this structure:

{
    "risk_level": "LOW | POTENTIAL RISK | HIGH RISK",
    "suspicious_indicators": [
        "indicator 1",
        "indicator 2"
    ],
    "explanation": "Brief explanation.",
    "recommended_action": "Practical action the user should take."
}

Keep each suspicious indicator short and specific.

Do not include markdown.
Do not include headings outside the JSON.
Do not include any text before or after the JSON.
"""

    response = openai_client.responses.create(
        model="gpt-5.6-terra",
        input=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": prompt
                    },
                    {
                        "type": "input_image",
                        "image_url": image_data_url
                    }
                ]
            }
        ]
    )
    result = json.loads(response.output_text)

    return result

#Phone scanner phone number normalization function
def normalize_phone_number(phone_number):

    phone_number = phone_number.strip()

    cleaned = ""

    for character in phone_number:

        if character.isdigit() or character == "+":
            cleaned += character

    return cleaned

# Function to check phone number using Abstract Phone API
def check_abstract_phone(phone_number):

    api_key = os.getenv("ABSTRACT_PHONE_API_KEY")

    if not api_key:
        raise RuntimeError(
            "ABSTRACT_PHONE_API_KEY is not configured."
        )

    url = "https://phoneintelligence.abstractapi.com/v1/"

    try:

        print("Calling Abstract API for:", phone_number)

        response = requests.get(
            url,
            params={
                "api_key": api_key,
                "phone": phone_number
            },
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        print("Abstract API response:")
        print(data)

        return data

    except requests.RequestException as error:

        print("Abstract Phone API error:", error)

        return None

def analyse_phone_number(phone_number):

    # =====================================
    # 1. NORMALIZE PHONE NUMBER
    # =====================================

    normalized_phone = normalize_phone_number(
        phone_number
    )


    # =====================================
    # 2. CHECK INTERNAL DATABASE
    # =====================================

    flagged_number = (
        FlaggedPhoneNumber.query
        .filter_by(
            phone_number=normalized_phone,
            is_active=True
        )
        .first()
    )


    # =====================================
    # 3. IF FOUND IN DATABASE
    # =====================================

    if flagged_number:

        return {
            "source": "internal_database",

            "phone_number":
                normalized_phone,

            "risk_level":
                flagged_number.risk_level,

            "suspicious_indicators": [
                "Number found in ScamCheck flagged-number database"
            ],

            "explanation":
                flagged_number.description
                or
                "This number exists in the ScamCheck flagged-number database.",

            "recommended_action":
                "Do not provide personal information or make payments "
                "until the caller has been independently verified.",

            "details": {
                "reported_source":
                    flagged_number.source
            }
        }


    # =====================================
    # 4. NOT FOUND → CALL ABSTRACT API
    # =====================================

    api_result = check_abstract_phone(
        normalized_phone
    )


    # =====================================
    # 5. API FAILED
    # =====================================

    if api_result is None:

        return {
            "source": "abstract_api",

            "phone_number":
                normalized_phone,

            "risk_level":
                "UNKNOWN",

            "suspicious_indicators": [],

            "explanation":
                "The external phone intelligence service "
                "could not be reached.",

            "recommended_action":
                "Exercise caution and independently verify the caller.",

            "details": {}
        }


    # =====================================
    # 6. EXTRACT ABSTRACT DATA SAFELY
    # =====================================

    validation = (
        api_result.get("phone_validation")
        or {}
    )

    risk = (
        api_result.get("phone_risk")
        or {}
    )

    carrier = (
        api_result.get("phone_carrier")
        or {}
    )

    location = (
        api_result.get("phone_location")
        or {}
    )


    # =====================================
    # 7. CONVERT ABSTRACT RISK
    #    TO SCAMCHECK RISK
    # =====================================

    abstract_risk = (
        risk.get("risk_level")
        or ""
    ).strip().lower()


    if (
        abstract_risk == "high"
        or risk.get("is_abuse_detected") is True
    ):

        scamcheck_risk = "HIGH RISK"


    elif (
        abstract_risk == "medium"
        or risk.get("is_disposable") is True
    ):

        scamcheck_risk = "POTENTIAL RISK"


    elif abstract_risk == "low":

        scamcheck_risk = "LOW"


    else:

        scamcheck_risk = "UNKNOWN"


    # =====================================
    # 8. BUILD SUSPICIOUS INDICATORS
    # =====================================

    suspicious_indicators = []


    if risk.get("is_abuse_detected") is True:

        suspicious_indicators.append(
            "Abuse has been detected for this number"
        )


    if risk.get("is_disposable") is True:

        suspicious_indicators.append(
            "Disposable phone number detected"
        )


    if validation.get("is_voip") is True:

        suspicious_indicators.append(
            "This number uses a VoIP service"
        )


    if validation.get("is_valid") is False:

        suspicious_indicators.append(
            "Phone number could not be validated"
        )


    # =====================================
    # 9. RETURN ABSTRACT RESULT
    # =====================================

    return {
        "source":
            "abstract_api",

        "phone_number":
            normalized_phone,

        "risk_level":
            scamcheck_risk,

        "suspicious_indicators":
            suspicious_indicators,

        "explanation":
            "No active ScamCheck database report was found. "
            "The number was checked using external phone intelligence.",

        "recommended_action":
            "If the caller requests money, credentials or OTPs, "
            "verify the request using an official contact channel.",

        "details": {

            "valid":
                validation.get("is_valid"),

            "line_status":
                validation.get("line_status"),

            "voip":
                validation.get("is_voip"),

            "carrier":
                carrier.get("name"),

            "line_type":
                carrier.get("line_type"),

            "country":
                location.get("country_name"),

            "api_risk":
                risk.get("risk_level"),

            "disposable":
                risk.get("is_disposable"),

            "abuse_detected":
                risk.get("is_abuse_detected")
        }
    }

@app.context_processor
def inject_psa_alerts():
    return {
        "psa_alerts": PSA_ALERTS
    }

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/check-phone', methods=['POST'])
@login_required
def check_phone():

    phone = request.form.get(
        'phone',
        ''
    ).strip()

    if not phone:

        flash(
            'Please enter a phone number.',
            'error'
        )

        return redirect(
            url_for('home')
        )


    # =====================================
    # ANALYSE PHONE NUMBER
    # =====================================

    analysis = analyse_phone_number(
        phone
    )


    # =====================================
    # BUILD RESULT FOR result.html
    # =====================================

    indicators = analysis.get(
        "suspicious_indicators",
        []
    )


    if indicators:

        indicators_text = "\n".join(
            f"• {indicator}"
            for indicator in indicators
        )

    else:

        indicators_text = (
            "• No specific suspicious indicators detected."
        )


    summary = (
        f"{analysis['explanation']}\n\n"
        f"Indicators:\n"
        f"{indicators_text}"
    )


    result = {
    'type': 'Phone Number',
    'value': analysis["phone_number"],
    'risk': analysis["risk_level"],
    'summary': summary,
    'recommendation': analysis["recommended_action"],

    # NEW
    'source': analysis.get("source"),
    'details': analysis.get("details", {})
}


    # =====================================
    # SAVE TO SCAN HISTORY
    # =====================================

    scan = ScanHistory(

        user_id=current_user.id,

        scan_type="phone",

        input_value=
            analysis["phone_number"],

        risk_level=
            analysis["risk_level"],

        result_summary=
            analysis["explanation"],

        suspicious_indicators=
            json.dumps(
                analysis.get(
                    "suspicious_indicators",
                    []
                )
            ),

        recommended_action=
            analysis["recommended_action"],

        blob_name=None
    )


    db.session.add(scan)

    db.session.commit()


    # =====================================
    # DISPLAY RESULT
    # =====================================

    return render_template(
        'result.html',
        result=result
    )


@app.route('/check-url', methods=['POST'])
@login_required
def check_url():

    submitted_url = request.form.get(
        'url',
        ''
    ).strip()

    if not submitted_url:
        flash(
            'Please enter a URL.',
            'error'
        )
        return redirect(
            url_for('home')
        )


    normalized_url = normalize_url(
        submitted_url
    )


    try:

        safe_browsing_result = (
            check_safe_browsing(
                normalized_url
            )
        )


        matches = safe_browsing_result.get(
            'matches',
            []
        )


        if matches:

            threat_types = []

            for match in matches:

                threat_type = match.get(
                    'threatType',
                    'UNKNOWN'
                )

                if threat_type not in threat_types:
                    threat_types.append(
                        threat_type
                    )


            readable_threats = [
                threat.replace('_', ' ').title()
                for threat in threat_types
            ]


            result = {
                'type': 'URL',
                'value': normalized_url,
                'risk': 'HIGH RISK',
                'summary': (
                    'Google Safe Browsing identified '
                    'this URL on an unsafe-resource list. '
                    'Detected category: '
                    + ', '.join(readable_threats)
                ),
                'recommendation': (
                    'Do not visit the website, enter '
                    'credentials, download files or '
                    'make payments through this URL.'
                )
            }


        else:

            result = {
                'type': 'URL',
                'value': normalized_url,
                'risk': 'LOW',
                'summary': (
                    'Google Safe Browsing did not '
                    'return a known threat match '
                    'for this URL.'
                ),
                'recommendation': (
                    'No known Safe Browsing match '
                    'was found, but this does not '
                    'guarantee that the website is safe. '
                    'Remain cautious with unexpected links.'
                )
            }


    except requests.RequestException as error:

        print(
            "Safe Browsing error:",
            error
        )

        result = {
            'type': 'URL',
            'value': normalized_url,
            'risk': 'UNKNOWN',
            'summary': (
                'ScamCheck could not contact '
                'Google Safe Browsing.'
            ),
            'recommendation': (
                'Do not assume the URL is safe. '
                'Please try again later.'
            )
        }


    if current_user.is_authenticated:
        scan = ScanHistory(
        user_id=current_user.id,
        scan_type="url",
        input_value=normalized_url,
        risk_level=result["risk"],
        result_summary=result["summary"],
        suspicious_indicators=json.dumps([]),
        recommended_action=result["recommendation"],
        blob_name=None
    )

    db.session.add(scan)
    db.session.commit()

    return render_template(
        'result.html',
        result=result
    )


@app.route('/check-screenshot', methods=['POST'])
@login_required
def check_screenshot():

    if 'file' not in request.files:
        flash('No screenshot was selected.', 'error')
        return redirect(url_for('home'))

    file = request.files['file']

    if file.filename == '':
        flash('No screenshot was selected.', 'error')
        return redirect(url_for('home'))

    if not allowed_file(file.filename):
        flash('Only PNG, JPG and JPEG files are allowed.', 'error')
        return redirect(url_for('home'))

    filename = secure_filename(file.filename)

    content_type = file.content_type

    file_bytes = file.read()

    # Upload screenshot to Azure Blob Storage
    blob_name = upload_to_blob(
        file_bytes=file_bytes,
        filename=filename,
        content_type=content_type
    )

    # Analyse screenshot using OpenAI
    ai_result = analyse_screenshot(
        image_bytes=file_bytes,
        content_type=content_type
    )

    # Convert suspicious indicators into a readable list
    indicators = "\n".join(
        f"• {indicator}"
        for indicator in ai_result["suspicious_indicators"]
    )

    # Build the assessment using the existing summary field
    summary = (
        f"Risk Level: {ai_result['risk_level']}\n\n"
        f"Suspicious Indicators:\n"
        f"{indicators}\n\n"
        f"Explanation:\n"
        f"{ai_result['explanation']}"
    )

    # Keep the same structure expected by result.html
    result = {
        'type': 'Screenshot',
        'value': filename,
        'risk': ai_result['risk_level'],
        'summary': summary,
        'recommendation': ai_result['recommended_action']
    }

    # Save screenshot scan to history
    if current_user.is_authenticated:
        scan = ScanHistory(
        user_id=current_user.id,
        scan_type="screenshot",
        input_value=filename,
        risk_level=ai_result["risk_level"],
        result_summary=ai_result["explanation"],
        suspicious_indicators=json.dumps(
            ai_result["suspicious_indicators"]
        ),
        recommended_action=ai_result["recommended_action"],
        blob_name=blob_name
    )

    db.session.add(scan)
    db.session.commit()

    return render_template(
        'result.html',
        result=result
    )


@app.route('/resources')
def resources():
    return render_template('resources.html')


@app.route("/history")
@login_required
def history():

    scans = (
        ScanHistory.query
        .filter_by(user_id=current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .all()
    )

    for scan in scans:
        try:
            scan.indicators_list = json.loads(
                scan.suspicious_indicators or "[]"
            )
        except json.JSONDecodeError:
            scan.indicators_list = []

    return render_template(
        "history.html",
        scans=scans
    )


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(
            username=username
        ).first()

        if user and check_password_hash(
            user.password_hash,
            password
        ):
            login_user(user)

            flash("Login successful.")
            return redirect(url_for("home"))

        flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:
            flash("Username already exists.")
            return redirect(url_for("register"))

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role="user"
        )

        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.")
    return redirect(url_for("home"))


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
