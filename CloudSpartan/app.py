from flask import Flask, render_template, request, redirect, url_for, session, flash
from aws_config_functions import list_config_rules, get_compliance_details, get_ec2_name_from_arn, get_rds_name_from_arn, get_s3_name_from_arn
from resource_types import RESOURCE_TYPES
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from io import BytesIO
import botocore.exceptions
import gzip
import boto3
import json
import datetime
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)


AWS_DEFAULT_REGION = 'us-east-1'

RESOURCE_HANDLERS = {
    'AWS::EC2::Instance': get_ec2_name_from_arn,
    'AWS::RDS::DBInstance': get_rds_name_from_arn,
    'AWS::S3::Bucket': get_s3_name_from_arn,
}

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    aws_account_number = db.Column(db.String(200), unique=True,)
    access_key = db.Column(db.String(200), unique=True,)
    secret_key = db.Column(db.String(200))
    detector_id = db.Column(db.String(80))

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(200))
    resource_type = db.Column(db.String(200))
    resource_arn = db.Column(db.String(300))
    resource_name = db.Column(db.String(300))
    compliance_type = db.Column(db.String(50))

class ResourceInventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    resource_arn = db.Column(db.String(300), unique=True)
    resource_type = db.Column(db.String(200))
    configuration = db.Column(db.Text)

class CloudTrailBucket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bucket_name = db.Column(db.String(200), nullable=False)
    path = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return """
            <html>
                <head>
                    <script>
                        alert('You need to be logged in to access this page.');
                        window.location.href = "{}";
                    </script>
                </head>
                <body></body>
            </html>
            """.format(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

###########################################
#                Register                 #
###########################################

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        aws_account_number = request.form.get('aws_account_number')
        access_key = request.form.get('access_key')
        secret_key = request.form.get('secret_key')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error = "Username already exists. Please choose a different one."
            return render_template('register.html', error=error)

        existing_key = User.query.filter_by(access_key=access_key).first()
        if existing_key:
            error = "This AWS access key has already been registered."
            return render_template('register.html', error=error)
        
        existing_account_number = User.query.filter_by(aws_account_number=aws_account_number).first()
        if existing_account_number:
            error = "This AWS Account has already been registered."
            return render_template('register.html', error=error)

        user = User(username=username, access_key=access_key, aws_account_number=aws_account_number, secret_key=secret_key)
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registered successfully.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            error = "An error occurred. Please try again."

    return render_template('register.html')

###########################################
#                 Login                   #
###########################################

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['access_key'] = user.access_key
            session['secret_key'] = user.secret_key

            store_aws_details_in_db(user.access_key, user.secret_key)

            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')

    return render_template('login.html')

###########################################
#                 Dashboard               #
###########################################

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    store_resource_inventory_in_db(session['access_key'], session['secret_key'])
    user = User.query.filter_by(id=session['user_id']).first()
    
    all_resources = ResourceInventory.query.all()
    
    resource_counts = {}
    for resource in all_resources:
        if resource.resource_type not in resource_counts:
            resource_counts[resource.resource_type] = 0
        resource_counts[resource.resource_type] += 1
    
    sorted_resource_counts = sorted(resource_counts.items(), key=lambda x: x[1], reverse=True)

    detector_id_exists = db.session.query(User.detector_id).filter(User.detector_id.isnot(None)).first()
    detector_id_status = "Connected" if detector_id_exists else "Not Connected"

    aws_account_exists = db.session.query(User.aws_account_number).filter(User.aws_account_number.isnot(None)).first()
    aws_account_status = "Connected" if aws_account_exists else "Not Connected"

    cloudtrail_bucket_exists = db.session.query(CloudTrailBucket.bucket_name, CloudTrailBucket.path).filter(
        CloudTrailBucket.bucket_name.isnot(None), CloudTrailBucket.path.isnot(None)).first()
    cloudtrail_status = "Connected" if cloudtrail_bucket_exists else "Not Connected"
    
    with open('severity.json', 'r') as file:
        severity_levels = json.load(file)

    non_compliant_findings = Finding.query.filter(Finding.compliance_type != 'COMPLIANT').all()

    severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}

    for finding in non_compliant_findings:
        severity = severity_levels.get(finding.rule_name, None)
        if severity:
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

    detector = user.detector_id
    if detector:
        findings = get_guardduty_findings(detector)
        findings_count = len(findings)
    else:
        findings_count = 0

    compliant_count = Finding.query.filter_by(compliance_type="COMPLIANT").count()
    non_compliant_count = Finding.query.filter_by(compliance_type="NON_COMPLIANT").count()

    return render_template('dashboard.html', resource_counts=sorted_resource_counts, username=user.username, detector_id_status=detector_id_status, cloudtrail_status=cloudtrail_status, aws_account_status=aws_account_status, severity_counts=severity_counts, findings_count=findings_count, compliant_count=compliant_count, non_compliant_count=non_compliant_count)

def store_resource_inventory_in_db(access_key, secret_key):
    client = boto3.client('config', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=AWS_DEFAULT_REGION)
    
    for rtype in RESOURCE_TYPES:
        try:
            resources = client.list_discovered_resources(resourceType=rtype)['resourceIdentifiers']
            
            for resource in resources:
                
                configuration = client.get_resource_config_history(
                    resourceType=resource['resourceType'],
                    resourceId=resource['resourceId'],
                    limit=1 
                )
                
                
                resource_arn = resource.get('resourceArn', None)
                
                inventory_item = ResourceInventory(
                    resource_arn=resource_arn,
                    resource_type=resource['resourceType'],
                    configuration=json.dumps(configuration['configurationItems'][0], cls=DateTimeEncoder)
                )
                
                db.session.add(inventory_item)
        except Exception as e:
            print(f"Error fetching resources for type {rtype}: {e}")
    
    db.session.commit()

def store_aws_details_in_db(access_key, secret_key):
    client = boto3.client('config', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=AWS_DEFAULT_REGION)
    rules = list_config_rules(client)

    for rule in rules:
        details = get_compliance_details(client, rule)

        for detail in details:
            resource_type = detail['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceType']
            resource_arn = detail['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
            compliance_type = detail['ComplianceType']

            handler = RESOURCE_HANDLERS.get(resource_type)
            if handler:
                resource_name = handler(resource_arn, AWS_DEFAULT_REGION, access_key, secret_key)
            else:
                resource_name = resource_arn.split(':')[-1].split('/')[-1]

            finding = Finding(rule_name=rule, resource_type=resource_type, resource_arn=resource_arn, resource_name=resource_name, compliance_type=compliance_type)
            db.session.add(finding)
    db.session.commit()

###########################################
#               CloudTrail                #
###########################################

def get_cloudtrail_logs_from_s3(bucket_name, log_prefix):
    
    s3 = boto3.client('s3', aws_access_key_id=session['access_key'], aws_secret_access_key=session['secret_key'])
    log_files = []
    try:
        objects = s3.list_objects_v2(Bucket=bucket_name, Prefix=log_prefix)
        if 'Contents' not in objects:
            print("No files found in the specified S3 bucket with the given prefix.")
            return log_files

        for obj in objects.get('Contents', []):
            
            if obj['Key'].endswith('/'):
                continue

            response = s3.get_object(Bucket=bucket_name, Key=obj['Key'])
            
            
            if obj['Key'].endswith('.gz'):
                with gzip.GzipFile(fileobj=BytesIO(response['Body'].read())) as gzipfile:
                    log_data = json.loads(gzipfile.read().decode('utf-8'))
            else:
                log_data = json.loads(response['Body'].read().decode('utf-8'))

            allowed_sources = ['iam.amazonaws.com', 'guardduty.amazonaws.com', 'cloudtrail.amazonaws.com']
            log_data['Records'] = [record for record in log_data['Records'] if record.get('eventSource') in allowed_sources]

            if log_data['Records']:
                log_files.append(log_data)

    except Exception as e:
        print(f"Error fetching CloudTrail logs from S3: {e}")
    return log_files

@app.route('/add_cloudtrail_bucket', methods=['POST'])
@login_required
def add_cloudtrail_bucket():
    bucket_name = request.form.get('bucket_name')
    path = request.form.get('path')
    new_bucket = CloudTrailBucket(bucket_name=bucket_name, path=path, user_id=session['user_id'])
    db.session.add(new_bucket)
    db.session.commit()
    return redirect(url_for('settings'))

@app.route('/delete_cloudtrail_bucket/<int:bucket_id>', methods=['POST'])
@login_required
def delete_cloudtrail_bucket(bucket_id):
    bucket = CloudTrailBucket.query.get(bucket_id)
    if bucket and bucket.user_id == session['user_id']:
        db.session.delete(bucket)
        db.session.commit()
    return redirect(url_for('settings'))

@app.route('/cloudtrail_logs', methods=['GET'])
@login_required
def cloudtrail_logs():
    user = User.query.filter_by(id=session['user_id']).first()

    user_buckets = CloudTrailBucket.query.filter_by(user_id=session['user_id']).all()
    if not user_buckets:
        return """
            <html>
                <head>
                    <script>
                        alert('No CloudTrail bucket found for this user. Please set it up in the settings.');
                        window.location.href = "{}";
                    </script>
                </head>
                <body></body>
            </html>
            """.format(url_for('settings'))

    logs = []
    for bucket in user_buckets:
        logs.extend(get_cloudtrail_logs_from_s3(bucket.bucket_name, bucket.path))

    return render_template('cloudtrail_logs.html', logs=logs, username=user.username)

###########################################
#               GuardDuty                 #
###########################################

@app.route('/update_detector_id', methods=['POST'])
@login_required
def update_detector_id():
    detector_id = request.form.get('detector_id')
    user = User.query.filter_by(id=session['user_id']).first()
    user.detector_id = detector_id
    db.session.commit()
    flash('Detector ID updated successfully!', 'success')
    return redirect(url_for('settings'))

@app.route('/delete_guardduty_detector', methods=['POST'])
@login_required
def delete_guardduty_detector():
    user = User.query.filter_by(id=session['user_id']).first()
    
    if user.detector_id:
        user.detector_id = None
        db.session.commit()
        flash('Detector ID deleted successfully!', 'success')
    else:
        flash('No Detector ID to delete!', 'warning')
    
    return redirect(url_for('settings'))

def get_guardduty_findings(detector):
    client = boto3.client('guardduty', aws_access_key_id=session['access_key'], aws_secret_access_key=session['secret_key'], region_name='us-east-1')

    response = client.list_findings(
        DetectorId=detector,
    )

    findings = []

    response = client.list_findings(DetectorId=detector)

    findings_ids = response.get('FindingIds', [])
    if findings_ids:
        findings_response = client.get_findings(DetectorId=detector, FindingIds=findings_ids)
        all_findings = findings_response.get('Findings', [])

        findings = [f for f in all_findings if not f.get('Archived', False)]

    return findings

@app.route('/threatdetection')
@login_required
def guardduty_alerts():
    user = User.query.filter_by(id=session['user_id']).first()

    detector = user.detector_id
    if not detector:
        return """
            <html>
                <head>
                    <script>
                        alert('No Detector ID found for this user. Please set it up in the settings.');
                        window.location.href = "{}";
                    </script>
                </head>
                <body></body>
            </html>
            """.format(url_for('settings'))

    findings = get_guardduty_findings(detector)

    return render_template('threatdetection.html', findings=findings, username=user.username)

###########################################
#                 Report                  #
###########################################

@app.route('/report', methods=['GET'])
@login_required
def generate_report():
    user = User.query.filter_by(id=session['user_id']).first()
    findings = Finding.query.all()
    non_compliant_findings = [f for f in findings if f.compliance_type == "NON_COMPLIANT"]

    with open('description.json', 'r') as file:
        description = json.load(file)
    with open('remediation_steps.json', 'r') as file:
        remediation_steps = json.load(file)
    with open('severity.json', 'r') as file:
        severity = json.load(file)

    return render_template('report.html', len=len, findings=non_compliant_findings, description=description, remediation_steps=remediation_steps, severity=severity, username=user.username)

@app.route('/settings', methods=['GET'])
@login_required
def settings():
    user = User.query.filter_by(id=session['user_id']).first()
    bucket = CloudTrailBucket.query.filter_by(user_id=session['user_id']).all()
    bucket_exists = CloudTrailBucket.query.filter_by(user_id=user.id).first() is not None
    detector_exists = bool(user.detector_id)
    return render_template('settings.html', aws_account_number=user.aws_account_number, access_key=user.access_key, username=user.username, bucket=bucket, bucket_exists=bucket_exists, detector_exists=detector_exists, detectors=[user])   

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    Finding.query.delete()
    ResourceInventory.query.delete()
    db.session.commit()
    session.clear()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)

with app.app_context():
    db.create_all()