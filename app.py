from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from datetime import datetime, date
import hashlib
from flask_login import current_user, login_required
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
import json
from sqlalchemy import Text


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chainharbor.db'
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    full_name = db.Column(db.String(100), nullable=True)
    farm_name = db.Column(db.String(100), nullable=True)
    location = db.Column(db.String(100), nullable=True)
    contact_info = db.Column(db.String(20), nullable=True)
    batches = db.relationship('Batch', backref='farmer', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def generate_nft(self, batch_number):
        unique_string = f"{self.id}-{datetime.utcnow()}-{batch_number}"
        nft = hashlib.sha256(unique_string.encode()).hexdigest()
        return nft

    def __repr__(self):
        return f'<User {self.username}>'

class Batch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    batch_number = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    certifications = db.Column(db.String(100), nullable=True)
    quality_checks = db.Column(db.Text, nullable=True)
    origin = db.Column(db.String(100), nullable=True)
    harvest_date = db.Column(db.DateTime, nullable=True)
    images = db.Column(Text, nullable=True)
    additional_notes = db.Column(db.Text, nullable=True)
    nft = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    transaction_hash = db.Column(db.String(64), nullable=True)
    previous_hash = db.Column(db.String(64), nullable=True)
    block_index = db.Column(db.Integer, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Blockchain:
    def __init__(self):
        self.chain = []

    def new_block(self, data):
        # Check if 'harvest_date' is a string before attempting to convert
        if isinstance(data['harvest_date'], str):
            data['harvest_date'] = datetime.strptime(data['harvest_date'], '%Y-%m-%d')

        data['timestamp'] = str(data['timestamp'])
        block = {'index': len(self.chain) + 1, 'data': data}
        self.chain.append(block)
        return block

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1] if self.chain else None

blockchain = Blockchain()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        new_user = User(username=username, role=role)
        new_user.set_password(password)

        # Include role-specific details
        if role == 'farmer':
            new_user.full_name = request.form['full_name']
            new_user.farm_name = request.form['farm_name']
            new_user.location = request.form['location']
            new_user.contact_info = request.form['contact_info']

        # Add user to the database
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)

        if user:
            if user.role == 'farmer':
                # Handle farmer dashboard
                return render_template('farmer_dashboard.html', user=user)
            elif user.role == 'distributor':
                # Handle distributor dashboard
                return render_template('distributor_dashboard.html', user=user)
            elif user.role == 'retailer':
                # Handle retailer dashboard
                return render_template('retailer_dashboard.html', user=user)
            elif user.role == 'customer':
                # Handle customer dashboard
                return render_template('customer_dashboard.html', user=user)

    return redirect(url_for('login'))


@app.route('/farmer_dashboard')
@login_required
def farmer_dashboard():
    batches = current_user.batches
    return render_template('farmer_dashboard.html', batches=batches)

# Define new route for registering a new batch
# Define new route for registering a new batch
@app.route('/farmer_dashboard/register_batch', methods=['POST'])
@login_required
def register_batch():
    # Get data from the form
    product_name = request.form['product_name']
    quantity = int(request.form['quantity'])

    # Additional Details
    description = request.form.get('description', '')
    certifications = request.form.get('certifications', '')
    quality_checks = request.form.get('quality_checks', '')
    origin = request.form.get('origin', '')
    harvest_date = request.form.get('harvest_date', '')
    images_json = json.dumps(request.form.getlist('images'))
    additional_notes = request.form.get('additional_notes', '')

    # Simulate creating an NFT (Non-Fungible Token)
    nft = f"NFT-{len(current_user.batches) + 1}"

    # Generate a unique batch number based on the number of existing batches
    batch_number = f"Batch-{len(current_user.batches) + 1}"

    # Simulate updating the blockchain with the new batch
    blockchain.new_block({
        'product_name': product_name,
        'quantity': quantity,
        'description': description,
        'certifications': certifications,
        'quality_checks': quality_checks,
        'origin': origin,
        'harvest_date': harvest_date,
        'images': images_json,
        'additional_notes': additional_notes,
        'nft': nft,
        'timestamp': datetime.utcnow(),
        'transaction_hash': 'simulated_transaction_hash',  # Update with actual blockchain integration
        'previous_hash': blockchain.hash(blockchain.chain[-1]) if blockchain.chain else None,
        'block_index': len(blockchain.chain) + 1,
    })

    # Update the registered batches for the current user
    new_batch = Batch(
    product_name=product_name,
    quantity=quantity,
    batch_number=batch_number,  # Use the dynamically generated batch number
    nft=nft,
    timestamp=datetime.utcnow(),
    transaction_hash='simulated_transaction_hash',  # Update with actual blockchain integration
    block_index=len(blockchain.chain),
    description=description,
    certifications=certifications,
    quality_checks=quality_checks,
    origin=origin,
    harvest_date=datetime.utcnow().date(),
    images=images_json,
    additional_notes=additional_notes,
    farmer=current_user  # Associate the batch with the current farmer
)

    db.session.add(new_batch)
    db.session.commit()

    return redirect('/farmer_dashboard')  # Use url_for to generate URLs dynamically

if __name__ == '__main__':
    app.run(debug=True)
