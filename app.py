import os
import secrets
import string
from datetime import datetime

from flask import (
    Flask, render_template, redirect, url_for, request,
    flash, jsonify, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# App Configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-fallback-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------------------------------------------------------------------------
# Database Models
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    token_balance = db.Column(db.Integer, default=0)
    access_key = db.Column(db.String(32), nullable=True, unique=True)
    unlocked_assets = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Tool(db.Model):
    __tablename__ = 'tools'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    affiliate_url = db.Column(db.String(512))
    token_reward = db.Column(db.Integer, default=50)
    category = db.Column(db.String(80))
    icon_emoji = db.Column(db.String(10))


class Verification(db.Model):
    __tablename__ = 'verifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tool_id = db.Column(db.Integer, db.ForeignKey('tools.id'), nullable=False)
    order_id = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), default='pending')
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('verifications', lazy=True))
    tool = db.relationship('Tool', backref=db.backref('verifications', lazy=True))

# ---------------------------------------------------------------------------
# Flask-Login User Loader
# ---------------------------------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------------------------------------------------------------------
# Database Seeder
# ---------------------------------------------------------------------------

def seed_tools():
    if Tool.query.first() is None:
        tools = [
            Tool(
                name='Runway ML',
                category='AI Animation',
                icon_emoji='🎬',
                token_reward=80,
                affiliate_url='https://runwayml.com',
                description='Industry-leading generative AI suite for video creation, image synthesis, and motion design. Transform text and images into cinematic video clips with unparalleled quality.'
            ),
            Tool(
                name='Pika Labs',
                category='AI Animation',
                icon_emoji='⚡',
                token_reward=60,
                affiliate_url='https://pika.art',
                description='Next-generation AI video platform that turns your ideas into stunning motion content. Create, edit, and animate videos with simple text prompts.'
            ),
            Tool(
                name='ElevenLabs',
                category='AI Audio',
                icon_emoji='🎙️',
                token_reward=50,
                affiliate_url='https://elevenlabs.io',
                description='State-of-the-art AI voice synthesis and cloning technology. Generate ultra-realistic voiceovers, dub content into 29+ languages, and design custom AI voices.'
            ),
            Tool(
                name='Leonardo AI',
                category='Asset Generator',
                icon_emoji='🖼️',
                token_reward=70,
                affiliate_url='https://leonardo.ai',
                description='Production-quality AI art and asset generation platform. Create game assets, concept art, and design elements with fine-tuned models and advanced controls.'
            ),
            Tool(
                name='CapCut Pro',
                category='Video Editing',
                icon_emoji='✂️',
                token_reward=40,
                affiliate_url='https://capcut.com',
                description='Professional all-in-one video editor with AI-powered features. Auto-captions, background removal, color correction, and hundreds of trending templates.'
            ),
            Tool(
                name='Topaz Video AI',
                category='Video Editing',
                icon_emoji='🔬',
                token_reward=90,
                affiliate_url='https://topazlabs.com/topaz-video-ai',
                description='Enterprise-grade AI video enhancement suite. Upscale footage to 8K, recover details, stabilize shaky video, and interpolate frames with neural network precision.'
            ),
        ]
        db.session.add_all(tools)
        db.session.commit()

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    tools = Tool.query.all()
    return render_template('index.html', tools=tools)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            return redirect(url_for('register'))

        admin_password = os.environ.get('ADMIN_PASSWORD', '')
        is_admin = (password == admin_password and admin_password != '')

        user = User(username=username, email=email, is_admin=is_admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash('Account created successfully! Welcome aboard.', 'success')
        return redirect(url_for('vault'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('vault'))

        flash('Invalid email or password.', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/verify', methods=['GET', 'POST'])
@login_required
def verify():
    tools = Tool.query.all()

    if request.method == 'POST':
        tool_id = request.form.get('tool_id', type=int)
        order_id = request.form.get('order_id', '').strip()

        if not tool_id or not order_id:
            flash('Please select a tool and enter your order/receipt ID.', 'error')
            return redirect(url_for('verify'))

        existing = Verification.query.filter_by(
            user_id=current_user.id,
            tool_id=tool_id,
            order_id=order_id
        ).first()

        if existing:
            flash('You have already submitted this receipt for verification.', 'error')
            return redirect(url_for('verify'))

        verification = Verification(
            user_id=current_user.id,
            tool_id=tool_id,
            order_id=order_id,
            status='pending'
        )
        db.session.add(verification)
        db.session.commit()

        flash('Verification submitted! Your request is now in the admin queue.', 'success')
        return redirect(url_for('vault'))

    return render_template('verify.html', tools=tools)


@app.route('/vault')
@login_required
def vault():
    return render_template('vault.html')


@app.route('/vault/redeem/key', methods=['POST'])
@login_required
def redeem_key():
    if current_user.token_balance < 100:
        flash('Insufficient tokens. You need at least 100 tokens to redeem a Chrome Extension Key.', 'error')
        return redirect(url_for('vault'))

    if current_user.access_key:
        flash('You have already redeemed a Chrome Extension Key.', 'error')
        return redirect(url_for('vault'))

    charset = string.ascii_letters + string.digits
    key = ''
    for _ in range(16):
        key += secrets.choice(charset)

    current_user.access_key = key
    current_user.token_balance -= 100
    db.session.commit()

    flash(f'Chrome Extension Key generated: {key}', 'success')
    return redirect(url_for('vault'))


@app.route('/vault/redeem/assets', methods=['POST'])
@login_required
def redeem_assets():
    if current_user.token_balance < 50:
        flash('Insufficient tokens. You need at least 50 tokens to unlock the Cinematic Asset Pack.', 'error')
        return redirect(url_for('vault'))

    if current_user.unlocked_assets:
        flash('You have already unlocked the Cinematic Video Asset Pack.', 'error')
        return redirect(url_for('vault'))

    current_user.unlocked_assets = True
    current_user.token_balance -= 50
    db.session.commit()

    flash('Cinematic Video Asset Pack unlocked! Check your email for download details.', 'success')
    return redirect(url_for('vault'))


@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)

    pending = Verification.query.filter_by(status='pending').order_by(
        Verification.submitted_at.desc()
    ).all()

    all_verifications = Verification.query.order_by(
        Verification.submitted_at.desc()
    ).all()

    return render_template('admin.html', pending=pending, all_verifications=all_verifications)


@app.route('/admin/approve/<int:verification_id>', methods=['POST'])
@login_required
def approve_verification(verification_id):
    if not current_user.is_admin:
        abort(403)

    verification = Verification.query.get_or_404(verification_id)
    verification.status = 'approved'

    tool = Tool.query.get(verification.tool_id)
    user = User.query.get(verification.user_id)

    if tool and user:
        user.token_balance += tool.token_reward

    db.session.commit()
    flash(f'Verification #{verification_id} approved. {tool.token_reward} tokens credited.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/reject/<int:verification_id>', methods=['POST'])
@login_required
def reject_verification(verification_id):
    if not current_user.is_admin:
        abort(403)

    verification = Verification.query.get_or_404(verification_id)
    verification.status = 'rejected'
    db.session.commit()

    flash(f'Verification #{verification_id} rejected.', 'error')
    return redirect(url_for('admin'))


@app.route('/api/verify-extension-key')
def verify_extension_key():
    key = request.args.get('key', '').strip()
    if not key:
        return jsonify({'status': 'error', 'message': 'No key provided'}), 400

    user = User.query.filter_by(access_key=key).first()
    if user:
        return jsonify({
            'status': 'valid',
            'username': user.username,
            'unlocked_assets': user.unlocked_assets
        })
    return jsonify({'status': 'invalid', 'message': 'Key not found'}), 404

# ---------------------------------------------------------------------------
# App Entry Point
# ---------------------------------------------------------------------------

with app.app_context():
    db.create_all()
    seed_tools()

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=False
    )
