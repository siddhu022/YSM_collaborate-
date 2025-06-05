from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'EchoNote'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clip.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    contact = db.Column(db.String(15), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    role = db.Column(db.String(20), default='employee')
    
    def __repr__(self):
        return f'<User {self.email}>'
    
class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_url = db.Column(db.String(255), nullable=False)
    note = db.Column(db.Text, nullable=False)
    newspaper = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    impact = db.Column(db.String(50), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id')) 
    tags = db.Column(db.String(200)) 
    author = db.Column(db.String(100))
    approval_status = db.Column(db.String(20))
    comments = db.relationship('Comment', backref='news', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    news_id = db.Column(db.Integer, db.ForeignKey('news.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(100)) 

    def __repr__(self):
        return f'<News {self.newspaper} - {self.department}>'

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        contact = request.form.get('contact')
        password = request.form.get('password')

        if not contact or not password:
            flash('Please enter your email/phone and password.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter(
            (User.email == contact) | (User.contact == contact)
        ).first()
        
        if user and check_password_hash(user.password, password):
            session['user_role'] = 'emp'  
            session['logged_in'] = True
            session['session_user'] = user.email
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        elif contact == 'sid02@gmail.com' and password == 'Siddhesh@02':
            session['user_role'] = 'emp'
            session['logged_in'] = True
            session['session_user'] = 'sid02@gmail.com'
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        elif contact == 'sid02@gmail.com' and password != 'Siddhesh@02':
            flash('Incorrect password. Please try again.', 'danger')
        elif contact == 'admin@gmail.com' and password == 'admin123':
            session['user_role'] = 'admin'
            session['logged_in'] = True
            session['session_user'] = 'admin@gmail.com'
            flash('Admin login successful!', 'success')
            return redirect(url_for('dashboard'))
        elif contact == 'admin@gmail.com' and password != 'admin123':
            flash('Incorrect password. Please try again.', 'danger')
        else:
            flash('Invalid credentials. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('conf_password')
        contact = request.form.get('contact')
        department = request.form.get('department')
        gender = request.form.get('gender')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('registration'))

        flash('Registration successful!', 'success')
        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password=hashed_password, contact=contact, department=department, gender=gender)

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('registration.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        flash('Message sent successfully!', 'success')
        return redirect(url_for('contact'))

    return render_template('contact.html')

@app.route('/dashboard')
def dashboard():
    if 'user_role' not in session:
        flash("Unauthorized access")
        return redirect(url_for('login'))

    section = request.args.get('section', 'news')
    selected_department = request.args.get('select')
    selected_date = request.args.get('date')
    selected_impact = request.args.get('impact')
    selected_tag = request.args.get('tag')

    query = News.query

    if selected_department and selected_department != "All":
        query = query.filter(News.department == selected_department)

    if selected_date and selected_date != "All":
        query = query.filter(News.date == selected_date)

    if selected_impact and selected_impact != "All":
        query = query.filter(News.impact == selected_impact)

    if selected_tag and selected_tag != "All":
        query = query.filter(News.tags.ilike(f'%{selected_tag}%'))

    news_items = query.order_by(News.date.desc()).all()

    departments = [d[0] for d in db.session.query(News.department).distinct().all()]
    dates = [d[0] for d in db.session.query(News.date).distinct().all()]
    impacts = [i[0] for i in db.session.query(News.impact).distinct().all()]
    all_tags = db.session.query(News.tags).distinct().all()
    tag_list = sorted({tag.strip() for tags in all_tags if tags[0] for tag in tags[0].split(',')})

    users = User.query.all() if section == 'manage_users' and session.get('user_role') == 'admin' else []

    return render_template(
        'dashboard.html',
        news_items=news_items,
        section=section,
        users=users,
        departments=departments,
        dates=dates,
        impacts=impacts,
        tag_list=tag_list,
        selected_department=selected_department,
        selected_date=selected_date,
        selected_impact=selected_impact,
        selected_tag=selected_tag
    )

@app.route('/my_upload')
def my_upload():
    if 'user_role' not in session:
        flash("Unauthorized access")
        return redirect(url_for('dashboard'))

    user_email = session.get('session_user')
    my_news_items = News.query.filter_by(author=user_email).order_by(News.date.desc()).all()
    return render_template('my_upload.html', news_items=my_news_items)

@app.route('/news_detail/<int:news_id>')
def news_details(news_id):
    if 'user_role' not in session:
        flash("Unauthorized access")
        return redirect(url_for('dashboard'))

    news = News.query.get_or_404(news_id)
    return render_template('news_detail.html', news=news)

@app.route('/delete_news/<int:news_id>', methods=['POST'])
def delete_news(news_id):
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))

    news = News.query.get_or_404(news_id)

    try:
        db.session.delete(news)
        db.session.commit()
        flash('News item deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting news item.', 'danger')
        print(e)

    return redirect(url_for('dashboard'))

@app.route('/image_upload')
def image_upload():
    if 'user_role' not in session:
        flash("Unauthorized access")
        return redirect(url_for('dashboard'))

    return render_template('image_upload.html')

@app.route('/add_comment/<int:news_id>', methods=['POST'])
def add_comment(news_id):
    if 'user_role' not in session:
        flash("Unauthorized access")
        return redirect(url_for('login'))

    content = request.form.get('content')
    author = session.get('session_user') or 'Guest'

    if content:
        comment = Comment(news_id=news_id, content=content, author=author)
        db.session.add(comment)
        db.session.commit()
        flash('Comment added!', 'success')

    return redirect(url_for('news_details', news_id=news_id))

@app.route('/manage_users')
def manage_users():
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))

    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if session.get('user_role') != 'admin':
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.email = request.form['email']
        user.role = request.form['role']
        db.session.commit()
        return redirect(url_for('dashboard', section='manage_users'))
    
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if session.get('user_role') != 'admin':
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('dashboard', section='manage_users'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

news_items = []

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/submit_transaction', methods=['POST'])
def submit_transaction():
    if 'user_role' not in session:
        flash("Unauthorized access")
        return redirect(url_for('login'))

    image = request.files.get('image')
    note = request.form.get('note')
    newspaper = request.form.get('newspaper')
    department = request.form.get('department')
    impact = request.form.get('impact')
    date = request.form.get('date')

    if not (image and allowed_file(image.filename) and note and newspaper and department and impact and date):
        flash("All fields including a valid image are required.")
        return redirect(url_for('image_upload'))

    filename = secure_filename(image.filename)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image.save(filepath)

    '''news_items.append({
        'image_url': '/' + filepath.replace('\\', '/'),
        'note': note,
        'newspaper': newspaper,
        'department': department,
        'impact': impact,
        'date': date
    })'''
    
    new_news = News(
        image_url='/' + filepath.replace('\\', '/'),
        note=note,
        newspaper=newspaper,
        department=department,
        impact=impact,
        date=date,
        author=session.get('session_user'),
        tags=request.form.get('tags'),
        approval_status='Pending'
    )
    db.session.add(new_news)
    db.session.commit()

    flash("News uploaded successfully!")
    return redirect(url_for('dashboard'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/home')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
    app.run(debug=True)
