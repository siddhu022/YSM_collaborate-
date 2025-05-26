from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = 'EchoNote'

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        contact = request.form.get('contact')
        password = request.form.get('password')

        if contact == 'sid02@gmail.com' and password == 'Siddhesh@02':
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
        return redirect(url_for('registration'))

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

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/dashboard')
def dashboard():
    if 'user_role' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', news_items=news_items)

@app.route('/clipping')
def clipping():
    return render_template('img_detail.html')

@app.route('/image_upload')
def image_upload():
    return render_template('image_upload.html')

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
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Unauthorized access")
        return redirect(url_for('dashboard'))

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

    news_items.append({
        'image_url': '/' + filepath.replace('\\', '/'),
        'note': note,
        'newspaper': newspaper,
        'department': department,
        'impact': impact,
        'date': date
    })

    flash("News uploaded successfully!")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
