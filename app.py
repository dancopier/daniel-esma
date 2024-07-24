from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
import sqlite3, pytz
import hashlib
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired
from flask_socketio import SocketIO, emit  # Import SocketIO
from flask import after_this_request
import functools
from datetime import datetime
import sqlite3
import os
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
app = Flask(__name__)
socketio = SocketIO(app)

app.secret_key = 'diary558231'


@app.route('/')
def home():
    return render_template('index.html')


def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def get_user_password(username):
    conn = sqlite3.connect('diary.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    password = cursor.fetchone()
    conn.close()
    if password:
        return password[0]
    return None


@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        stored_password = get_user_password(username)
        if stored_password and stored_password == hashed_password:
            conn = sqlite3.connect('diary.db')
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM users WHERE username=?", (username,))
            user_id = cursor.fetchone()[0]  # Retrieve the user_id
            conn.close()
            
            session['logged_in'] = True
            session['username'] = username
            session['user_id'] = user_id  # Store the user_id in the session

            return redirect(url_for('user_dashboard'))

        else:
            # Invalid credentials
            return render_template('index.html')

@app.route('/user/logout', methods=['POST'])
def logout():
    if request.method == 'POST':
        # Only logout if the POST method is used, which will ensure it's a deliberate action
        session.pop('username', None)
        flash('You have been logged out.', 'success')
        return redirect(url_for('index'))
    else:
        # If accessed via GET, redirect to the dashboard or profile page
        flash('Logout cancelled.', 'info')
        return redirect(url_for('user_dashboard', username=session.get('username')))

#####################################################################################################


@app.route('/user/register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Check if username exists
        conn = sqlite3.connect('diary.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            alert_message = "Username already exists! Please choose another."
            return render_template('success.html', alert_message=alert_message)

        # If username is available, proceed with registration
        hashed_password = hash_password(password)
        cursor.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                       (username, hashed_password, email))
        conn.commit()
        conn.close()

        alert_message = "You have successfully registered."
        return render_template('success.html', alert_message=alert_message)

    return render_template('index.html')

##################################################################################################
@app.route('/create_diary', methods=['GET', 'POST'])
def create_diary():
    if 'username' not in session:
        return redirect('/user/login')

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        username = session['username'] 

        current_datetime = datetime.now()
        date = current_datetime.strftime('%Y-%m-%d')
        time = current_datetime.strftime('%H:%M:%S')

        conn = sqlite3.connect('diary.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user_id = cursor.fetchone()[0]
        conn.close()

        conn = sqlite3.connect('diary.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO diary_entries (user_id, title, content, date, time) VALUES (?, ?, ?, ?, ?)',
                       (user_id, title, content, date, time))
        conn.commit()
        conn.close()

        return redirect('/user_dashboard')

    return render_template('diary_entry.html')


@app.route('/user_dashboard')
def user_dashboard():
    if 'username' not in session:
        return redirect('/user/login')

    username = session['username']
    conn = sqlite3.connect('diary.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT diary_entries.id, diary_entries.title, diary_entries.content, 
        diary_entries.date, diary_entries.time
        FROM diary_entries 
        INNER JOIN users ON diary_entries.user_id = users.id 
        WHERE users.username = ?
    ''', (username,))
    entries = cursor.fetchall()
    conn.close()

    return render_template('user_dashboard.html', entries=entries)


################################################################################################
@app.route('/user/home')
def user_home():
    return render_template('user_home.html')
######################################################################################################


@app.route('/view_diary/<int:entry_id>')
def view_diary(entry_id):
    if 'username' not in session or 'user_id' not in session:
        return redirect('/user/login')

    user_id = session['user_id']
    conn = sqlite3.connect('diary.db')
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM diary_entries WHERE id = ? AND user_id = ?', (entry_id, user_id))
    entry = cursor.fetchone()
    conn.close()

    if not entry:
        return "Diary entry not found or unauthorized access"

    return render_template('view_user_diary.html', entry=entry)

####################################################################################################


@app.route('/diary/view')
def diary_view():
    if 'username' not in session:
        # Redirect to login if user is not logged in
        return redirect('/user/login')

    username = session['username']
    conn = sqlite3.connect('diary.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT diary_entries.id, diary_entries.title, diary_entries.content, 
        diary_entries.date, diary_entries.time
        FROM diary_entries 
        INNER JOIN users ON diary_entries.user_id = users.id 
        WHERE users.username = ?
    ''', (username,))
    entries = cursor.fetchall()
    conn.close()

    return render_template('diary_list.html', entries=entries)
##################################################################################################

@app.route('/edit_entry/<int:entry_id>', methods=['GET', 'POST'])
def edit_entry(entry_id):
    if 'username' not in session or 'user_id' not in session:
        return redirect('/user/login') 

    if request.method == 'GET':

        username = session['username']
        user_id = session['user_id']

        conn = sqlite3.connect('diary.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM diary_entries WHERE id = ? AND user_id = ?', (entry_id, user_id))
        entry = cursor.fetchone()
        conn.close()

        if not entry:
            return "Diary entry not found or unauthorized access"

        return render_template('edit_entry.html', entry=entry) 

    elif request.method == 'POST':

        title = request.form['title']
        content = request.form['content']
        date = request.form['date']
        time = request.form['time']

        conn = sqlite3.connect('diary.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE diary_entries SET title=?, content=?, date=?, time=? WHERE id=? AND user_id=?',
                       (title, content, date, time, entry_id, session['user_id']))
        conn.commit()
        conn.close()

        return redirect(f'/view_diary/{entry_id}')

@app.route('/update_entry', methods=['POST'])
def update_entry():
    if request.method == 'POST':
        updated_entries = request.json.get('entries')
        
        if updated_entries:
            conn = sqlite3.connect('diary.db')
            cursor = conn.cursor()
            
            try:
                for entry in updated_entries:
                    entry_id = entry.get('entryId')
                    field_name = entry.get('fieldName')
                    updated_content = entry.get('updatedContent')

                    cursor.execute(f"UPDATE diary_entries SET {field_name}=? WHERE id=?", (updated_content, entry_id))

                conn.commit()
                return jsonify({'message': 'Entries updated successfully'})
            except Exception as e:
                conn.rollback()
                return jsonify({'error': str(e)}), 500
            finally:
                conn.close()

    return jsonify({'error': 'Invalid request'}), 400

@app.route('/delete_entry/<int:entry_id>', methods=['POST'])
def delete_entry(entry_id):
    if 'username' not in session or 'user_id' not in session:
        return redirect('/user/login')  # Redirect to login if user is not logged in

    # Delete the diary entry associated with the specified ID and the logged-in user
    username = session['username']
    user_id = session['user_id']

    conn = sqlite3.connect('diary.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM diary_entries WHERE id = ? AND user_id = ?', (entry_id, user_id))
    conn.commit()
    conn.close()

    return redirect('/user_dashboard')

####################################################################################################
UPLOAD_FOLDER = 'static/profile_pics'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    conn = sqlite3.connect('diary.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return "Welcome to the index page!"

@app.route('/profile/<username>')
def profile(username):
    if not username:
        flash('Username not provided', 'error')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user is None:
        flash('User not found', 'error')
        return redirect(url_for('index'))

    return render_template('profile.html', user=user)


@app.route('/upload_profile_pic', methods=['POST'])
def upload_profile_pic():
    if 'profile_pic' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('profile', username=session.get('username')))

    file = request.files['profile_pic']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('profile', username=session.get('username')))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET profile_pic = ? WHERE username = ?', (filename, session.get('username')))
        conn.commit()
        conn.close()

        flash('Profile picture updated successfully!', 'success')
        return redirect(url_for('profile', username=session.get('username')))

    flash('Allowed file types are png, jpg, jpeg, gif', 'error')
    return redirect(url_for('profile', username=session.get('username')))



############################################################################################
def get_admin_password(username):
    conn = sqlite3.connect('diary.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM admins WHERE username=?", (username,))
    password = cursor.fetchone()
    conn.close()
    if password:
        return password[0]
    return None

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        stored_password = get_admin_password(username)
        if stored_password and stored_password == hashed_password:
          
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            return "Invalid username or password. Please try again."
    return render_template('admin_login.html')
link_status = True

@app.route('/admin/logout')
def admin_logout():
    session.clear()


    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_logged_in' in session and session['admin_logged_in']:
        username = session['admin_username']
        return render_template('admin_dashboard.html', username=username, link_status=link_status)
    else:
        return redirect(url_for('admin_login'))

# Add a decorator to prevent caching for the /admin/dashboard route
@app.after_request
def add_no_cache(response):
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response
####################################################################################################
DB_FILE = "diary.db"
def check_admin():
    if 'admin_logged_in' in session and session['admin_logged_in']:
        return True
    return False

# Decorator to check if an admin is logged in
def admin_required(func):
    @functools.wraps(func)
    def decorated_function(*args, **kwargs):
        if not check_admin():
            return redirect(url_for('admin_login'))
        return func(*args, **kwargs)
    return decorated_function

# Apply the decorator to admin-only routes
@app.route('/admin_create_announcement')
@admin_required
def admin_create_announcement():
    return render_template('admin_create_announcement.html')

@app.route('/admin_view_announcements')
@admin_required
def admin_view_announcements():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Announcements")
    Announcements = cursor.fetchall()
    conn.close()
    return render_template('admin_view_announcements.html', notices=Announcements)

# Add cache control for admin routes
@app.after_request
def add_no_cache(response):
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response




@app.route('/admin_submit_announcement', methods=['GET', 'POST'])
def submit_announcement():
    if not check_admin():
        return redirect(url_for('admin_login'))
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # Extract data from the form submission
        title = request.form.get('title')
        content = request.form.get('content')
        publish_date = request.form.get('publish_date')
        cursor.execute("INSERT INTO Announcements (title, content, publish_date) VALUES (?, ?, ?)",
                       (title, content, publish_date))
        conn.commit()
        conn.close()
        # Pass refresh=True to trigger a refresh
        return render_template('admin_dashboard.html', refresh=True)
    except Exception as e:
        return f'Error: {str(e)}'

@app.route('/admin_delete_announcement', methods=['GET', 'POST'])
def delete_announcement():
    if not check_admin():
        return redirect(url_for('admin_login'))
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # Extract the announcement ID from the request
        delete_id = request.form.get('delete_id')
        # Delete the announcement from the database
        cursor.execute("DELETE FROM Announcements WHERE id = ?", (delete_id,))
        # Commit the changes and close the connection
        conn.commit()
        conn.close()
        return 'Announcement deleted successfully!'
    except Exception as e:
        return f'Error: {str(e)}'

@app.route('/admin_edit_announcement', methods=['POST'])
def edit_announcement():
    if not check_admin():
        return redirect(url_for('admin_login'))
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # Extract data from the request
        edit_id = request.form.get('edit_id')
        edited_title = request.form.get('title')
        edited_content = request.form.get('content')
        edited_publish_date = request.form.get('publish_date')
        # Update the announcement in the database
        cursor.execute("UPDATE Announcements SET title = ?, content = ?, publish_date = ? WHERE id = ?",
                       (edited_title, edited_content, edited_publish_date, edit_id))
        # Commit the changes and close the connection
        conn.commit()
        conn.close()
        return 'Announcement updated successfully!'
    except Exception as e:
        return f'Error: {str(e)}'

# Decorator to check if an admin is logged in
def admin_required(func):
    @functools.wraps(func)
    def decorated_function(*args, **kwargs):
        if not check_admin():
            return redirect(url_for('admin_login'))
        return func(*args, **kwargs)
    return decorated_function

@app.route('/view_users', methods=['GET'])
@admin_required  # Apply admin authentication to the route
def view_users():
    conn = sqlite3.connect('diary.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users")
    users_data = cursor.fetchall()
    conn.close()
    return render_template('view_users.html', users=users_data)

# Add cache control for this route
@app.after_request
def add_no_cache(response):
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response


@app.route('/admin_home')
@admin_required  # Apply admin authentication to the route
def admin_home():
    return render_template('admin_home.html', link_status=link_status)

# Add cache control for this route
@app.after_request
def add_no_cache(response):
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        conn = sqlite3.connect('diary.db')
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO admins (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
        return "Admin Registration successful! Thank you."
    return render_template('admin_register.html')

@app.route('/post_entry', methods=['POST'])
def post_entry():
    try:
        entry_data = request.get_json()

        # Get the current date and time
        current_datetime = datetime.now()
        current_date = current_datetime.strftime('%Y-%m-%d')
        current_time = current_datetime.strftime('%H:%M:%S')

        # Connect to the SQLite database
        conn = sqlite3.connect('diary.db')
        cursor = conn.cursor()

        # Insert the received diary entry into the 'public_diary_entries' table
        cursor.execute('''
            INSERT INTO public_diary_entries (title, content, date, time)
            VALUES (?, ?, ?, ?)
        ''', (entry_data['title'], entry_data['content'], current_date, current_time))

        # Commit changes and close the connection
        conn.commit()
        conn.close()

        return jsonify({'message': 'Entry posted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
##################################################################################################
@app.route('/admin_create_database', methods=['GET'])
@admin_required  # Apply admin authentication to the route
def admin_create_database():
    return render_template('create_database.html')

# Add cache control for this route
@app.after_request
def add_no_cache(response):
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@app.route('/delete_database', methods=['POST'])
@admin_required  # Apply admin authentication to the route
def delete_database():
    try:
        conn = sqlite3.connect('diary.db')
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        tables_to_exclude = ['admins', 'sqlite_sequence']  # Exclude specified tables
        for table in tables:
            if table[0] not in tables_to_exclude:
                cursor.execute(f"DROP TABLE {table[0]};")
        conn.commit()
        conn.close()
        return render_template('admin_dashboard.html')
    except Exception as e:
        return f'Error deleting database: {str(e)}'

# Add cache control for this route
@app.after_request
def add_no_cache(response):
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@app.route('/delete_databases')
def delete_databases():
    return render_template('delete_database.html')
######################################################################################################
def init_database():
    conn = sqlite3.connect('diary.db')
    cursor = conn.cursor()
    
    # Create users table with profile_pic column
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            profile_pic TEXT  -- Added column for profile picture
        )
    ''')
    
    # Create admins table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # Create diary_entries table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS diary_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,  -- Foreign key referencing the users table
            title TEXT,
            content TEXT,
            date TEXT,
            time TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Create public_diary_entries table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS public_diary_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT,
            date TEXT,
            time TEXT
        )
    ''')
    
    # Create posted_diary_comments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posted_diary_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_id INTEGER,
            username TEXT,
            comment TEXT,
            posted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (entry_id) REFERENCES public_diary_entries(id)
        )
    ''')

    conn.commit()
    conn.close()

@app.route('/initialize_database', methods=['GET'])
def initialize_database():
    init_database()
    return redirect('/admin/dashboard')

@app.route('/vote_settings')
def vote_settings():
    return render_template('vote_settings.html')

# Route to view the public diary entries
@app.route('/view_public_diary_entries')
def view_public_diary_entries():
    conn = sqlite3.connect('diary.db')
    cursor = conn.cursor()

    cursor.execute("SELECT id, title, content, date, time FROM public_diary_entries")
    view_public_diary_entries = cursor.fetchall()

    entries_with_comments = []

    for entry in view_public_diary_entries:
        cursor.execute("SELECT username, comment, posted_at FROM posted_diary_comments WHERE entry_id = ?", (entry[0],))
        comments = cursor.fetchall()
        entry_with_comments = {
            'id': entry[0],
            'title': entry[1],
            'content': entry[2],
            'date': entry[3],
            'time': entry[4],
            'comments': [{'username': comment[0], 'content': comment[1], 'posted_at': comment[2]} for comment in comments]
        }
        entries_with_comments.append(entry_with_comments)

    conn.close()

    return render_template('view_public_diary_entries.html', entries=entries_with_comments)


@app.route('/add_comment/<int:entry_id>', methods=['POST'])
def add_comment(entry_id):
    comment = request.form.get('comment')
    username = request.form.get('username')

    if not username:
        username = 'Anonymous User'

    if comment:
        conn = sqlite3.connect('diary.db')
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO posted_diary_comments (entry_id, username, comment)
            VALUES (?, ?, ?)
        ''', (entry_id, username, comment))
        

        conn.commit()
        conn.close()

    return redirect(url_for('user_dashboard'))

@app.route('/come_backsoon')
def come_backsoon():
    return render_template('come_backsoon.html')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
