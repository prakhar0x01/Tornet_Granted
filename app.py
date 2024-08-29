from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime
from datetime import  date
from flask_sqlalchemy import SQLAlchemy
from concurrent.futures import ThreadPoolExecutor
import OpenSSL.crypto
import smtplib
from email.mime.text import MIMEText
import threading
from threading import Thread
from queue import Queue
import queue
import string
from bs4 import BeautifulSoup
import json
from reportlab.pdfgen import canvas
import hashlib
import requests
import random
import re
import urllib
from io import BytesIO


app = Flask(__name__)

proxy = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

# Configure SQLAlchemy
app.config['SECRET_KEY'] = 'cHJha2hhcjB4MDE6YWRtaW4='
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# User model for authentication
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    api_key = db.Column(db.String(64), unique=True, nullable=False)
    secret_access_key = db.Column(db.String(64),unique=True,nullable=True)
    def check_password(self, password):
        password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return password == self.password

with app.app_context():
        db.create_all()

# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Unauthorize page
@app.route('/unauthorize',methods=['GET'])
def unauthorize():
    if request.method == 'GET':
        return render_template('unauthorize.html')


# Default Page is Dashboard
@app.route('/',methods=['GET'])
def default():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    if request.method == 'GET':
        if current_user:
            return redirect(url_for('dashboard'))
        
        return redirect(url_for('login'))


# Login page route
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        username = request.form['username'] # admin
        password = request.form['password'] # admin

        if username and password:
            with app.app_context():
                user = User.query.filter_by(username=username).first()

                if user is not None and user.check_password(password):
                    login_user(user)
                    return redirect(url_for('dashboard'))

            #    message = "Invalid Credentials."

    return render_template('login.html')
##############################################

def get_scheduled_tasks():
    """
    Retrieves a list of all scheduled tasks.
    """
    tasks = []

    if not scheduler:
        return None
    else:    
        for job in scheduler.get_jobs():
            trigger = job.trigger
            if isinstance(trigger, CronTrigger):
                # Format cron schedule
                cron_schedule = '{0} {1} {2} {3} {4}'.format(
                    trigger.minute, trigger.hour, trigger.day_of_week, trigger.day, trigger.month
                )
            else:
                # Assume date trigger
                cron_schedule = job.trigger.run_date.strftime('%Y-%m-%d %H:%M')

            tasks.append({
                'task_route': job.args[0],  # Update to use func_name instead of func_args[0]
                'data': job.args[1],  # Update to use args[1] for task data
                'email': job.args[2],  # Update to use args[2] for email address
                'cron_schedule': cron_schedule
            })
        return tasks

###############################################
# Dashboard.
@app.route('/dashboard')
@login_required
def dashboard():
    if request.method == 'POST':
        return redirect(url_for('login'))
    
    tasks = get_scheduled_tasks()
    api_key = current_user.api_key
    secret_access_key = current_user.secret_access_key

    if tasks != None:
        return render_template('dashboard.html',tasks=tasks, api_key = api_key, secret_access_key = secret_access_key, username=current_user.username)
    else:
        return render_template('dashboard.html', api_key = api_key, secret_access_key = secret_access_key, username = current_user.username)


# Users
@app.route('/users', methods=['GET'])
@login_required
def users():
    if request.method == 'GET' and current_user.username == 'admin':
        users = User.query.all()
        return render_template('users.html', users=users)
    else:
        return redirect(url_for('unauthorize'))
    

# Adding a user via admin
@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST' and current_user.username == 'admin':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            message = 'Please enter all fields'
            return render_template('add_user.html',error = message)
        
        if User.query.filter_by(username=username).first():
            message = "User with that username already exists."
            return render_template("add_user.html",error=message)
        
        api_key = 'TORNET'+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))
        secret_access_key = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(40))
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        user = User(username=username,password=hashed_password,api_key=api_key,secret_access_key=secret_access_key)

        db.session.add(user)
        db.session.commit()
        # Show success message
        message = 'User added successfully!'
        return render_template('add_user.html',success = message)
    
    #else:    
    #    return redirect(url_for('unauthorize'))
    
    if request.method == 'GET' and current_user.username != 'admin':
        return redirect(url_for('unauthorize'))

    return render_template('add_user.html')

## Update User Password
@app.route('/update_password', methods=['POST','GET'])
@login_required
def update_password():
    if request.method == 'GET' and current_user.username != 'admin':
        return redirect(url_for('unauthorize'))

    if request.method == 'POST' and current_user.username == 'admin':
        username = request.form.get('username')
        password = request.form.get('password')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            existing_user.password = hashed_password
            db.session.commit()

            message = f"Password for {username} updated successfully...!!"
            return render_template("update_user.html", success=message)
        else:
            message = f"User with username {username} does not exist."
            return render_template("update_user.html", error=message)

    return render_template("update_user.html")

## Delete User
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.username != 'admin':
        return redirect(url_for('unauthorize'))

    user = User.query.get(user_id)

    if user:
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for('users'))
    else:
        return render_template('users.html', error="User not found.")
    
################################################################## EXPORTING URLS ################################################################

def export_links(file_path, export_format):
    now = datetime.now()

    filename = f"onion-links+{now.strftime('%H_%M_%S')}.{export_format.lower()}"

    with open(file_path, "r") as f:
        extracted_links = [line.strip() for line in f.readlines()]

    if export_format == "txt":
        # Convert list to string with newlines and timestamps
        file_content = "\n".join([f"{link}" for link in extracted_links])
        response = make_response(file_content.encode("utf-8"))
        response.headers["Content-Type"] = "text/plain"
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return response

    elif export_format == "json":
        # Convert list to JSON with timestamps and indentation
        data = {"data": [{"link": link} for link in extracted_links], "date": f"{date.today()}", "time": f"{now.strftime('%H:%M:%S')}","total": f"{len(extracted_links)}"}
        file_content = json.dumps(data, indent=4, sort_keys=True).encode("utf-8")
        response = make_response(file_content)
        response.headers["Content-Type"] = "application/json"
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return response

    elif export_format == "pdf":
# Create
        output = BytesIO()
        pdf = canvas.Canvas(output, pagesize=(8.5 * 72, 11 * 72))
        lines_per_page = int((700 - 25) / 15)  # Lines per page

        page_number = 1
        y_position = 700 - 25  # Starting position
        link_index = 0  # Current link index

        # Title with page number and timestamp
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(30, 770, f"Discovered Links - Page {page_number} ({now.strftime('%Y-%m-%d %H:%M:%S')})")

        # Headers and line styles
        pdf.setFont("Helvetica", 12)
        pdf.drawString(30, 740, f"Total Unique Links: {len(extracted_links)}")
        pdf.line(30, 735, 550, 735)

        while link_index < len(extracted_links):
            # Add links to current page
            for i in range(lines_per_page):
                if link_index < len(extracted_links):
                    pdf.drawString(40, y_position, f"• {extracted_links[link_index]}")
                    link_index += 1
                    y_position -= 15
                else:
                    break

            # Check if page limit is reached and start new page
            if y_position < 25:
                page_number += 1
                pdf.showPage()
                y_position = 700 - 25
                pdf.setFont("Helvetica-Bold", 16)
                pdf.drawString(30, 770, f"Extracted Links - Page {page_number}")
                pdf.setFont("Helvetica", 12)

        # Close the PDF document and set headers
        pdf.save()
        response = make_response(output.getvalue())
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return response

    else:
        raise ValueError(f"Invalid export format: {export_format}")


################################################################### ENUMNERATE URLs ##########################################################################
def extract_onion_links(content):
    # USING A SIMPLE REGEX to extract the possible .onion links.
    regexquery = r"\w+\.onion"
    mineddata = set()
    for match in re.finditer(regexquery, content):
        mineddata.add(match.group(0))

    return list(mineddata)

def get_fetch_urls(url, urls_queue):
    ##  CHANGING USER-AGENT IN EVERY TURN, MAY BE PROTECTED BY ANY BLOCKS BY WAF or HOST. YOU CAN ADD MORE IF YOU WANT.
    ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19577",
            "Mozilla/5.0 (X11) AppleWebKit/62.41 (KHTML, like Gecko) Edge/17.10859 Safari/452.6",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2656.18 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36",
            "Mozilla/5.0 (Linux; U; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.27 Safari/525.13",
            "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_5_8; zh-cn) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"]

    ua = random.choice(ua_list)
    headers = {'User-Agent': ua}

    try:
        response = requests.get(url, proxies=proxy, headers=headers)
        soup = BeautifulSoup(response.content, 'lxml')

        # Extract .onion links from the content
        content = soup.text
        onion_links = extract_onion_links(content)

        for link in onion_links:
            urls_queue.put(link.strip())

    except Exception as e:
        print(f"Error fetching URL: {url}")
        # IF YOU WANT TO SEE THE ERROR, OTHERWISE DON'T UNCOMMENT IT.
#        print(e)

####################################################################### FINDING LINKS ########################################################

@app.route('/enumerate/discover', methods=['GET', 'POST'])
#@login_required # Commented the login required cuz, it throws error in scheduling tasks.
def discover():
    threads = []
    urls_queue = queue.Queue()

#    if not current_user.is_authenticated:
#        return redirect(url_for('unauthorize'))

    if request.method == 'GET':
        api_key = current_user.api_key
        secret_access_key = current_user.secret_access_key
        return render_template('discover.html', api_key = api_key, secret_access_key = secret_access_key)

    export_format = request.form.get('export_format')

    if export_format is not None:
        return export_links('internal/discover/export_links.txt', export_format)


# Implemented the search engines based , but it is not a good idea to thow out such thing on the frontend, 
# hence decided to remove the search engine based searching.    

#    search_engine = request.form.get('search_engine') --> DEAR, FRONTEND DEV DO NOT UNCOMMENT THIS LINE
    keywords = request.form.get('keywords')
    api_key = request.form.get('api_key')
    secret_access_key = request.form.get('secret_access_key')
    
    if request.method == 'POST' and (keywords!=None or (User.query.filter_by(api_key=api_key).first() and User.query.filter_by(secret_access_key=secret_access_key))):
#        keywords = request.form.get('keywords')
#    if request.method == 'POST' and keywords!=None:
        level = request.form.get('level')
        keywords_list = keywords.split(',')
        for keyword in keywords_list:

            # So my approach on searching is that, we can research popular and amount based search engines & then fetch the links directly from them.
            # Based on the results we created this logic require less time to discover large amount of URLs.

            ### THE MORE HIGHER LEVEL YOU CHOOSE THE MORE AMOUNT IT WILL TAKE TO RESPOND & LARGE AMOUNT OF STUFF(Onion links)
            if level == '5':
                # Ahmia
                get_fetch_urls(f"http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search?q={keyword.strip()}",urls_queue)
                # GDark
                get_fetch_urls(f"http://zb2jtkhnbvhkya3d46twv3g7lkobi4s62tjffqmafjibixk6pmq75did.onion/gdark/search.php?query={keyword.strip()}&search=1&results=10000",urls_queue)
                # Deep Search
                get_fetch_urls(f"http://search7tdrcvri22rieiwgi5g46qnwsesvnubqav2xakhezv4hjzkkad.onion/result.php?search={keyword.strip()}",urls_queue)
                # Onion Scanner
                get_fetch_urls(f"http://pvhwsb7a3d2oq73xtr3pzvmrruvswyqgkyahcb7dmbbfftr4qtsmvjid.onion/?sort_type=search&search_result={keyword.strip()}",urls_queue)

                # Chooses 85+ because, TORGLE output the maximum amount of links i..e 88 pages of links(each include 10 onion links)
                # Started from 1, cuz page numbers can never be zero.

                # IN EVERY LEVEL BASED CONDITION, EVERY URL YOU SEE IN THE BELOW ARRAY `urls_to_fetch` they are doing GET based searching but included multiple pages.
                # Hence, I use for loop to interate the page to certain level.
                for count in range(1,20):
                    urls_to_fetch = [
                        f"http://u5lyidiw4lpkonoctpqzxgyk6xop7w7w3oho4dzzsi272rwnjhyx7ayd.onion/page/{count}/?s={keyword.strip()}",
                        f"http://venusoseaqnafjvzfmrcpcq6g47rhd7sa6nmzvaa4bj5rp6nm5jl7gad.onion/Search?Query={keyword.strip()}&Page={count}",
                        f"http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={keyword.strip()}&page={count}",
                        f"http://e27slbec2ykiyo26gfuovaehuzsydffbit5nlxid53kigw3pvz6uosqd.onion/?q={keyword.strip()}&p={count}",
                        f"http://iy3544gmoeclh5de6gez2256v6pjh4omhpqdh2wpeeppjtvqmjhkfwad.onion/torgle/?page={count}&query={keyword.strip()}&thumbs=on"
                        f"http://findtorroveq5wdnipkaojfpqulxnkhblymc7aramjzajcvpptd4rjqd.onion/search?q={keyword.strip()}&page={count}",
                        f"http://krakenai2gmgwwqyo7bcklv2lzcvhe7cxzzva2xpygyax5f33oqnxpad.onion/search/?q={keyword.strip()}&PAGEN_1={count}&SIZEN_1=10"
                        f"http://5qqrlc7hw3tsgokkqifb33p3mrlpnleka2bjg7n46vih2synghb6ycid.onion/index.php?a=search&q={keyword.strip()}&page={count}&f=1"
                        ]
                    
                    for url in urls_to_fetch:
                        thread = threading.Thread(target=get_fetch_urls, args=(url, urls_queue))
                        threads.append(thread)
                        thread.start()

                    
            elif level == '4':
                # Ahmia
                get_fetch_urls(f"http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search?q={keyword.strip()}",urls_queue)
                # GDark
                get_fetch_urls(f"http://zb2jtkhnbvhkya3d46twv3g7lkobi4s62tjffqmafjibixk6pmq75did.onion/gdark/search.php?query={keyword.strip()}&search=1&results=10000",urls_queue)
                # Deep Search
                get_fetch_urls(f"http://search7tdrcvri22rieiwgi5g46qnwsesvnubqav2xakhezv4hjzkkad.onion/result.php?search={keyword.strip()}",urls_queue)

 
                ## There is some issue happening when going more than 20, may be the large amount of concurrent requests.
                ## If you can find the solution of it, then feel free to collaborate @prakhar0x01 --> github
                for count in range(1,20):
                    urls_to_fetch = [
                        f"http://u5lyidiw4lpkonoctpqzxgyk6xop7w7w3oho4dzzsi272rwnjhyx7ayd.onion/page/{count}/?s={keyword.strip()}",
                        f"http://venusoseaqnafjvzfmrcpcq6g47rhd7sa6nmzvaa4bj5rp6nm5jl7gad.onion/Search?Query={keyword.strip()}&Page={count}",
                        f"http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={keyword.strip()}&page={count}",
                        f"http://findtorroveq5wdnipkaojfpqulxnkhblymc7aramjzajcvpptd4rjqd.onion/search?q={keyword.strip()}&page={count}",
                        f"http://krakenai2gmgwwqyo7bcklv2lzcvhe7cxzzva2xpygyax5f33oqnxpad.onion/search/?q={keyword.strip()}&PAGEN_1={count}&SIZEN_1=10"
                        f"http://5qqrlc7hw3tsgokkqifb33p3mrlpnleka2bjg7n46vih2synghb6ycid.onion/index.php?a=search&q={keyword.strip()}&page={count}&f=1"
                        ]
                    for url in urls_to_fetch:
                        thread = threading.Thread(target=get_fetch_urls, args=(url, urls_queue))
                        threads.append(thread)
                        thread.start()


            elif level == '3':
               # Ahmia
                get_fetch_urls(f"http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search?q={keyword.strip()}",urls_queue)
                # Onion Scanner
                get_fetch_urls(f"http://pvhwsb7a3d2oq73xtr3pzvmrruvswyqgkyahcb7dmbbfftr4qtsmvjid.onion/?sort_type=search&search_result={keyword.strip()}",urls_queue)

                for count in range(1,20):
                    urls_to_fetch = [
                        f"http://u5lyidiw4lpkonoctpqzxgyk6xop7w7w3oho4dzzsi272rwnjhyx7ayd.onion/page/{count}/?s={keyword.strip()}",
                        f"http://venusoseaqnafjvzfmrcpcq6g47rhd7sa6nmzvaa4bj5rp6nm5jl7gad.onion/Search?Query={keyword.strip()}&Page={count}",
                        f"http://krakenai2gmgwwqyo7bcklv2lzcvhe7cxzzva2xpygyax5f33oqnxpad.onion/search/?q={keyword.strip()}&PAGEN_1={count}&SIZEN_1=10"
                        f"http://5qqrlc7hw3tsgokkqifb33p3mrlpnleka2bjg7n46vih2synghb6ycid.onion/index.php?a=search&q={keyword.strip()}&page={count}&f=1"
                        ]
                    
                    for url in urls_to_fetch:
                        thread = threading.Thread(target=get_fetch_urls, args=(url, urls_queue))
                        threads.append(thread)
                        thread.start()


            elif level == '2':
               # Ahmia
                get_fetch_urls(f"http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search?q={keyword.strip()}",urls_queue)
                # Deep Search
                get_fetch_urls(f"http://search7tdrcvri22rieiwgi5g46qnwsesvnubqav2xakhezv4hjzkkad.onion/result.php?search={keyword.strip()}",urls_queue)
      
                for count in range(1,11):
#-----              ## I KNOW THIS IS NOT THE BEST EFFECTIVE APPROACH TO THIS TASKS, THE TIME CONSUMED CAN BE MINIMIZED,
                    ## BUT FOR 4-5 DAYS, THIS SEEMS TO BE EFFECTIVE APPROACH.
                    urls_to_fetch = [f"http://findtorroveq5wdnipkaojfpqulxnkhblymc7aramjzajcvpptd4rjqd.onion/search?q={keyword.strip()}&page={count}",
                                     f"http://5qqrlc7hw3tsgokkqifb33p3mrlpnleka2bjg7n46vih2synghb6ycid.onion/index.php?a=search&q={keyword.strip()}&page={count}&f=1"
                                     ]
                    
                    for url in urls_to_fetch:
#                        print(urls_queue)
                        thread = threading.Thread(target=get_fetch_urls, args=(url, urls_queue))
                        threads.append(thread)
                        thread.start()
                            

            elif level == '1':
               # Ahmia
                get_fetch_urls(f"http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search?q={keyword.strip()}",urls_queue)
                # Deep Search
                get_fetch_urls(f"http://search7tdrcvri22rieiwgi5g46qnwsesvnubqav2xakhezv4hjzkkad.onion/result.php?search={keyword.strip()}",urls_queue)
                
            else:
                message = "Invalid Input..!!"
                return render_template('discover.html', error=message)    
            
#----
    # When all threads were done their tasks
    for thread in threads:
        thread.join()


    # Collect the all the onion links and filter the unique from them.
    urls = list()
#   urls = set()       #We can also use set
# 
    with open("internal/discover/export_links.txt", "w") as f:     
        while not urls_queue.empty():
            link = urls_queue.get()
            if link not in urls:    # To avoid Duplicates
    #            urls.add(link)     # Adding element in a set.
                urls.append(link)
                f.write(f"{link}\n")
            # IF YOU WANT TO SHOW THE OUTPUT IN YOUR TERMINAL.
#            print(link)
        f.close()

    total = f"Found total : {len(urls)} Unique links"
    return render_template('discover.html', api_key = api_key, secret_access_key = secret_access_key, urls = urls, total = total)

########################################################### SCHEDULE TASKS ################################################################################

# Available tasks with their routes and data formats
tasks = {
    '/enumerate/discover': {
        'data_format': {'keywords': str, 'level': int},
        'description': 'Discovers onion links based on keywords and depth level.'
    },
    '/monitor/website': {
        'data_format': {'url': str, 'interval': int},
        'description': 'Monitors changes on a website at a specified interval.'
    }
}

# Background scheduler
scheduler = None

@app.route('/schedule', methods=['GET', 'POST'])
def schedule_task():
    global scheduler

    if request.method == 'GET':
        return render_template('schedule.html', tasks=tasks.items())

    task_route = request.form.get('task_route')
    email = request.form.get('email')
    scheduled_time_str = request.form.get('scheduled_time')

    try:
        # Validate task selection
        if task_route not in tasks:
            raise ValueError('Invalid task selection.')

        # Parse scheduled time
        scheduled_time = datetime.strptime(scheduled_time_str, '%Y-%m-%dT%H:%M')

        # Create scheduler if not already running
        if not scheduler:
            scheduler = BackgroundScheduler()
            app.config['scheduler'] = scheduler
            scheduler.start()

        # Extract task data
        task_data = get_task_data(task_route, request.form)
#        task_data.update({'api_key': current_user.api_key, 'secret_access_key': current_user.secret_access_key})

        # Schedule the task
        scheduler.add_job(
            func=schedule_task_wrapper,
            args=[task_route, task_data, email, current_user.api_key, current_user.secret_access_key],
            trigger='date',
            run_date=scheduled_time
        )

        return render_template('schedule.html', success=f'Task scheduled successfully for: {scheduled_time}')
    
    except Exception as e:
        return render_template('schedule.html',error = f'An Error Occured : {e}')

def get_task_data(task_route, form_data):
    """
    Extracts and validates task-specific data from the form.
    """
    task_data = {}
    for field, data_type in tasks[task_route]['data_format'].items():
        try:
            task_data[field] = data_type(form_data.get(field))

        except Exception as e:
            raise ValueError(f'Invalid data for field "{field}": {e}')
        
    return task_data

def schedule_task_wrapper(task_route, task_data, email, api_key, secret_access_key):
    """
    Wrapper function for scheduled tasks.
    """
    task_data.update({'api_key': api_key, 'secret_access_key': secret_access_key})
#    print(api_key,secret_access_key) # If you want to show the parsed keys


    if task_route == '/enumerate/discover':
        route = f"http://127.0.0.1:5000{task_route}"

        response = requests.post(route, data=task_data)

        if response.status_code:
            regexquery = r"\w+\.onion"
            links = re.findall(regexquery, response.text)
            onion_links = set(links)
            send_email_notification(email, task_route, onion_links)
        else:
            raise Exception(f'Task failed with HTTP status code {response.status_code}')
    else:
        return 'Invalid Task Route'

def send_email_notification(email, task_route, task_result):
    """
    Sends email notification about task completion.

    This is a basic example using smtplib. You may need to adjust it depending on your email service and desired format.
    """
    try:
        # Replace with your actual email server address and port
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()

        # Replace with your sender email address and Password

        with open('config.txt', 'r') as file:
    # Initialize variables to store sender email and password
            sender_email = None
            password = None
    
    # Iterate through each line in the file
            for line in file:
        # Split the line by colon
                parts = line.strip().split(':')
        
        # Check if the line contains sender email
                if len(parts) == 2 and parts[0].strip() == 'sender_email':
                    sender_email = parts[1].strip()
        
        # Check if the line contains password
                elif len(parts) == 2 and parts[0].strip() == 'password':
                    password = parts[1].strip()
        file.close()           
                    
        server.login(sender_email, password)

        # Prepare email message
        message_content = f'Task "{task_route}" completed successfully!\n\nResult:\n'
        for element in task_result:
            message_content += f'\n- {element}'

        message = MIMEText(message_content)
        message['Subject'] = f'[TORNET GRANTED]: Task `{task_route}` Completed Successfully'
        message['From'] = sender_email
        message['To'] = email

        # Send email
        server.sendmail(sender_email, [email], message.as_string())
        server.quit()
    except Exception as e:
        print(f'Error sending email notification: {e}')

    print(f'Sending email notification to {email} for task "{task_route}"')

###################################################### VALIDATE ##################################################################
import subprocess
# Define number of worker threads
num_workers = 10


@app.route("/enumerate/validate", methods=["GET", "POST"])
@login_required
def validate():
    """
    Handles both GET and POST requests.
    """
    export_format = request.form.get('export_format')

    if export_format is not None:
        return export_links('internal/validate/export_links.txt', export_format)

    if request.method == "POST":
        # User submitted a URL
        url = request.form.get("url").strip()

        # Create a queue for results
        results_queue = Queue()

        # Define worker function
        def worker(url, results_queue):
            try:
                # Build curl command
                command = f"curl -x socks5h://localhost:9050 {url} -I -X HEAD"

                # Execute curl command and capture output
                result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # Check for successful execution
                if result.returncode == 0:
                    # Extract headers
                    headers = result.stdout.decode().split("\n")
                    headers_dict = {k: v.strip() for k, v in [line.split(": ") for line in headers if ": " in line]}

                    # Put headers dictionary in queue
                    results_queue.put((url, headers_dict))
                else:
                    # Put error message in queue
                    results_queue.put((url, None))
            except Exception as e:
                return None

        # Start worker threads
        threads = []
        for _ in range(num_workers):
            thread = threading.Thread(target=worker, args=(url, results_queue))
            thread.start()
            threads.append(thread)

        # Wait for all threads to finish
        for thread in threads:
            thread.join()

        # Collect results from queue
        all_headers = {}
        while not results_queue.empty():
            url, headers = results_queue.get()
            if headers:
                all_headers.update({url: headers})

        # Render results template
        return render_template("validate.html", url=url, headers=all_headers)
    else:
        # Display empty results page
        return render_template("validate.html", url="", headers={})

############################################################# UPLOAD FILE #################################################

@app.route("/validate_file", methods=["GET", "POST"])
@login_required
def upload_file():
    if request.method == "POST":
        # Get uploaded file
        uploaded_file = request.files["file"]

        # Check if file is valid
        if uploaded_file.filename != "" and allowed_file(uploaded_file.filename):
            # Save file
            file_path = f"internal/uploads/{uploaded_file.filename}"
            uploaded_file.save(file_path)

            # Process each line in the file
            with open(file_path, "r") as f:
                all_urls = [line.strip() for line in f]

            # Check URL status
            results = []
            for url in all_urls:
                status = check_url_status(url)
                results.append({"url": url, "status": status})

            # Count active and dead URLs
            active_urls = sum(url["status"] == "Active" for url in results)
            dead_urls = len(results) - active_urls
            #print(results)

            return render_template("validate.html", message="File processed successfully!",
                                   active_urls=active_urls, dead_urls=dead_urls, results=results)
        else:
            # Render error message
            return render_template("validate.html", message="Invalid file format.")
    else:
        # Render upload form
        return redirect(url_for('validate'))

# Define allowed file extensions
ALLOWED_EXTENSIONS = {"txt"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def check_url_status(url):
    url = f"http://{url}"
    try:
        response = requests.head(url, timeout=10, proxies=proxy)
        #print(response)
        if response.status_code == 200 or response.status_code == 302 or response.status_code == 301 or response.status_code == 401 or response.status_code == 403 :
        # Extract .onion links from the content
            
            onion_links = extract_onion_links(content)
            return f"Active (Status Code: {response.status_code})"
        else:
            return f"Dead (Status Code: {response.status_code})"
    except requests.RequestException as e:
        return "Dead (Error: Connection Error)"

##################################################### RENDER  #############################################################################

@app.route("/enumerate/render", methods=["GET", "POST"])
@login_required
def render():
    if request.method == "POST":
        # Get onion URL from form
        onion_url = request.form["onion_url"]

        if 'http' not in onion_url:
            return render_template('render.html',error = "Invalid URL: Try using `http://`")

        try:
            # Fetch the URL content using Tor session
            response = requests.get(onion_url,proxies=proxy)

            # Get DOM content
            content = response.content.decode()
            raw_content = content.replace('<', '&lt;').replace('>', '&gt;')
            dom_content = BeautifulSoup(raw_content, 'html.parser').prettify()

            """
            with open(f"templates/view.html", "w") as f:
                f.write(f"<pre><code>{dom_content}</code></pre>")
            f.close()
            """
            #render_here = "<iframe src='/render/view' name='rendered_frame' style='width:100%;height:500px;'></iframe>"

            #Render the extracted DOM as HTML content
            #return redirect(url_for("render"))
            return render_template("render.html", onion_url = onion_url, dom_content = f'<pre><code class="html">{dom_content}</code></pre>')
        except Exception as e:
            # Render error message
            return redirect(url_for("render"))
    else:
        # Render form for user to input onion URL
        return render_template("render.html")

"""
@app.route("/enumerate/render/view",methods=['GET'])
def view():
    return render_template('view.html')    
"""
############################################################################################################################

#########################################################  Details  ########################################################
results = []
wordlist_file = "internal/wordlists.txt"
seen_urls = set()
results_lock = threading.Lock()

ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19577",
            "Mozilla/5.0 (X11) AppleWebKit/62.41 (KHTML, like Gecko) Edge/17.10859 Safari/452.6",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2656.18 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36",
            "Mozilla/5.0 (Linux; U; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.27 Safari/525.13",
            "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
            "Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_5_8; zh-cn) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27"]

ua = random.choice(ua_list)
headers = {'User-Agent': ua}


regex_patterns = {
    'EMAILS': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'CRYPTO_ADDRESS': r'(?<![\w\d])[13][a-km-zA-HJ-NP-Z0-9]{26,33}(?![\w\d])',  # Crypto Addresses
    'API_KEYS': r'(?:access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey|RSA)\b\W*\w+',  # API Keys and Access Tokens
    'USERNAME_PASSWORD': r'\b(?:password|username|pass|user|passwd)\b\W*\w+',  # Usernames and Passwords
    'DOMAIN_NAMES': r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|org|net|edu|gov|mil|io))\b',  # Domain Names
    'BASEPATHS': r'(?<="|\')http?://'+'f{url}'+'[^\s"\']+'  # Basepaths, Directories, Files
}

def fetch_javascript_urls(response_text, base_url):
    javascript_urls = re.findall(r'<script.*?src=[\'"](.*?\.js)', response_text)
    return [urllib.parse.urljoin(base_url, js_url) if not js_url.startswith('http') else js_url for js_url in javascript_urls]

def process_response(url, response_text):
    matches = {}
    for pattern_name, pattern in regex_patterns.items():
        matches[pattern_name] = set(re.findall(pattern, response_text))
    return matches

def worker(url, word):
    fuzzed_url = f"{url}/{word}"

    if fuzzed_url in seen_urls:
        return

    try:
        response = requests.get(fuzzed_url, proxies=proxy, headers=headers)

    except requests.exceptions.RequestException as e:
        print(f"Error fetching {fuzzed_url}: {e}")
        return

    if response.status_code == 200 and response.text:
        with results_lock:
            if f"FUZZED: {fuzzed_url}" not in results:
                results.append(f"FUZZED: {fuzzed_url}")

            matches = process_response(fuzzed_url, response.text)
            with open("internal/details/export_links.txt", "w") as f: 
                for pattern_name, pattern_matches in matches.items():
                    for match in pattern_matches:
                        result_entry = f"({pattern_name})| {match} | {fuzzed_url}"
                        results.append(result_entry)    
                        f.write(f"{match}  ->  {fuzzed_url}\n")
            f.close()            
                


            # Scraping JavaScript files and applying regex
            javascript_urls = fetch_javascript_urls(response.text, fuzzed_url)
            for js_url in javascript_urls:
                try:
                    js_response = requests.get(js_url, proxies=proxy, headers=headers)
                    if js_response.status_code == 200:
                        js_matches = process_response(js_url, js_response.text)
                        for pattern_name, pattern_matches in js_matches.items():
                            for match in pattern_matches:
                                js_result_entry = f"JavaScript ({pattern_name})| {match} | {js_url}"
                                results.append(js_result_entry)  
                                with open("internal/details/export_links.txt", "a") as f:   
                                    f.write(f"{match}  ->   {js_url}\n") 
                                f.close()        

                except requests.exceptions.RequestException as e:
                    print(f"Error fetching JavaScript content from {js_url}: {e}")               

@app.route('/enumerate/details', methods=['POST', 'GET'])
@login_required
def fuzz_site():
    global results
    results = []

    export_format = request.form.get('export_format')
    if export_format is not None:
        return export_links('internal/details/export_links.txt', export_format)

    if request.method == 'GET':
        return render_template('details.html')

    if request.method == 'POST':
        url = request.form['url']
        new_word = request.form.get('new_word')
        is_fuzz = request.form.get('is_fuzz')

        if new_word:
            with open(wordlist_file, 'a') as f:
                f.write(f"{new_word}\n")
            return render_template("details.html", message=f"{new_word} Successfully added in Wordlists.")

        with open(wordlist_file) as f:
            words = [line.strip() for line in f]

        threads = []
        worker(url, "")  # Perform non-fuzzed operation initially

        if is_fuzz == 'on':
            for word in words:
                if word not in seen_urls:
                    thread = threading.Thread(target=worker, args=(url, word))
                    threads.append(thread)
                    thread.start()

            for thread in threads:
                thread.join()

    return render_template('details.html', results=results)

######################################################## EXIF METADATA ######################################################

@app.route("/enumerate/metadata", methods=["POST"])
@login_required
def metadata():
    if request.method == "POST":
        if 'file' not in request.files:
            return render_template("metadata.html", message="No file part")

        uploaded_file = request.files['file']

        if uploaded_file.filename == '':
            return render_template("metadata.html", message="No selected file")

        if uploaded_file:
            image_path = f"internal/metadata/{uploaded_file.filename}"
            uploaded_file.save(image_path)

            # Use exiftool to get metadata
            command = f'exiftool "{image_path}"'
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

            # Display the metadata
            metadata = result.stdout if result.stdout else "No metadata found"
            return render_template("details.html", message="File uploaded and metadata extracted:", metadata=metadata)

    return redirect(url_for('fuzz_site'))

####################################################################  DEANONYMIZE  ###########################################################
"""
@app.route('/enumerate/deanonymize', methods=['GET','POST'])
def onion_certificate():

    if request.method == 'GET':
        return render_template('deanonymize.html')


    if request.method == 'POST':
        url = request.form.get('url')  # Replace with the Onion site you want to query

        try:
            response = requests.get(url, verify=False, proxies=proxy)  # Ignoring SSL verification for Onion sites
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, response.content)

            # Fetching certificate details
            issuer = cert.get_issuer()
            subject = cert.get_subject()
            expiration_date = cert.get_notAfter().decode("utf-8")

            return render_template('onion_certificate.html', issuer=issuer, subject=subject, expiration_date=expiration_date)
        
        except requests.exceptions.RequestException as e:
            return f"Error fetching certificate information: {e}"
    
"""
######################################################3###############  LOGOUT   #############################################################

# Logout rout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
