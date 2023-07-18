''' MAIN SERVER FILE FOR MINI PROJECT'''
#!/usr/bin/env python

# This is a simple web server for a traffic counting application.
# It's your job to extend it by adding the backend functionality to support
# recording the traffic in a SQL database. You will also need to support
# some predefined users and access/session control. You should only
# need to extend this file. The client side code (html, javascript and css)
# is complete and does not require editing or detailed understanding.

# import the various libraries needed
import http.cookies as Cookie # some cookie handling support
from http.server import BaseHTTPRequestHandler, HTTPServer
from os import times # the heavy lifting of the web server
import urllib # some url parsing support
import urllib.parse
import json # support for json encoding
import sys # needed for agument handling
import sqlite3
import random
import string
import time
import re
from datetime import datetime
import dateutil.relativedelta
# from requests.models import guess_json_utf

DATABASE = './traffic.db'

# access_database requires the name of a sqlite3 database file and the query.
# It does not return the result of the query.
def access_database(dbfile, query, *args):
    '''function to modify or update the database without returning any result'''
    connect = sqlite3.connect(dbfile)
    cursor = connect.cursor()
    cursor.execute(query,args)
    connect.commit()
    connect.close()

# access_database requires the name of an sqlite3 database file and the query.
# It returns the result of the query
def access_database_with_result(dbfile, query, *args):
    '''function to read data from the database.
    It mainly returns the results as a list of tuples'''
    connect = sqlite3.connect(dbfile)
    cursor = connect.cursor()
    rows = cursor.execute(query,args).fetchall()
    connect.commit()
    connect.close()
    return rows


def generate_magic(length=12, chars=string.ascii_uppercase+string.digits):
    ''' Generate a random string consisting of letters and numbers
    of size 12 that representrs the magic token for a session '''
    magix = ''.join(random.choice(chars) for _ in range(length))
    while magix in tuple_to_set(access_database_with_result(DATABASE, "SELECT magic FROM session")):
        magix = ''.join(random.choice(chars) for _ in range(length))
    return magix

def tuple_to_set(tup):
    ''' Convert a tuple with only one element to a set '''
    return {v[0] for v in tup}

def get_sesh_id():
    ''' creates a new sessionid for a new session '''
    return access_database_with_result(DATABASE, "SELECT MAX(sessionid) FROM session")[0][0]+4

def get_user_id(uname):
    ''' Given a username, get the respective user id '''
    if uname not in ['','!']:#try:
        answer = access_database_with_result(DATABASE, '''SELECT userid
                                        FROM users 
                                        WHERE username=? ''',uname)[0][0]
    else:#except:
        answer = None
    return answer

def create_rec_id():
    ''' Create a new record id for an entry in traffic table '''
    return access_database_with_result(DATABASE, "SELECT MAX(recordid) FROM traffic")[0][0]+1

def make_traffic_csv():
    ''' Helper function for creating traffic.csv.
        Returns the text to be stored in the csv '''
    recent_time = access_database_with_result(DATABASE, '''SELECT MAX(time) FROM traffic
                                                WHERE mode=1''')[0][0]
    answer = None
    if recent_time:
        recent_time = datetime.fromtimestamp(recent_time)
        day_ = recent_time + \
            dateutil.relativedelta.relativedelta(hour=00,minute=00,second=00,microsecond=00)
        day_diff = int(datetime.timestamp(day_))

        res = access_database_with_result(DATABASE,'''SELECT location,type,
                                                                SUM(CASE WHEN occupancy=1 THEN 1 ELSE 0 END),
                                                                SUM(CASE WHEN occupancy=2 THEN 1 ELSE 0 END),
                                                                SUM(CASE WHEN occupancy=3 THEN 1 ELSE 0 END),
                                                                SUM(CASE WHEN occupancy=4 THEN 1 ELSE 0 END)
                                                                FROM traffic 
                                                                INNER JOIN session 
                                                                ON traffic.sessionid = session.sessionid
                                                                WHERE mode=1
                                                                AND time>=? 
                                                                GROUP BY type,location 
                                                                ORDER BY userid ''' ,day_diff)
        if len(res)>0:
            res = [[str(el1) for el1 in el] for el in res]
            final_text = '\n'.join([','.join(list(ele)) for ele in res])
            answer = final_text
        else:
            answer = ''
    return answer

def make_hours_csv():
    ''' Helper function for creating hours.csv.
        Returns the text to be stored in the csv '''
    users={}
    for item in range(1,11):
        users[item]=['test'+str(item),'0.0','0.0','0.0']
    get_end = access_database_with_result(DATABASE,"SELECT MAX(end) from session")
    if len(get_end)>0 and get_end[0][0]>0:
        user_list = access_database_with_result(DATABASE,'''SELECT username FROM users
                        INNER JOIN session 
                        ON users.userid=session.userid''')
        try:
            user_list = {get_user_id(a[0]) for a in user_list}
        except Exception as ex:
            print(ex)
            return 'Relogin'
        now = datetime.fromtimestamp(get_end[0][0])
        day_ = now + \
            dateutil.relativedelta.relativedelta(hour=00,minute=00,second=00,microsecond=00)
        day_ = datetime.timestamp(day_)
        # day_diff = round((now-day_).total_seconds()/3600,1)
        week_ = now + \
            dateutil.relativedelta.relativedelta(weeks=-1,hour=00,
                minute=00,second=00,microsecond=00)
        week_ = datetime.timestamp(week_)
        # week_diff = round((now-week_).total_seconds()/3600,1)
        month_ = now + \
            dateutil.relativedelta.relativedelta(months=-1,days=+1,
                hour=00,minute=00,second=00,microsecond=00)
        month_ = datetime.timestamp(month_)
        # month_diff = round((now-month_).total_seconds()/3600,1)

        for usr in user_list:
            if usr in users:
                days = access_database_with_result(DATABASE, '''SELECT start,end
                    FROM session WHERE userid=? AND end>? ''',usr,day_)
                weeks = access_database_with_result(DATABASE, '''SELECT start,end FROM session
                        WHERE userid=? AND end>? ''',usr,week_)
                months = access_database_with_result(DATABASE, '''SELECT start,end FROM session
                        WHERE userid=? AND end>? ''',usr,month_)
                differences = [0.0,0.0,0.0]
                if len(days)>0:
                    for start,end in days:
                        if start>day_:
                            differences[0] += end-start
                        else:
                            differences[0] += end - day_

                if len(weeks)>0:
                    for start,end in weeks:
                        if start>week_:
                            differences[1] += end-start
                        else:
                            differences[1] += end - week_

                if len(months)>0:
                    for start,end in months:
                        if start>month_:
                            differences[2] += end-start
                        else:
                            differences[2] += end - month_

                differences = [differences[0]/3600, differences[1]/3600,differences[2]/3600]
                users[usr] = ['test'+str(usr),str(round(differences[0],1)),\
                    str(round(differences[1],1)),str(round(differences[2],1))]
        res = '\n'.join([','.join([users[elem][0],users[elem][1],\
                                users[elem][2],users[elem][3]]) for elem in users.keys()])
    elif not get_end[0][0]:
        res = '\n'.join([','.join([users[elem][0],users[elem][1],\
                                users[elem][2],users[elem][3]]) for elem in users.keys()])
    else:
        res = 'Nothing'
    return res


def get_total(sid,uid):
    ''' Computes the total records satisfying the conditions '''
    total = access_database_with_result(DATABASE,'''SELECT COUNT(traffic.recordid)
                                                                FROM traffic
                                                                INNER JOIN session
                                                                ON traffic.sessionid = session.sessionid
                                                                WHERE session.userid == ?
                                                                AND traffic.sessionid ==?
                                                                AND traffic.mode=1''',uid,sid )[0][0]
    return total

def get_total_with_type(sid,uid,type_):
    ''' Calculates the total number of records of each vehicle type specified'''
    total = access_database_with_result(DATABASE,'''SELECT COUNT(traffic.recordid)
                                                                FROM traffic
                                                                INNER JOIN session 
                                                                ON traffic.sessionid = session.sessionid
                                                                WHERE session.userid == ?
                                                                AND traffic.sessionid ==?
                                                                AND traffic.type==?
                                                                AND traffic.mode=1''', uid,sid,type_)[0][0]
    return total


def build_response_refill(where, what):
    """This function builds a refill action that allows part of the
       currently loaded page to be replaced."""
    return {"type":"refill","where":where,"what":what}


def build_response_redirect(where):
    """This function builds the page redirection action
       It indicates which page the client should fetch.
       If this action is used, only one instance of it should
       contained in the response and there should be no refill action."""
    return {"type":"redirect", "where":where}


def is_logged_in(iuser):
    """Decide if the combination of user and magic is valid"""
    ## alter as required
    results = access_database_with_result(DATABASE, '''SELECT users.username, session.magic FROM users
                                                    INNER JOIN session ON session.userid = users.userid
                                                    WHERE users.username ==? AND session.end==0 ''', iuser)
    if len(results)>0:
        answer = (True,results[0][1])
    else:
        answer = (False,)
    return answer

def handle_validate(iuser, imagic):
    """Decide if the combination of user and magic is valid"""
    ## alter as required
    results = access_database_with_result(DATABASE, '''SELECT users.username, session.magic FROM users
                                                    INNER JOIN session ON session.userid = users.userid
                                                    WHERE users.username ==?
                                                    AND session.magic==? ''', iuser,imagic)
    # if len(results)>0:
    #     return True
    # else:
    #     return False
    return bool(len(results)>=1)


def handle_delete_session(iuser, imagic):
    """Remove the combination of user and magic from the data base, ending the login"""
    uid = get_user_id(iuser)
    if uid:
        end_time = int(time.time())
        access_database(DATABASE, '''UPDATE session SET end=?
            WHERE userid==? AND magic==? ''',end_time,uid,imagic)


def handle_login_request(iuser, imagic, parameters):
    """A user has supplied a username (parameters['usernameinput'][0])
       and password (parameters['passwordinput'][0]) check if these are
       valid and if so, create a suitable session record in the database
       with a random magic identifier that is returned.
       Return the username, magic identifier and the response action set."""
    # valid = handle_validate(iuser, imagic)
    # if valid[0] == True:
    #     # the user is already logged in, so end the existing session.
    #     handle_delete_session(iuser, valid[1])
    response = []
    ## alter as required
    usernames = tuple_to_set(access_database_with_result(DATABASE, "SELECT username FROM users"))
    try:
        if len(parameters['usernameinput'][0])==0 or len(parameters['passwordinput'][0])==0:
            pass
        if parameters['usernameinput'][0] in usernames:
            user = parameters['usernameinput'][0]
            valid = is_logged_in(user)
            if valid[0]:
                # the user is already logged in, so end the existing session.
                handle_delete_session(user, valid[1])
            pwd = access_database_with_result(DATABASE, '''SELECT password FROM users
                        WHERE username=? ''',user)[0][0]
            if parameters['passwordinput'][0] == pwd: ## The user is valid
                sid = get_sesh_id()
                uid = get_user_id(user)
                if not uid:
                    response.append(build_response_redirect('/index.html'))
                    user = '!'
                    magic = ''
                    return [user, magic, response]
                magic = generate_magic()
                start_time = int(time.time())
                access_database(DATABASE, '''INSERT INTO session(sessionid,userid,magic,start,end)
                                            VALUES (?,?,?,?,0)''',sid,uid,magic,start_time)
                response.append(build_response_redirect('/page.html'))

            else: ## The pwd is not valid
                response.append(build_response_refill('message', \
                        'Invalid password, failed to login/re-login'))
                user = '!'
                magic = ''

        else: ## The user is not valid
            response.append(build_response_refill('message', \
                    'Invalid username! Please try again'))
            user = '!'
            magic = ''
    except Exception as ex:
        print(ex)
        response.append(build_response_refill('message', \
                    'Possible invalid or missing entries'))
        user = '!'
        magic = ''
    return [user, magic, response]


def handle_add_request(iuser, imagic, parameters):
    """The user has requested a vehicle be added to the count
       parameters['locationinput'][0] the location to be recorded
       parameters['occupancyinput'][0] the occupant count to be recorded
       parameters['typeinput'][0] the type to be recorded
       Return the username, magic identifier (these can be empty  strings)
       and the response action set."""
    response = []
    choices = {"car": 0, "van":1, "truck":2, "taxi":3, "other":4, "motorbike":5, "bicycle":6, "bus":7}
    ## alter as required
    uid = get_user_id(iuser)
    if uid:
        try:
            sid = access_database_with_result(DATABASE, '''SELECT sessionid FROM session
            WHERE userid=? AND magic=? ''',uid,imagic)[0][0]
            try:
                loc = parameters['locationinput'][0]
            except:
                total = get_total(sid,uid)
                response.append(build_response_refill('message', 'Please enter a location'))
                response.append(build_response_refill('total', f'{total}'))
                user = iuser
                magic = imagic
                return [user, magic, response]
            occ = int(parameters['occupancyinput'][0])
            if occ not in range(1,5):
                raise Exception
            type_ = choices[parameters['typeinput'][0]]
            loc_pattern = re.compile("[^0-9a-zA-Z ]")
            good_loc = re.sub(loc_pattern,'',loc).lower()
            timestamp = int(time.time())
            if handle_validate(iuser, imagic) is not True:
                #Invalid sessions redirect to login
                response.append(build_response_redirect('/index.html'))
                user='!'
                magic=''
            else: ## a valid session so process the addition of the entry.
                if good_loc != '':
                    cnt = access_database_with_result(DATABASE, "SELECT * FROM traffic")
                    if len(cnt)>0:
                        reid = create_rec_id()
                        access_database(DATABASE, '''INSERT INTO traffic(recordid,sessionid,time,type,occupancy,location,mode)
                                                    VALUES (?,?,?,?,?,?,1) ''',
                                                    reid,sid,timestamp,type_,occ,good_loc)
                    else:
                        access_database(DATABASE, '''INSERT INTO traffic(recordid,sessionid,time,type,occupancy,location,mode)
                                                    VALUES (100,?,?,?,?,?,1) ''',
                                                    sid,timestamp,type_,occ,good_loc)
                    total = get_total(sid,uid)

                    response.append(build_response_refill('message', f'Entry with location as {good_loc} added successfullly'))
                    response.append(build_response_refill('total', f'{total}'))
                    user = iuser
                    magic = imagic
                else:
                    total = get_total(sid,uid)
                    response.append(build_response_refill('message', 'Invalid Input for Location. Entry could not be added'))
                    response.append(build_response_refill('total', str(total)))
                    user = iuser
                    magic = imagic
        except Exception as ex:
            sid = access_database_with_result(DATABASE, '''SELECT sessionid FROM session
            WHERE userid=? AND magic=? ''',uid,imagic)[0][0]
            print(ex)
            total = get_total(sid,uid)
            response.append(build_response_refill('message', 'Error. Entry could not be added'))
            response.append(build_response_refill('total', str(total)))
            user = iuser
            magic = imagic
    else:
        response.append(build_response_redirect('/index.html'))
        user,magic = '',''

    return [user, magic, response]


def handle_undo_request(iuser, imagic, parameters):
    """The user has requested a vehicle be removed from the count
       This is intended to allow counters to correct errors.
       parameters['locationinput'][0] the location to be recorded
       parameters['occupancyinput'][0] the occupant count to be recorded
       parameters['typeinput'][0] the type to be recorded
       Return the username, magic identifier (these can be empty  strings)
        and the response action set."""
    response = []
    ## alter as required
    choices = {"car": 0, "van":1, "truck":2, "taxi":3, 
    "other":4, "motorbike":5, "bicycle":6, "bus":7}
    if handle_validate(iuser, imagic) is not True:
        #Invalid sessions redirect to login
        response.append(build_response_redirect('/index.html'))
    else: ## a valid session so process the recording of the entry.
        uid = get_user_id(iuser)
        try:
            sid = access_database_with_result(DATABASE, '''SELECT sessionid FROM session
                                                        WHERE userid=? AND magic=? ''',uid,imagic)[0][0]
            try:
                loc = parameters['locationinput'][0]
            except:
                total = get_total(sid,uid)
                response.append(build_response_refill('message', 'Please enter a location'))
                response.append(build_response_refill('total', f'{total}'))
                user = ''
                magic = ''
                return [user, magic, response]
            occ = int(parameters['occupancyinput'][0])
            type_ = choices[parameters['typeinput'][0]]
            loc_pattern = re.compile("[^0-9a-zA-Z ]")
            good_loc = re.sub(loc_pattern,'',loc).lower()
            if good_loc != '':
                # good_loc = good_loc.string
                cnt = access_database_with_result(DATABASE, "SELECT * FROM traffic")
                if len(cnt)>0:
                    reid = create_rec_id()
                    timestamp = int(time.time())
                    get_ans = access_database_with_result(DATABASE, ''' SELECT MAX(recordid)
                                                                    FROM traffic
                                                                    WHERE sessionid==? AND 
                                                                    type==? AND 
                                                                    occupancy==? AND 
                                                                    location==? AND
                                                                    mode==1 ''',
                                                                    sid,type_,occ,good_loc)
                    if get_ans[0][0]:
                        rec1 = get_ans[0][0]
                        access_database(DATABASE, ''' UPDATE traffic SET mode=2
                                                    WHERE recordid=? AND
                                                    sessionid=? AND 
                                                    type=? AND 
                                                    occupancy=? AND 
                                                    location=? AND
                                                    mode=1 ''',
                                                    rec1,sid,type_,occ,good_loc)
                        access_database(DATABASE, '''INSERT INTO traffic(recordid,sessionid,
                                                        time,type,occupancy,location,mode)
                                                    VALUES (?,?,?,?,?,?,0) ''',
                                                    reid,sid,timestamp,type_,occ,good_loc)
                        total = get_total(sid,uid)
                        response.append(build_response_refill('message', f'Entry with location as \
                            {good_loc} Un-done successfully!'))
                        response.append(build_response_refill('total', f'{total}'))
                        user = iuser
                        magic = imagic
                    else:
                        total = get_total(sid,uid)
                        response.append(build_response_refill('message', f'Entry could not be Un-done. \
                            No record with location as {good_loc} found!'))
                        response.append(build_response_refill('total', f'{total}'))
                        user = ''
                        magic = ''
                else:
                    total = get_total(sid,uid)
                    response.append(build_response_refill('message', 'Database is empty. No entry to undo'))
                    response.append(build_response_refill('total', f'{total}'))
                    user = ''
                    magic = ''
            else:
                total = get_total(sid,uid)
                response.append(build_response_refill('message', 'Invalid input for location. Please try again'))
                response.append(build_response_refill('total', f'{total}'))
                user = ''
                magic = ''
        except Exception as ex:
            print(ex)
            sid = access_database_with_result(DATABASE, '''SELECT sessionid FROM session
                                                        WHERE userid=? AND magic=? ''',uid,imagic)[0][0]
            total = get_total(sid,uid)
            response.append(build_response_refill('message', 'Invalid input. Please try again'))
            response.append(build_response_refill('total', f'{total}'))
            user = ''
            magic = ''
    return [user, magic, response]


def handle_back_request(iuser, imagic):
    """This code handles the selection of the back 
        button on the record form (page.html)
       You will only need to modify this code if you make 
       changes elsewhere that break its behaviour"""
    print('Inside handle_back')
    response = []
    ## alter as required
    if handle_validate(iuser, imagic) is not True:
        response.append(build_response_redirect('/index.html'))
        user = ''
        magic = ''
    else:
        response.append(build_response_redirect('/summary.html'))
        user = iuser
        magic = imagic
    return [user, magic, response]


def handle_logout_request(iuser, imagic):
    """This code handles the selection of the logout button on the summary page (summary.html)
       You will need to ensure the end of the session is recorded in the database
       And that the session magic is revoked."""
    response = []
    ## alter as required
    handle_delete_session(iuser,imagic)
    response.append(build_response_redirect('/index.html'))
    user = '!'
    magic = ''
    return [user, magic, response]


def handle_summary_request(iuser, imagic):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    ## alter as required
    if handle_validate(iuser, imagic) is not True:
        response.append(build_response_redirect('/index.html'))
        user,magic = '',''
    else:
        uid = get_user_id(iuser)
        if uid:
            sid = access_database_with_result(DATABASE, "SELECT sessionid FROM session WHERE userid=? AND magic=? ",uid,imagic)[0][0]
            choices = {"car": 0, "van":1, "truck":2, "taxi":3, "other":4, "motorbike":5, "bicycle":6, "bus":7}
            response.append(build_response_refill('sum_car', get_total_with_type(sid,uid,choices["car"])))
            response.append(build_response_refill('sum_taxi', get_total_with_type(sid,uid,choices["taxi"])))
            response.append(build_response_refill('sum_bus', get_total_with_type(sid,uid,choices["bus"])))
            response.append(build_response_refill('sum_motorbike', get_total_with_type(sid,uid,choices["motorbike"])))
            response.append(build_response_refill('sum_bicycle', get_total_with_type(sid,uid,choices["bicycle"])))
            response.append(build_response_refill('sum_van', get_total_with_type(sid,uid,choices["van"])))
            response.append(build_response_refill('sum_truck', get_total_with_type(sid,uid,choices["truck"])))
            response.append(build_response_refill('sum_other', get_total_with_type(sid,uid,choices["other"])))
            response.append(build_response_refill('total', get_total(sid,uid)))
            user = iuser
            magic = imagic
        else:
            user,magic = '',''
    return [user, magic, response]


# HTTPRequestHandler class
class myHTTPServer_RequestHandler(BaseHTTPRequestHandler):
    ''' use the BaseHTTPRequestHandler to handle GET requests and
        display relevant pages as requested '''
    # GET This function responds to GET requests to the web server.
    def do_GET(self):
        ''' handles all GET requests '''
        # The set_cookies function adds/updates two cookies returned with a webpage.
        # These identify the user who is logged in. The first parameter identifies the user
        # and the second should be used to verify the login session.
        def set_cookies(self_v, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie['u_cookie'] = user
            self_v.send_header("Set-Cookie", ucookie.output(header='', sep=''))
            mcookie = Cookie.SimpleCookie()
            mcookie['m_cookie'] = magic
            self_v.send_header("Set-Cookie", mcookie.output(header='', sep=''))

        # The get_cookies function returns the values of the user and magic cookies if they exist
        # it returns empty strings if they do not.
        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get('Cookie'))
            user = ''
            magic = ''
            for keyc, valuec in rcookies.items():
                if keyc == 'u_cookie':
                    user = valuec.value
                if keyc == 'm_cookie':
                    magic = valuec.value
            return [user, magic]

        # Fetch the cookies that arrived with the GET request
        # The identify the user session.
        user_magic = get_cookies(self)

        print(user_magic)

        # Parse the GET request to identify the file requested and the parameters
        parsed_path = urllib.parse.urlparse(self.path)

        # Decided what to do based on the file requested.

        # Return a CSS (Cascading Style Sheet) file.
        # These tell the web client how the page should appear.
        if self.path.startswith('/css'):
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return a Javascript file.
        # These tell contain code that the web client can execute.
        elif self.path.startswith('/js'):
            self.send_response(200)
            self.send_header('Content-type', 'text/js')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # A special case of '/' means return the index.html (homepage)
        # of a website
        elif parsed_path.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./index.html', 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return html pages.
        elif parsed_path.path.endswith('.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('.'+parsed_path.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # The special file 'action' is not a real file, it indicates an action
        # we wish the server to execute.
        elif parsed_path.path == '/action':
            self.send_response(200) #respond that this is a valid page request
            # extract the parameters from the GET request.
            # These are passed to the handlers.
            parameters = urllib.parse.parse_qs(parsed_path.query)

            if 'command' in parameters:
                # check if one of the parameters was 'command'
                # If it is, identify which command and call the appropriate handler function.
                if parameters['command'][0] == 'login':
                    [user, magic, response] = handle_login_request(user_magic[0], user_magic[1], parameters)
                    #The result of a login attempt will be to set the cookies to identify the session.
                    set_cookies(self, user, magic)
                elif parameters['command'][0] == 'add':
                    [user, magic, response] = handle_add_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'undo':
                    [user, magic, response] = handle_undo_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'back':
                    [user, magic, response] = handle_back_request(user_magic[0], user_magic[1])
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'summary':
                    [user, magic, response] = handle_summary_request(user_magic[0], user_magic[1])
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'logout':
                    [user, magic, response] = handle_logout_request(user_magic[0], user_magic[1])
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                else:
                    # The command was not recognised, report that to the user.
                    response = []
                    response.append(build_response_refill('message', 'Internal Error: Command not recognised.'))

            else:
                # There was no command present, report that to the user.
                response = []
                response.append(build_response_refill('message', 'Internal Error: Command not found.'))

            text = json.dumps(response)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(text, 'utf-8'))

        elif self.path.endswith('/statistics/hours.csv'):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for /statistics/hours.csv should be handled.
            ## you should check a valid user is logged in. 
            # You are encouraged to wrap this behavour in a function.
            ftext = "Username,Day,Week,Month\n"
            iuser,imagic = user_magic
            if handle_validate(iuser, imagic) is not True:
                parsed_path = urllib.parse.urlparse(self.path)
                self.send_response(404)
                self.end_headers()
            else:
                add_text = make_hours_csv()
                if add_text in {'Nothing','Relogin'}:
                    pass
                else:
                    ftext += add_text
                    encoded = bytes(ftext, 'utf-8')
                    self.send_response(200)
                    self.send_header('Content-type', 'text/csv')
                    self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('hours.csv'))
                    self.send_header("Content-Length", len(encoded))
                    self.end_headers()
                    self.wfile.write(encoded)

        elif self.path.endswith('/statistics/traffic.csv'):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for  /statistics/traffic.csv should be handled.
            ## you should check a valid user is checked in. 
            # You are encouraged to wrap this behavour in a function.
            # text = "This should be the content of the csv file."
            text = "Location,Type,Occupancy1,Occupancy2,Occupancy3,Occupancy4\n"
            iuser,imagic = user_magic
            if handle_validate(iuser, imagic) is not True:
                #Invalid sessions redirect to login
                parsed_path = urllib.parse.urlparse(self.path)
                self.send_response(404)
                self.end_headers()
            else:
                additional_text = make_traffic_csv()
                if additional_text in ['',None]:
                    encoded = bytes(text, 'utf-8')
                    self.send_response(200)
                    self.send_header('Content-type', 'text/csv')
                    self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('traffic.csv'))
                    self.send_header("Content-Length", len(encoded))
                    self.end_headers()
                    self.wfile.write(encoded)
                else:
                    text+=additional_text
                    encoded = bytes(text, 'utf-8')
                    self.send_response(200)
                    self.send_header('Content-type', 'text/csv')
                    self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('traffic.csv'))
                    self.send_header("Content-Length", len(encoded))
                    self.end_headers()
                    self.wfile.write(encoded)


        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404)
            self.end_headers()
        return

def run():
    """This is the entry point function to this code."""
    print('starting server...')
    ## You can add any extra start up code here
    # Server settings
    # Choose port 8081 over port 80, which is normally used for a http server
    if len(sys.argv)<2: # Check we were given both the script name and a port number
        print("Port argument not provided.")
        return
    server_address = ('127.0.0.1', int(sys.argv[1]))
    httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
    print('running server on port =',sys.argv[1],'...')
    httpd.serve_forever() # This function will not return till the server is aborted.

run()
