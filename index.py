from flask import Flask, redirect, url_for, request, render_template, make_response, session, jsonify
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import os
from dotenv import load_dotenv, dotenv_values 
import googleapiclient.http
import google.generativeai as genai

load_dotenv() 
genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
model = genai.GenerativeModel('gemini-1.5-flash')
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY')
CLIENT_SECRETS_FILE = "client_secrets.json"
SCOPES = [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/drive.metadata.readonly',
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/drive.file',
    'openid'
]

def get_user_info(credentials):
    user_info_service = googleapiclient.discovery.build('oauth2', 'v2', credentials=credentials)
    user_info = user_info_service.userinfo().get().execute()
    return user_info

def generate_response(text):
    response = model.generate_content(text)
    return response.text.strip()

@app.route('/login')
def login():
    if 'credentials' in session:
        return redirect(url_for('home'))
    
    return render_template('login.html')

@app.route('/google')
def google_oauth():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for('callback', _external=True)

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    session['state'] = state

    return redirect(authorization_url)

@app.route('/callback')
def callback():
    state = session['state']
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('callback', _external=True)

    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    return redirect(url_for('home'))

@app.route('/home')
def home():

    if 'credentials' not in session:
        return redirect(url_for('login'))
    
    user_info = get_user_info(google.oauth2.credentials.Credentials(**session['credentials']))
    return render_template('home.html', user_info=user_info, user_profile=user_info['picture'], user_name=user_info['name'], user_email=user_info['email'])

@app.route('/form')
def form():
    user_info = get_user_info(google.oauth2.credentials.Credentials(**session['credentials']))
    return render_template('form.html', user_info=user_info, user_profile=user_info['picture'], user_name=user_info['name'], user_email=user_info['email'])

@app.route('/api/form', methods=['POST'])
def api_form():
    data = request.get_json()
    input = data['input']
    response = generate_response(input)
    return jsonify({'response': response})

if __name__ == '__main__':
    app.run(debug=True, port=8000)
