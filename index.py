from flask import Flask, redirect, url_for, request, render_template, session, jsonify
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import os
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables
load_dotenv()
genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
model = genai.GenerativeModel('gemini-1.5-flash')
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY')

# Google OAuth 2.0 settings
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
    """Fetches user information using OAuth 2.0 credentials."""
    try:
        user_info_service = googleapiclient.discovery.build('oauth2', 'v2', credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        return user_info
    except Exception as e:
        print(f"Error fetching user info: {e}")
        return None

def generate_response(text):
    """Generates a response using the generative AI model."""
    try:
        response = model.generate_content(text)
        return response.text.strip()
    except Exception as e:
        print(f"Error generating response: {e}")
        return "Sorry, I couldn't generate a response."

@app.route('/login')
def login():
    """Login route to initiate the OAuth flow."""
    if 'credentials' in session:
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/google')
def google_oauth():
    """Route to handle Google OAuth authentication."""
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for('callback', _external=True)
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    """Callback route for Google OAuth."""
    try:
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
    except Exception as e:
        print(f"Error in callback: {e}")
        return redirect(url_for('login'))

@app.route('/home')
def home():
    """Home route that displays user information."""
    if 'credentials' not in session:
        return redirect(url_for('login'))
    
    credentials = google.oauth2.credentials.Credentials(**session['credentials'])
    user_info = get_user_info(credentials)
    
    if not user_info:
        return redirect(url_for('login'))
    
    return render_template('home.html', user_info=user_info, user_profile=user_info['picture'], user_name=user_info['name'], user_email=user_info['email'])

@app.route('/form')
def form():
    """Form route to display the user form."""
    if 'credentials' not in session:
        return redirect(url_for('login'))
    
    credentials = google.oauth2.credentials.Credentials(**session['credentials'])
    user_info = get_user_info(credentials)
    
    if not user_info:
        return redirect(url_for('login'))
    
    return render_template('form.html', user_info=user_info, user_profile=user_info['picture'], user_name=user_info['name'], user_email=user_info['email'])

@app.route('/api/form', methods=['POST'])
def api_form():
    """API route to handle form submission and response generation."""
    try:
        data = request.get_json()
        input_text = data['input']
        response_text = generate_response(input_text)
        return jsonify({'response': response_text})
    except Exception as e:
        print(f"Error handling form API request: {e}")
        return jsonify({'response': "An error occurred while processing your request."}), 500

if __name__ == '__main__':
    app.run(debug=True, port=8000)