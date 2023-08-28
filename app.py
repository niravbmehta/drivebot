import os
from flask import Flask, request, jsonify
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from flask import session, redirect, url_for
from flask_session import Session
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from googleapiclient.discovery import build
import json
import openai
import requests
import tempfile

app = Flask(__name__)
app.secret_key = ""
#os.urandom(24)

#OpenAI API key
OPENAI_API_KEY = "sk-"
openai.api_key = OPENAI_API_KEY

# Set the session type to filesystem (other options are 'redis', 'memcached', etc.)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = tempfile.mkdtemp()

Session(app)
# Store for session parameters
user_store = {}

@app.route('/oauth2callback')
def oauth2callback():
    print("Session at beginning of oauth2callback: ", session)
    flow = InstalledAppFlow.from_client_secrets_file(
        'client_secrets.json',
        scopes=['https://www.googleapis.com/auth/drive.readonly']
    )
    flow.redirect_uri = 'https://fa1f-73-158-248-229.ngrok-free.app/oauth2callback'
    print("Generated Redirect URI:", flow.redirect_uri)  # Debug line
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    session['credentials'] = flow.credentials.to_json()
    user_store['credentials'] = flow.credentials.to_json()
    print(url_for('google_drive_integration'))
    return redirect(url_for('google_drive_integration'))

@app.route('/logout')
def logout():
    session.pop('credentials', None)
    print("Logging out...")
    return redirect(url_for('index'))  # Might want to redirect elsewhere or add a simple "logged out" message

@app.route('/drive', methods=['GET', 'POST'])
def google_drive_integration():
    # This method checks user creds, searches google drive, etc.

    creds = None
    if 'credentials' in session:
        creds_data = json.loads(session['credentials'])
        creds = Credentials.from_authorized_user_info(creds_data)
    elif 'credentials' in user_store:
        creds_data = json.loads(user_store['credentials'])
        creds = Credentials.from_authorized_user_info(creds_data)

    if not creds or not creds.valid:
        return redirect(url_for('authorize'))

    drive_service = build('drive', 'v3', credentials=creds)
    user_query = user_store["user_query"]
    #Refine the user's question into a  concise query for Google Drive
    refined_user_query = refine_query_with_gpt3(user_query)
    print("Refined User query in Drive is: ",refined_user_query)
    
    results = drive_service.files().list(q=f'fullText contains "{refined_user_query}"', pageSize=10).execute()
    items = results.get('files', [])
    print("Items fetched: ", items)
    if not items:
        response_text = "No files match the query!"
    else:
        response_text = search_drive_files(user_query, items, creds)
    print("Session when we get to drive: ",session)
    #user_id = session.get('user_id')
    user_id = user_store["user_id"]
    send_to_slack(response_text, user_id)
    #session.pop('user_id', None)
    return "You can now check Slack for the file list.", 200

def search_drive_files(query, items, creds):
    contents = []
    for item in items:
        mimeType = item['mimeType']
        file_id = item['id']
        if mimeType == 'application/vnd.google-apps.document':
            contents.append(item['name'])
            docs_service = build('docs', 'v1', credentials=creds)
            doc = docs_service.documents().get(documentId=file_id).execute()
            content = read_elements(doc['body']['content'])
            contents.append(content)
    # If it's a Google Sheet (Note: This will fetch only the first sheet's data)
        elif mimeType == 'application/vnd.google-apps.spreadsheet':
            contents.append(item['name'])
            sheets_service = build('sheets', 'v4', credentials=creds)
            # Fetch the spreadsheet's metadata to get sheet names
            sheet_metadata = sheets_service.spreadsheets().get(spreadsheetId=file_id).execute()
            first_sheet_name = sheet_metadata['sheets'][0]['properties']['title']
            sheet = sheets_service.spreadsheets().values().get(spreadsheetId=file_id, range=f"{first_sheet_name}!A:Z").execute()
            content = '\n'.join([','.join(row) for row in sheet.get('values', [])])
            contents.append(content)
    
    # Trim content to max 3000 words. (given gpt3.5's 4096 token limit)
    full_content = ' '.join(contents)

    # Split by space to count words
    words = full_content.split()

    # Check if word count exceeds 3000
    if len(words) > 3000:
        # Trim words to the first 3000
        trimmed_words = words[:3000]
        # Update contents list with the trimmed version
        contents = [' '.join(trimmed_words)]

    #Now use OpenAI APIs to answer user query with drive results
    print ("Contents being sent to OpenAI: ",contents)
    print ("Query is: ", query)
    # Create the conversation messages array
    messages = [
        {"role": "system", "content": "You are a helpful assistant that can answer questions based on content from Google Drive."},
        {"role": "user", "content": f"Based on the following content from Google Drive:\n\n{contents}"},
        {"role": "user", "content": query}
    ]

    # Use OpenAI API to get the answer
    model_engine = "gpt-3.5-turbo"  
    response = openai.ChatCompletion.create(
        model=model_engine,
        messages=messages
    )

    # Extract and return the assistant's reply
    assistant_reply = response['choices'][0]['message']['content']
    return assistant_reply

def read_elements(elements):
    """Recursively extracts text from Google Doc elements"""
    text = ""
    for element in elements:
        if 'paragraph' in element:
            for part in element['paragraph']['elements']:
                # Check if 'textRun' exists before accessing its content
                if 'textRun' in part:
                    text += part['textRun']['content']
        if 'table' in element:
            for row in element['table']['tableRows']:
                text += read_elements(row['tableCells'])
    return text

def send_to_slack(message, user_id):
    """Send a delayed message to Slack."""
    global user_store
    # Fetch user_id from session instead of request
    #user_id = session.pop('user_id', None)
    print("User id passed: ", user_id)
    response_url = user_store["slack_response_url"]
    #response_url = session.pop('slack_response_url', None)
    if not response_url:
        print(f"No response_url found for user_id: {user_id}")
        return
    
    payload = {
        "text": message
    }
    headers = {
        "Content-Type": "application/json"
    }
    response = requests.post(response_url, data=json.dumps(payload), headers=headers)
    return response

@app.route('/authorize')
def authorize():
    print("Session at beginning of authorize:",session)
    flow = InstalledAppFlow.from_client_secrets_file(
        'client_secrets.json',
        scopes=['https://www.googleapis.com/auth/drive.readonly']
    )
    flow.redirect_uri = "https://fa1f-73-158-248-229.ngrok-free.app/oauth2callback"
    #url_for('oauth2callback', _external=True)
    authorization_url, _ = flow.authorization_url(prompt='consent')
    print("Redirecting to:",authorization_url) #Debug
    return redirect(authorization_url)


@app.route('/events', methods=['POST'])
def slack_event():
    data = request.json
    print("Events")
    if 'challenge' in data:
        return jsonify({'challenge': data['challenge']})
    return jsonify({'status': 'success'})

def refine_query_with_gpt3(user_question):
    """Use GPT-3.5-turbo to transform a natural language question into a concise query."""
    user_message = "The user is trying to find answers from the contents of his Google Drive. Reframe this question into a short search phrase to use in google drive: " + user_question
    messages = [
        {"role": "system", "content": "You are a helpful assistant. Your task is to translate verbose user questions into concise search queries suitable for Google Drive search. Keep the essence, but make it short and clear."},
        {"role": "user", "content": user_question}
    ]
    print("User Message to GPT3.5: ",user_message)
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=messages,
        temperature=0.2
    )
    refined_query = response['choices'][0]['message']['content']
    refined_query = refined_query.strip('"')
    refined_query = refined_query.replace("'", "\\'")
    return refined_query

@app.route('/askbot', methods=['POST'])
def handle_command():
    global user_store
    user_id = request.form.get('user_id')
    print("Session at beginning of askbot: ",session)
    # Store user_id in the session
    session.permanent = True
    session['user_id'] = user_id
    session.modified = True
    print("User id being stored against: ",user_id)
    user_store["slack_response_url"] = request.form['response_url']
    user_store["user_id"] = user_id
    print("Response url being stored with it: ", request.form['response_url'])
    user_query = request.form.get('text')
    user_store["user_query"] = user_query
    print("User store after saving everything: ", user_store)

    # Check if we have credentials in session
    creds = None
    if 'credentials' in session:
        creds_data = json.loads(session['credentials'])
        creds = Credentials.from_authorized_user_info(creds_data)
    elif 'credentials' in user_store:
        creds_data = json.loads(user_store['credentials'])
        creds = Credentials.from_authorized_user_info(creds_data)

    # If we have valid creds, proceed to access Google Drive.
    if creds and creds.valid:
        google_drive_integration()
        response_text = "Fetched results above from Google Drive"
        """drive_service = build('drive', 'v3', credentials=creds)
        # Query the Google Drive API with the user's query
        results = drive_service.files().list(q=f"name contains '{user_query}'", pageSize=10).execute()
        items = results.get('files', [])
        file_names = [item['name'] for item in items]
        response_text = f"Results for '{user_query}':\n" + '\n'.join(file_names)
        """
    else:
        # If we don't have credentials, guide the user to initiate the auth flow.
        session['slack_response_url'] = request.form['response_url']
        print("Session after setting response_url:", session)
        response_text = "You need to authorize me to access Google Drive. Please visit this URL to do so: " + url_for('authorize', _external=True)

    return jsonify({'text': response_text})

if __name__ == '__main__':
    app.run(port=5000)
