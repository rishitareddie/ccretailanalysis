from flask import Flask, request, render_template, redirect, session
import os
import hashlib
from azure.storage.blob import BlobServiceClient
from dotenv import load_dotenv
import csv
from collections import defaultdict
import pandas as pd
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'uploads'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Flask app initialization
app = Flask(__name__)

app.secret_key = os.urandom(24)

# Configure the Flask app to use the upload folder
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

load_dotenv()

# Azure Storage Configuration
STORAGE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
BLOB_CONTAINER_NAME = "data"
USER_FILE_NAME = "users.csv"
CSV_FILES = ["housholds.csv", "transactions.csv", "products.csv", "combined_data"]

def upload_file_to_blob(file, filename):
    # Connect to Azure Blob Storage
    blob_service_client = BlobServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
    blob_client = blob_service_client.get_blob_client(container=BLOB_CONTAINER_NAME, blob=filename)

    try:
        # Upload the file directly to Azure Blob Storage
        with file as data:  # Use the file's stream directly
            print(f"Uploading file '{filename}' to Azure Blob Storage...")
            blob_client.upload_blob(data, overwrite=True)  # Overwrite if the file already exists
            print(f"File '{filename}' uploaded successfully!")
        return f"File '{filename}' uploaded successfully to Azure Blob Storage."
    except Exception as e:
        print(f"Error uploading file to Azure: {e}")
        return "Failed to upload file to Azure Blob Storage."


# Helper function: Register user
def register_user(username, email, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    user_data = f"{username},{email},{hashed_password}\n"

    # Save data locally
    with open(USER_FILE_NAME, "a") as file:
        file.write(user_data)

    # Upload file to Azure Blob Storage
    blob_service_client = BlobServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
    blob_client = blob_service_client.get_blob_client(container=BLOB_CONTAINER_NAME, blob=USER_FILE_NAME)
    with open(USER_FILE_NAME, "rb") as data:
        blob_client.upload_blob(data, overwrite=True)

    return "User registered successfully!"

# Helper function: Login user
def login_user(email, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Download the CSV file from Blob Storage
    blob_service_client = BlobServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
    blob_client = blob_service_client.get_blob_client(container=BLOB_CONTAINER_NAME, blob=USER_FILE_NAME)
    downloaded_data = blob_client.download_blob().readall().decode()

    # Validate credentials
    for line in downloaded_data.splitlines():
        stored_username, stored_email, stored_password = line.split(",")
        if stored_email == email and stored_password == hashed_password:
            return f"Login successful! Welcome {stored_username}."
    
    return "Invalid email or password. Please try again."

def read_data_from_blob(blob_file):
    blob_service_client = BlobServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
    blob_client = blob_service_client.get_blob_client(container=BLOB_CONTAINER_NAME, blob=blob_file)
    downloaded_data = blob_client.download_blob().readall().decode()

    # Convert to list of dictionaries (one per row)
    csv_reader = csv.DictReader(downloaded_data.splitlines())
    data_list = [row for row in csv_reader]
    
    df = pd.DataFrame(data_list)
    
    dtype_conversions = {
        "HSHD_NUM": "int32",
        "BASKET_NUM": "int32",
        "PRODUCT_NUM": "int32",
    }
    
    # Apply numeric conversions and handle errors
    for col, dtype in dtype_conversions.items():
        try:
            df[col] = pd.to_numeric(df[col], errors='coerce').astype(dtype)
        except Exception as e:
            print(f"Error converting column {col}: {e}")
            
    try:
        df['PURCHASE_'] = pd.to_datetime(df['PURCHASE_'], format='%d-%b-%y', errors='coerce')
        df['PURCHASE_'] = df['PURCHASE_'].dt.date
    except Exception as e:
        print(f"Error converting PURCHASE_ to datetime: {e}")
    
    return df


# Flask routes
@app.route('/')
def home():
    if 'user' in session:
        return render_template('index.html', user=session['user'])
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        result = register_user(username, email, password)
        return result
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        result = login_user(email, password)
        if "Login successful!" in result:
            session['user'] = email
            return redirect('/')
        return result
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    return render_template('dashboard.html', user=session['user'])

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

# Route for searching and sorting
@app.route('/datapull', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        # Get the search query from user input
        hshd_num = request.form.get('hshd_num')
        sort_by = request.form.get('sort_by')
        
        # Read combined data from CSV
        combined_data = read_data_from_blob('combined_data.csv')
    
        # Filter data based on HSHD_NUM
        filtered_data = combined_data[combined_data['HSHD_NUM'] == int(hshd_num)]

        if filtered_data.empty:
            return f"No data found for HSHD_NUM: {hshd_num}"

        # Sort data based on the selected column
        if sort_by:
            filtered_data = filtered_data.sort_values(by=sort_by)

        # Convert filtered and sorted data to a list of dictionaries to pass to template
        results = filtered_data.to_dict(orient='records')
        
        return render_template('datapull.html', results=results, hshd_num=hshd_num)

    return render_template('search.html')

@app.route('/ndatapull', methods=['GET', 'POST'])
def new_search():
    if request.method == 'POST':
        # Get the search query from user input
        hshd_num = request.form.get('hshd_num')
        sort_by = request.form.get('sort_by')
        
        # Read the newly merged data (new_combined_data.csv) from the local storage
        merged_data_path = os.path.join(UPLOAD_FOLDER, 'new_combined_data.csv')
        
        if not os.path.exists(merged_data_path):
            return "No data found. Please upload the necessary files first."
        
        merged_data = pd.read_csv(merged_data_path)
    
        # Filter data based on HSHD_NUM
        filtered_data = merged_data[merged_data['HSHD_NUM'] == int(hshd_num)]

        if filtered_data.empty:
            return f"No data found for HSHD_NUM: {hshd_num}"

        # Sort data based on the selected column
        if sort_by:
            filtered_data = filtered_data.sort_values(by=sort_by)

        # Convert filtered and sorted data to a list of dictionaries to pass to template
        results = filtered_data.to_dict(orient='records')
        
        return render_template('ndatapull.html', results=results, hshd_num=hshd_num)

    return render_template('nsearch.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload_data():
    if request.method == 'POST':
        # Check for files
        household_file = request.files.get('household_file')
        transaction_file = request.files.get('transaction_file')
        product_file = request.files.get('product_file')

        if not (household_file and transaction_file and product_file):
            return "One or more files are missing. Please upload all files."

        # Secure filenames
        household_filename = secure_filename(household_file.filename)
        transaction_filename = secure_filename(transaction_file.filename)
        product_filename = secure_filename(product_file.filename)

        # Define the local file paths where the files will be saved
        household_file_path = os.path.join(app.config['UPLOAD_FOLDER'], household_filename)
        transaction_file_path = os.path.join(app.config['UPLOAD_FOLDER'], transaction_filename)
        product_file_path = os.path.join(app.config['UPLOAD_FOLDER'], product_filename)

        # Save the files locally
        household_file.save(household_file_path)
        transaction_file.save(transaction_file_path)
        product_file.save(product_file_path)

        try:
            # Read the files into pandas DataFrames
            household_df = pd.read_csv(household_file_path)
            transaction_df = pd.read_csv(transaction_file_path)
            product_df = pd.read_csv(product_file_path)

            # Strip leading and trailing whitespace from column names
            household_df.columns = household_df.columns.str.strip()
            transaction_df.columns = transaction_df.columns.str.strip()
            product_df.columns = product_df.columns.str.strip()

            # Merge the DataFrames on relevant columns (e.g., HSHD_NUM, PRODUCT_NUM)
            merged_data = transaction_df.merge(household_df, on="HSHD_NUM", how="left")\
                                        .merge(product_df, on="PRODUCT_NUM", how="left")
                                        
            # Convert the PURCHASE_ column to datetime format
            merged_data['PURCHASE_'] = pd.to_datetime(merged_data['PURCHASE_'], format='%d-%b-%y', errors='coerce')
            merged_data['PURCHASE_'] = merged_data['PURCHASE_'].dt.date

            # Save the merged data into a new CSV file locally
            merged_filename = os.path.join(app.config['UPLOAD_FOLDER'], 'new_combined_data.csv')
            merged_data.to_csv(merged_filename, index=False)
            
            success_message = (
                f"Files uploaded and linked successfully! "
                f"<a href='/ndatapull'>Data Pulls On New Data</a>"
            )

            return success_message
        

        except Exception as e:
            return f"An error occurred while processing the files: {e}"

    return render_template('upload.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000) 
