# Tanzania E-Service 2FA Prototype

## Overview

A Flask-based TOTP 2FA prototype to combat e-service account takeovers in Tanzania, compliant with the Data Protection Act.
It is assumed under the app Tanzania E-Services Portal, which has a custom details as below:
email: tanzaniaeservicesportal@gmail.com
password for the email: Security123\*\*

## Setup

1. Clone the repository:
   git clone git@github.com:kenethkingu/tanzania-2fa-prototype.git
   cd tanzania-2fa-prototype

2. Create a virtual environment:
   python3 -m venv venv

   source venv/bin/activate (In MacOS or Ubuntu)
   venv\Scripts\activate.bat (In Windows CMD)
   .\venv\Scripts\Activate.ps1 (In Windows Powershell)

3. Install dependencies:
   pip install -r requirements.txt

4. Create a .env file:
   FLASK_SECRET_KEY=your-secure-secret-key
   AES_KEY=$(openssl rand -base64 32)

5. Run the app:
   python3 app.py

6. Visit https://localhost:5000 (accept the SSL warning).
