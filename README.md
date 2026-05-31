# VoteChain — Secure Online Voting System

VoteChain is a high-security, end-to-end encrypted online voting platform built with Flask and Firebase. It leverages modern cryptographic techniques to ensure voter anonymity, vote integrity, and tamper-proof results.

## 🚀 Tech Stack

### Backend
- **Framework**: [Flask](https://flask.palletsprojects.com/) (Python 3.x)
- **Database**: [Firebase Firestore](https://firebase.google.com/docs/firestore) (NoSQL)
- **Authentication**: Firebase Admin SDK, JWT (JSON Web Tokens)
- **Email Service**: Gmail SMTP / [Resend](https://resend.com/) (for OTP delivery)

### Security & Cryptography
- **Encryption Scheme**: `ECDH-AES256-GCM`
- **Key Exchange**: Elliptic Curve Diffie-Hellman (ECDH) using `SECP256R1`
- **Encryption**: AES-256-GCM for voter ballot encryption
- **Anonymity**: RSA Blind Signatures for voter authorization
- **Integrity**: Deterministic Nullifiers to prevent double voting without revealing voter identity
- **Hashing**: Bcrypt for secure OTP storage

### Frontend
- **Architecture**: Single Page Application (SPA)
- **Languages**: Vanilla JavaScript (ES6+), HTML5, CSS3
- **Security**: Client-side encryption of ballots before transmission

---

## ✨ Key Features

- **End-to-End Encryption (E2EE)**: Votes are encrypted on the voter's device and can only be decrypted by the election's private key during tallying.
- **Anonymous Voting**: Cryptographic nullifiers ensure a voter can only vote once per poll without linking their identity to their vote.
- **Flexible Poll Categories**:
  - **State Elections**: Verified via registered state.
  - **Corporate Voting**: Verified via company ownership/shares.
  - **Parliamentary Sessions**: Verified via MP chamber (Lok Sabha/Rajya Sabha).
- **Identity Verification**: Integrated support for Aadhaar and Decentralized Identifiers (DID).
- **Two-Factor Authentication (2FA)**: Secure registration and login via Email OTP.
- **Admin Dashboard**: Secure interface for creating polls, managing categories, and monitoring live results.
- **Automated Expiry**: Polls automatically close and move to tallying state based on pre-defined timestamps.

---

## 🛠️ Getting Started

### Prerequisites
- Python 3.8+
- Firebase Project Service Account Key (`serviceAccountKey.json`)

### Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd "Voting System"
   ```

2. **Set up Virtual Environment**:
   ```bash
   # Windows
   python -m venv env_win
   .\env_win\Scripts\activate

   # Linux/macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**:
   Create a `.env` file in the root directory:
   ```env
   FLASK_ENV=development
   SECRET_KEY=your_secret_key
   ADMIN_SECRET_CODE=your_admin_registration_code
   FIREBASE_CREDENTIALS_PATH=serviceAccountKey.json
   GMAIL_USER=your-email@gmail.com
   GMAIL_APP_PASSWORD=your-app-password
   PORT=5000
   ```

### Running the App

**Development**:
```bash
python app.py
```
The app will be available at `http://localhost:5000`.

**Production**:
```bash
gunicorn app:app --bind 0.0.0.0:8000 --workers 4
```

---

## 📂 Project Structure

- `app.py`: Main entry point and Flask application factory.
- `auth.py`: Authentication routes (Registration, OTP, Identity Verification).
- `polls.py`: Poll management (Creation, Listing, Expiry).
- `votes.py`: Secure voting logic and cryptographic verification.
- `models.py`: Dataclasses for Users, Polls, Votes, and OTPs.
- `encryption.py`: Cryptographic primitives for E2EE and Blind Signatures.
- `middleware.py`: JWT authentication and RBAC decorators.
- `frontend/`: Static assets (HTML, CSS, Client-side JS).

---

## 🔒 Security Architecture

VoteChain implements a "Zero Trust" model for ballots:
1. **Blinding**: The voter blinds their ballot and gets it signed by the server (Blind Signature).
2. **Encryption**: The choice is encrypted using the Poll's Public Key (ECDH).
3. **Submission**: The encrypted ballot and signature are submitted. The server verifies the signature without knowing who the voter is.
4. **Tallying**: Only when the poll closes can the Election Private Key be used to decrypt and count votes.
