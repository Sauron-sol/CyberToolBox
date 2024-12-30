# 2FA Generator 🔐

A modern and secure 2FA code manager with web interface. This application allows you to manage your two-factor authentication codes in a centralized way.

## Features

- 📱 TOTP (Time-based One-Time Password) code generation
- 🎥 QR code scanning via webcam
- 📂 QR code import via image files
- 💾 Secure storage of secrets in SQLite database
- ⏱️ Visual progress bar for timing
- 🔄 Automatic code refresh
- 🎨 Modern and responsive user interface

## Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- Webcam for QR code scanning (optional)

## Installation

1. Clone the repository:
```bash
git clone <repo-url>
cd 2fa-generator
```

2. Install dependencies:
```bash
npm install
```

3. Launch the application:
```bash
npm start
```

4. Open your browser at: `http://localhost:3001`

## Usage

### Adding a 2FA Account

Two methods are available:

1. **Camera Scanning**:
   - Click on "Scan with Camera"
   - Allow camera access
   - Present the QR code to scan

2. **Image Import**:
   - Click on "Upload Image"
   - Drag and drop your image or click to select

### Account Management

- Codes are automatically updated
- A progress bar indicates remaining time
- Use the "Delete" button to remove an account

## Security

- Secrets are securely stored in a SQLite database
- No data is sent to external servers
- The application runs entirely locally

## Development

Project structure:
```
2fa-generator/
├── index.js         # Express server
├── public/          # Frontend
│   └── index.html   # User interface
├── accounts.db      # SQLite database
└── package.json     # Dependencies
```

## Technologies Used

- Frontend: HTML5, CSS3, JavaScript (Vanilla)
- Backend: Node.js, Express
- Database: SQLite
- Libraries: otplib, html5-qrcode, QRCode.js

