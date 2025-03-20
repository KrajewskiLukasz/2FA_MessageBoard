# 🔒 SecureMessageApp  
![obraz](https://github.com/user-attachments/assets/7e993519-1089-4c29-84b4-91041dbffbde)

A secure Flask-based web application that allows users to **register, log in, and post signed messages**. The project focuses on **security**, including **password hashing, two-factor authentication (2FA), and message integrity verification**.  

---
## 🐳 Running SecureMessageApp with Docker  

You can containerize and run this application using **Docker** and **Docker Compose** for a seamless deployment.    

### 1️⃣ Build and Start the Containers  
```bash
docker-compose up --build
```
---
## 🚀 Features  

✅ **User Authentication & Security**  
- User **registration and login** with **hashed passwords** (**Flask-Bcrypt**)  
- **Two-Factor Authentication (2FA)** with TOTP/HOTP 
- **CSRF protection** enabled  

✅ **Messaging System**  
- Users can **create and view signed messages**  
- Messages contain **digital signatures** for verification  
- **SQLite database** for storing user credentials and messages  

✅ **Robust Form Validation**  
- **Strong password policy** (uppercase, lowercase, digit, special character)  
- Email and username **uniqueness checks**  
- Flash messages for **user feedback**  

✅ **Modern Tech Stack**  
## 🖥️ Frontend  
- **HTML, CSS, JavaScript** – for the user interface and interactivity  

## ⚙️ Backend  
- **Flask** – lightweight Python web framework  
- **Flask-Login** – session management and user authentication  
- **bcrypt** – password hashing for enhanced security  
- **PyOTP** – implementing Two-Factor Authentication (TOTP)  

## 🛡 Security & Storage  
- **Flask-WTF** – CSRF protection to prevent attacks  
- **SQLite** – lightweight relational database for data storage  
- **Nginx** – web server to serve the application securely  

## 🎨 How This App Looks Like  

Below are some screenshots showcasing the interface and functionality of **SecureMessageApp**.  

### 🔐 Login Page  
Users can securely log in using their credentials.  
![obraz](https://github.com/user-attachments/assets/75d5c892-20da-4f70-88d9-7bc0b2bac0cf)

### 📝 Registration Page  
New users can create an account with strong password validation.  
![obraz](https://github.com/user-attachments/assets/c1f86bee-b391-49f3-8319-6f401ac224c1)


### 📨 Messages Dashboard  
Users can create and view signed messages securely.  
![obraz](https://github.com/user-attachments/assets/0902bf9c-c917-49cd-9515-7e389e824838)


### 🔑 Two-Factor Authentication (2FA)  
Enhanced security with TOTP-based authentication.  
![obraz](https://github.com/user-attachments/assets/23f0a6a8-c79f-43f6-adf0-51fb96b48df1)


---
