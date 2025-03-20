# 🔒 SecureMessageApp  
![obraz](https://github.com/user-attachments/assets/7e993519-1089-4c29-84b4-91041dbffbde)

A secure Flask-based web application that allows users to **register, log in, and post signed messages**. The project focuses on **security**, including **password hashing, two-factor authentication (2FA), and message integrity verification**.  

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
- **Flask** (Python) for backend  
- **Flask-WTF** for secure forms  
- **Flask-SQLAlchemy** for database management  
- **Docker support** for easy deployment

---
