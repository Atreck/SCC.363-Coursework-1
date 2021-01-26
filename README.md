# SCC.363-Coursework-1
A third year Computer Science coursework to implement varying degrees of security and functionality to a registration/login system in a medical environment.

## Usage
To use in its current state, you must have 3 terminals open (2 if using included shell script)

- Open 3(2) terminals and navigate all to the src dir
```
cd .\src\
```
- Type ```rmiregistry``` or start the shell script.
- On another terminal, compile and run the server (commands vary depending on OS and version) this is for Java 13.0.1 on Windows 10
```java
javac -cp "lib/*;." *.java;& java -cp "lib/*;." Server
```
- On the last terminal, compile and run the frontend
```java
javac -cp "lib/*;." *.java;& java -cp "lib/*;." Main
```

## Two-Factor Authentication Testing
A 2FA service is optional when registering. Two dummy accounts have been set up with it enabled. In order to login, the Time-based One Time Password must be entered. The details of the dummy accounts are currently:

Username: ```admin```
Password: ```password```
Key: ```BGLBEVX44CZC45IOAQI3IFJBDBEOYY3A```

Username: ```testUser```
Password: ```MyPassword#3456```
Key: ```MAAULT5OH5P4ZAW7JC5PWJIMZZ7VWRNU```

### TOTP Usage
To get the TOTP codes, follow the instructions:

- Download an authenticator application on your phone (Google Authenticator works well).
- Enter the key for the listed account.
- A 6-digit code will cycle every few seconds, enter that when prompted on the login.

*TODO: Access via QR code*
