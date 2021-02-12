# SCC.363-Coursework-1
A third year Computer Science coursework to implement varying degrees of security and functionality to a registration/login system in a medical environment.

## Usage
To operate the system, a Windows 10 machine running JDK 13.0 is recommended.

### Automated
To automatically run the system, try and run the "run.bat" file from the main directory. 3 windows will pop up. If the login screen does not appear after 5 seconds (delay was added to ensure proper runtime), close all the terminal and try again.

### Manual
For manual compilation and running, you must have 3 terminals open (2 if using included shell script). All of them must either be opened in the src/ folder or by typing ```cd ./src/``` in the terminal. 

Console 1:
- Compile and run the registry or start the shell script.
```java
javac -cp "./lib/*;." main/*.java ;& rmiregistry
``` 

Console 2:
- Compile and run the server (commands vary depending on OS and version) this is for Java 13.0.1 on Windows 10
```java
java -cp "./lib/*;." main/Server
```

Console 3:
- Compile and run the frontend
```java
java -cp "./lib/*;." main/Main
```

## Two-Factor Authentication Testing
A 2FA service is optional when registering. Two dummy accounts have been set up with it enabled. In order to login, the Time-based One Time Password must be entered. The details of the dummy accounts are currently:

Username: ```admin```
Password: ```superUser89@pass```
Key: ```BGLBEVX44CZC45IOAQI3IFJBDBEOYY3A```

![admin QR Code](admin.png)

Username: ```testUser```
Password: ```MyPassword#3456```
Key: ```MAAULT5OH5P4ZAW7JC5PWJIMZZ7VWRNU```

![testUser QR Code](testUser.png)

### TOTP Usage
Now a QR code will be displayed when an account is newly registered. These can be scanned by any authenticator app for ease of access.

Alternatively, to use the TOTP codes, follow the instructions:

- Download an authenticator application on your phone (Google Authenticator works well).
- Enter the key for the listed account.
- A 6-digit code will cycle every few seconds, enter that when prompted on the login.

## Permissions and Logs Testing

Log in normally either as an Admin or Patient with the credentials provided above or as someone else with the credentials listed below:

Register as a: ```Doctor```<br>
Username: ```jsmith24```<br>
Password: ```changemeplease```<br>
Key: ```none```

Register as a: ```Nurse```<br>
Username: ```katewins678```<br>
Password: ```carrots%23Apps```<br>
Key: ```XUTWHKIO7IDSIP6EW5OTABC2ZM3XERGS```

![katewins678 QR code](katewins678_QRcode.png)

Register as a: ```Receptionist```<br>
Username: ```ahopkins15```<br>
Password: ```hopDrop%Bom12```<br>
Key: ```MQ52WMF4JQYV2FSLHB6AVFDDDBQPZVUO```

![ahopkins15 QR code](ahopkins15_QRcode.png)

Follow the on-screen instructions to invoke different actions, such as:

- see group permissions
  <br>go to [RecordsUtil.java](src/main/RecordsUtil.java) to see mappings between numerical values to their human-readable form
- update group permissions (as above)
- get user's/ patient's records
- update user's/ patient's records
- assign a user to a group

And see what you are allowed/ not allowed to do.
