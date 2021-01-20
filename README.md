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
