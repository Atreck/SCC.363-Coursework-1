@echo off

start cmd /k "cd src & javac -d "classes" -cp "lib/*;." main/*.java & cd classes & rmiregistry"
timeout /NOBREAK 2
start cmd /k "cd src/classes & java -cp "lib/*;." main/Server"
timeout /NOBREAK 2
start cmd /k "cd src/classes & java -cp "lib/*;." main/GUI"