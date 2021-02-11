@echo off

start cmd /k "cd src & javac -cp "./lib/*;." main/*.java & rmiregistry"
timeout /NOBREAK 2
start cmd /k "cd src & java -cp "./lib/*;." main/Server"
timeout /NOBREAK 3
start cmd /k "cd src & java -cp "./lib/*;." main/Main"