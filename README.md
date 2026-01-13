place all files in an app folder in android studio project folder. e.g. /home/user/AndroidStudioProjects/decentbond/app/
open in android studio

compile server using
g++ -lssl -lcrypto server.cpp -o server

Server expects privkey.pem and fullchain.pem in its working directories, these need to be CA signed and not self signed or else the app will not be able to contact the server.

Server usage in linux is './server -h <serverIP> -p 443' . May need sudo to bind to port 443. 
