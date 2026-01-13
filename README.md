the app folder is from the android project folder

compile server using
g++ -lssl -lcrypto server.cpp -o server

Server expects privkey.pem and fullchain.pem in its working directories, these need to be CA signed and not self signed or else the app will not be able to contact the server.
