# Confidential-and-Integrity-Conversation-Program

This program is basically a secured conversation between server and client. Where Server is being initialized first where it is creating a object which is storing a secret key of a AES cyptography which is a type of symmetric key cryptography.

Now, We'll be initializing program for client where it will first create a Key pair for RSA which is a type of public key cryptography. Then client will send it's public key to the server where server will encrypt it's secret key with RSA cryptography and sent it to client where client will decrypt it with his private key. The last operation can also be understood like a handshake where secured connection has been established both the client and server have the private through which they will use communicate between each other. Here in the program for the integrity check we will send two things together one will be the message to be sent either from client or server and hash value for the encrypted message and after receiving the message the receiver will again calculate the hash value and check with the sent hash value. If the hash value  doesn't gets matched, then the reciever will break the connection or if it gets matched then program will continue to work normally till anyone send "EXIT".
