# Java socket communication

This is the java program to let user communicate with other user in the system through server.
After user logged into the system, client will send hashed userid to the server and check whether
there is any incoming message to this userid or not. Then, the client ask user whether they want to 
send message to other user or not. When sending message to other, client gathers input from user which
are recipient user id and the message. Next, client generate the encrypted message using RSA and 
signature then send to server. After server get the message, it will verify the signature and store in
array in order to send to other user in the future.

## Installation
# require java 17.0.10 2024-01-16 LTS or other compatible version
git clone https://github.com/tanajan/java_socket_communication.git

## Usage

``` Java
# Generate userid and Server private and public key
java RSAKeyGen.java server
java RSAKeyGen.java [userid]

# Run server
java Server.java [port_number]

# Run client
java Client.java localhost [port_number] [user_id]

```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.
