# K3rnel - a decentralized chat communication network/protocol
# Developed by Arslaan Pathan - xminecrafterfun@gmail.com
from twisted.protocols.basic import LineReceiver
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import protocol, reactor
import json
import os


class ChatProtocol(LineReceiver):
    def __init__(self, clients: dict, auth: dict, friends: dict):
        self.clients = clients
        self.userAuth = auth
        self.friends = friends

    def connectionMade(self):
        peer = self.transport.getPeer()
        print(f"New client connected: {peer}")
        self.clients[peer] = {"client": self, "username": None, "authenticated": False}
        # self.sendLine(b"K3rnel Server v1.0.0 - Developed by Arslaan Pathan")

    def connectionLost(self, reason):
        peer = self.transport.getPeer()
        print(f"Client disconnected: {peer}")
        if peer in self.clients:
            del self.clients[peer]

    def lineReceived(self, line):
        # TODO: Add friending functionality
        # TODO: Add the actual messaging functionality - format: {"type": "sendMessage", "to": "username", "publicKey": "<public key of sender>"} - no "from" field to prevent sending messages on behalf of others
        print(f"Received: {line}")
        try:
            jsonData = json.loads(line.decode('utf-8'))
        except json.JSONDecodeError:
            self.sendLine(json.dumps({"type": "connRefused", "reason": "Your client has sent invalid or malformed JSON."}).encode('utf-8'))
            self.transport.loseConnection()
            return
        try:
            if jsonData["type"] == "setUsername":
                username = jsonData["username"]

                # Check if username is already taken
                if username.lower() in {data["username"].lower() for data in self.clients.values()}:
                    self.sendLine(json.dumps({"type": "connRefused", "reason": "You are logged in on another device. Log out or close K3rnel on your other device to continue here."}).encode('utf-8'))
                    self.transport.loseConnection()
                    return

                # Assign username to this client
                peer = self.transport.getPeer()

                if self.clients[peer]["authenticated"]:
                    self.sendLine(json.dumps({"type": "connRefused",
                                              "reason": "You are already authenticated. Stop hacking."}).encode(
                        'utf-8'))
                    self.transport.loseConnection()
                    return

                self.clients[peer]["username"] = username

                print(f"Client set username: {username}")
                print(self.clients)

            if jsonData["type"] == "authAndSetPrivateKey":
                # Private keys are hashed with SHA-256 on the client-side
                hashedKey = jsonData["privateKey"]
                peer = self.transport.getPeer()
                username = self.clients[peer]["username"]

                if username.lower() in {user.lower() for user in self.userAuth.keys()}:
                    self.sendLine(json.dumps({"type": "connRefused", "reason": "Username already taken"}).encode('utf-8'))
                    self.transport.loseConnection()
                    return

                self.userAuth[username] = hashedKey
                with open("data/authentication.json", "w") as authFile:
                    authFile.write(json.dumps(self.userAuth))
                self.clients[peer]["authenticated"] = True
                print(f"Client with username {username} has been authenticated!")

            if jsonData["type"] == "authWithPrivateKey":
                # Private keys are hashed with SHA-256 on the client-side
                hashedKey = jsonData["privateKey"]
                peer = self.transport.getPeer()
                username = self.clients[peer]["username"]

                if username not in self.userAuth.keys():
                    self.sendLine(json.dumps({"type": "connRefused", "reason": "The user specified does not exist."}).encode('utf-8'))
                    self.transport.loseConnection()
                    return

                if self.userAuth[username] != hashedKey:
                    self.sendLine(json.dumps({"type": "connRefused", "reason": "The private key is incorrect."}).encode('utf-8'))
                    self.transport.loseConnection()
                    return

                self.clients[peer]["authenticated"] = True
                print(f"Client with username {username} has been authenticated!")
            if jsonData["type"] == "friendRequest":
                peer = self.transport.getPeer()

                if not self.clients[peer]["authenticated"]:
                    self.sendLine(json.dumps({"type": "connRefused",
                                              "reason": "You are not authenticated yet."}).encode(
                        'utf-8'))
                    self.transport.loseConnection()
                    return

                username = self.clients[peer]["username"]
                to = jsonData["to"]
                # TODO: Check if the user to send the request to is on the server, if yes, send a message with a friend request and add to the JSON file, if no, add to the JSON file.
                # TODO: When a user logs in, send them the JSON of all friend requests.
        except ValueError:
            self.sendLine(json.dumps({"type": "connRefused", "reason": "Some arguments are missing"}).encode('utf-8'))
            self.transport.loseConnection()
            return


class ChatFactory(protocol.Factory):
    def __init__(self):
        # This holds references to all the connected clients
        self.clients = {}

        # This holds all the user authentication data
        if os.path.exists("data/authentication.json"):
            with open("data/authentication.json", "r") as authFile:
                self.userAuth = json.loads(authFile.read())
        else:
            self.userAuth = {}
            if not os.path.exists("data"):
                os.mkdir("data")
            with open("data/authentication.json", "w") as authFile:
                authFile.write("{}")

        # This holds the friends of all the users
        if os.path.exists("data/friends.json"):
            with open("data/friends.json", "r") as friendsFile:
                self.friends = json.loads(authFile.read())
        else:
            self.friends = {}
            if not os.path.exists("data"):
                os.mkdir("data")
            with open("data/friends.json", "w") as friendsFile:
                friendsFile.write("{}")

    def buildProtocol(self, addr):
        # This method is called for every new connection
        # It returns an instance of ChatProtocol
        return ChatProtocol(self.clients, self.userAuth, self.friends)


def main():
    # Start the server on port 5380
    endpoint = TCP4ServerEndpoint(reactor, 5380)
    endpoint.listen(ChatFactory())
    print("K3rnel server running on port 5380")
    reactor.run()


if __name__ == "__main__":
    main()
