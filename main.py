# K3rnel - a decentralized chat communication network/protocol
# Developed by Arslaan Pathan - xminecrafterfun@gmail.com
from twisted.protocols.basic import LineReceiver
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import protocol, reactor
import json
import os


class ChatProtocol(LineReceiver):
    def __init__(self, clients: dict, user_auth: dict):
        self.clients = clients
        self.userAuth = user_auth

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
        # TODO: Add the actual messaging functionality
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
        except ValueError:
            self.sendLine(json.dumps({"type": "connRefused", "reason": "Some arguments are missing"}).encode('utf-8'))
            self.transport.loseConnection()
            return


class ChatFactory(protocol.Factory):
    def __init__(self):
        # This will hold references to all the connected clients
        self.clients = {}
        if os.path.exists("data/authentication.json"):
            with open("data/authentication.json", "r") as authFile:
                self.userAuth = json.loads(authFile.read())

        else:
            self.userAuth = {}
            with open("data/authentication.json", "w") as authFile:
                authFile.write("{}")

    def buildProtocol(self, addr):
        # This method is called for every new connection
        # It returns an instance of ChatProtocol
        return ChatProtocol(self.clients, self.userAuth)


def main():
    # Start the server on port 5380
    endpoint = TCP4ServerEndpoint(reactor, 5380)
    endpoint.listen(ChatFactory())
    print("K3rnel server running on port 5380")
    reactor.run()


if __name__ == "__main__":
    main()
