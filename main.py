# K3rnel - a decentralized chat communication network/protocol
# Developed by Arslaan Pathan - xminecrafterfun@gmail.com
from typing import Any

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
        self.invalid_usernames = ["type"]

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
            self.sendLine(
                json.dumps({"type": "connRefused", "reason": "Your client has sent invalid or malformed JSON."}).encode(
                    'utf-8'))
            self.transport.loseConnection()
            return
        try:
            if jsonData["type"] == "setUsername":
                username = jsonData["username"]

                # Check if username is already taken
                if username.lower() in {data["username"].lower() for data in self.clients.values()}:
                    self.sendLine(json.dumps({"type": "connRefused",
                                              "reason": "You are logged in on another device. Log out or close K3rnel on your other device to continue here."}).encode(
                        'utf-8'))
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
                    self.sendLine(
                        json.dumps({"type": "connRefused", "reason": "Username already taken"}).encode('utf-8'))
                    self.transport.loseConnection()
                    return
                if username.lower() in self.invalid_usernames:
                    self.sendLine(json.dumps({"type": "connRefused", "reason": "Username not allowed"}).encode('utf-8'))
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
                    self.sendLine(
                        json.dumps({"type": "connRefused", "reason": "The user specified does not exist."}).encode(
                            'utf-8'))
                    self.transport.loseConnection()
                    return

                if self.userAuth[username] != hashedKey:
                    self.sendLine(
                        json.dumps({"type": "connRefused", "reason": "The private key is incorrect."}).encode('utf-8'))
                    self.transport.loseConnection()
                    return

                self.clients[peer]["authenticated"] = True
                print(f"Client with username {username} has been authenticated!")
                filtered_friends_list = self.filter_dict(self.friends, ["type", username])
                self.sendLine(json.dumps(filtered_friends_list).encode('utf-8'))
                print(f"Sent friends JSON to client with username {username}.")
            if jsonData["type"] == "friendRequest":
                peer = self.transport.getPeer()

                if not self.clients[peer]["authenticated"]:
                    self.sendLine(
                        json.dumps({"type": "connRefused", "reason": "You are not authenticated yet."}).encode('utf-8'))
                    self.transport.loseConnection()
                    return

                username = self.clients[peer]["username"]
                to = jsonData["to"]

                if to == username:
                    self.sendLine(
                        json.dumps({"type": "refused", "reason": "You cannot friend yourself."}).encode('utf-8'))

                target_client = self.getClientByUsername(to)
                if target_client:
                    target_client["client"].sendLine(json.dumps({
                        "type": "friendRequest",
                        "from": username
                    }).encode('utf-8'))

                if to not in self.friends:
                    self.friends[to] = []
                self.friends[to].append({username: "incoming"})
                self.friends[username].append({to: "outgoing"})
                with open("data/friends.json", "w") as friendsFile:
                    friendsFile.write(json.dumps(self.friends))
                print(f"Friend request sent from {username} to {to}!")
            if jsonData["type"] == "friendRequestAccept":
                peer = self.transport.getPeer()

                if not self.clients[peer]["authenticated"]:
                    self.sendLine(json.dumps({"type": "connRefused",
                                              "reason": "You are not authenticated yet."}).encode(
                        'utf-8'))
                    self.transport.loseConnection()
                    return

                username = self.clients[peer]["username"]
                to = jsonData["to"]

                if to not in self.friends[username] or username not in self.friends[to]:
                    self.sendLine(json.dumps({"type": "refused",
                                              "reason": "A friend request was never sent to or by the following person."}).encode(
                        'utf-8'))

                target_client = self.getClientByUsername(to)
                if target_client:
                    target_client["client"].sendLine(json.dumps({
                        "type": "friendRequestAccept",
                        "from": username
                    }).encode('utf-8'))
                self.friends[to][username] = "friend"
                self.friends[username][to] = "friend"
                print(f"Friend request accepted from {username} to {to}!")
            if jsonData["type"] == "friendRequestDeny":
                peer = self.transport.getPeer()

                if not self.clients[peer]["authenticated"]:
                    self.sendLine(json.dumps({"type": "connRefused",
                                              "reason": "You are not authenticated yet."}).encode(
                        'utf-8'))
                    self.transport.loseConnection()
                    return

                username = self.clients[peer]["username"]
                to = jsonData["to"]

                if to not in self.friends[username] or username not in self.friends[to]:
                    self.sendLine(json.dumps({"type": "refused",
                                              "reason": "A friend request was never sent to or by the following person."}).encode(
                        'utf-8'))

                target_client = self.getClientByUsername(to)
                if target_client:
                    target_client["client"].sendLine(json.dumps({
                        "type": "friendRequestDeny",
                        "from": username
                    }).encode('utf-8'))
                del self.friends[to][username]
                del self.friends[username][to]
                print(f"Friend request denied from {username} to {to}.")
        except ValueError:
            self.sendLine(json.dumps({"type": "connRefused", "reason": "Some arguments are missing"}).encode('utf-8'))
            self.transport.loseConnection()
            return

    def getClientByUsername(self, username) -> dict | None:
        for peer, client_data in self.clients.items():
            if client_data["username"] and client_data["username"].lower() == username.lower():
                return client_data
        return None

    def filter_dict(self, data: dict, keys: list) -> dict:
        new_dict = {}
        for key in keys:
            new_dict[key] = data.get(key)
        return new_dict


class ChatFactory(protocol.Factory):
    def __init__(self):
        self.clients = {}

        if os.path.exists("data/authentication.json"):
            with open("data/authentication.json", "r") as authFile:
                self.userAuth = json.loads(authFile.read())
        else:
            self.userAuth = {}
            if not os.path.exists("data"):
                os.mkdir("data")
            with open("data/authentication.json", "w") as authFile:
                authFile.write("{}")

        if os.path.exists("data/friends.json"):
            with open("data/friends.json", "r") as friendsFile:
                self.friends = json.loads(friendsFile.read())
        else:
            self.friends = {"type": "friends"}
            if not os.path.exists("data"):
                os.mkdir("data")
            with open("data/friends.json", "w") as friendsFile:
                friendsFile.write("{}")

    def buildProtocol(self, addr) -> ChatProtocol:
        return ChatProtocol(self.clients, self.userAuth, self.friends)


def main():
    # Start the server on port 5380
    endpoint = TCP4ServerEndpoint(reactor, 5380)
    endpoint.listen(ChatFactory())
    print("K3rnel server running on port 5380")
    reactor.run()


if __name__ == "__main__":
    main()
