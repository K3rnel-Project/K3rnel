# K3rnel - a decentralized chat communication network/protocol
# Developed by Arslaan Pathan - xminecrafterfun@gmail.com
from twisted.internet import ssl, reactor
from twisted.protocols.basic import LineReceiver
from twisted.internet import protocol
from autobahn.twisted.websocket import WebSocketServerProtocol, WebSocketServerFactory
import json


# TCP client to relay messages from WebSocket to TCP chat server
class TCPChatClientProtocol(LineReceiver):
    def __init__(self, ws_protocol):
        self.ws_protocol = ws_protocol

    def connectionMade(self):
        print("Connected to the TCP chat server.")

    def lineReceived(self, data):
        print(f"Received from TCP server: {data.decode('utf-8').strip()}")
        # Relay messages from the TCP server to the WebSocket client
        try:
            self.ws_protocol.sendMessage(data.encode('utf-8') if isinstance(data, str) else data)
        except Exception as e:
            print(f"Error relaying data to WebSocket: {e}")

    def connectionLost(self, reason):
        print("Connection to TCP chat server lost.")
        if self.ws_protocol:
            self.ws_protocol.sendClose()


# Factory to create TCP client protocol instances
class TCPChatClientFactory(protocol.ClientFactory):
    def __init__(self, ws_protocol):
        self.ws_protocol = ws_protocol

    def buildProtocol(self, addr):
        protocol_instance = TCPChatClientProtocol(self.ws_protocol)
        self.ws_protocol.setTCPClient(protocol_instance)
        return protocol_instance

    def clientConnectionFailed(self, connector, reason):
        print(f"Connection to TCP server failed: {reason}")
        if self.ws_protocol:
            self.ws_protocol.sendClose()


# WebSocket Protocol to handle WebSocket communication
class WebSocketChatProtocol(WebSocketServerProtocol):
    def onConnect(self, request):
        print(f"WebSocket client connected: {request.peer}")
        # Connect to the TCP chat server
        reactor.connectTCP("localhost", 5380, TCPChatClientFactory(self))

    def onMessage(self, payload, isBinary):
        print(f"Received from WebSocket client: {payload.decode('utf-8') if not isBinary else '[binary data]'}")

        # Check if the TCP client is connected
        if hasattr(self, 'tcp_client'):
            try:
                message = payload.decode('utf-8') if not isBinary else payload
                if isinstance(message, str):
                    message = message.strip()
                self.tcp_client.sendLine(message.encode('utf-8') if isinstance(message, str) else message)
                print(f"Sent to TCP server: {message.strip()}")
            except Exception as e:
                print(f"Error relaying WebSocket message to TCP server: {e}")
        else:
            print("TCP client not yet connected, message not sent.")
            self.sendMessage(json.dumps({"type": "error", "message": "Not connected to TCP server"}).encode('utf-8'))

    def setTCPClient(self, tcp_client):
        self.tcp_client = tcp_client

    def onClose(self, wasClean, code, reason):
        print(f"WebSocket connection closed: {reason}")
        if hasattr(self, 'tcp_client') and self.tcp_client.transport:
            self.tcp_client.transport.loseConnection()


# WebSocket factory that handles the creation of WebSocketChatProtocol
class WebSocketChatFactory(WebSocketServerFactory):
    protocol = WebSocketChatProtocol


def main():
    # Specify the paths to your SSL certificate and private key
    cert_path = 'ssl/server.crt'
    key_path = 'ssl/server.key'

    # Create an SSL context using the Certificate object
    context = ssl.DefaultOpenSSLContextFactory(key_path, cert_path)

    # Start the WebSocket server on port 5381 using SSL
    ws_factory = WebSocketChatFactory("wss://localhost:5381")
    reactor.listenSSL(5381, ws_factory, context)
    print("WebSocket bridge running on wss://localhost:5381")
    reactor.run()


if __name__ == "__main__":
    main()
