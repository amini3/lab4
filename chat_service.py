#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time

########################################################################
# Echo Server class
########################################################################

CMD_FIELD_LEN =1
IP_ADDR_LEN =15
IP_PORT_LEN =1
CHATROOMSIZEBYTES=4
CMD = {
    "getdir"        : b'\x01',
    "makeroom"      : b'\x02',
    "deleteroom"    : b'\x03',
}

CLIENT_CMDS = ["connect", "bye", "name", "chat"]

SOCKET_TIMEOUT = 4

# Call recv to read bytecount_target bytes from the socket. Return a
# status (True or False) and the received butes (in the former case).
def recv_bytes(sock, bytecount_target):
    # Be sure to timeout the socket if we are given the wrong
    # information.
    sock.settimeout(SOCKET_TIMEOUT)
    try:
        byte_recv_count = 0 # total received bytes
        recv_bytes = b''    # complete received message
        while byte_recv_count < bytecount_target:
            # Ask the socket for the remaining byte count.
            new_bytes = sock.recv(bytecount_target-byte_recv_count)
            # If ever the other end closes on us before we are done,
            # give up and return a False status with zero bytes.
            if not new_bytes:
                return(False, b'')
            byte_recv_count += len(new_bytes)
            recv_bytes += new_bytes
        # Turn off the socket timeout if we finish correctly.
        sock.settimeout(None)            
        return (True, recv_bytes)
    # If the socket times out, something went wrong. Return a False
    # status.
    except socket.timeout:
        sock.settimeout(None)        
        print("recv_bytes: Recv socket timeout!")
        return (False, b'')

class Server:

    HOSTNAME = "0.0.0.0"
    PORT = 50000

    RECV_SIZE = 256
    BACKLOG = 10
    
    MSG_ENCODING = "utf-8"

    def __init__(self):
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Get socket layer socket options.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind( (Server.HOSTNAME, Server.PORT) )

            ############################################################
            # Set the (listen) socket to non-blocking mode.
            self.socket.setblocking(False)
            ############################################################            

            # Set socket to listen state.
            self.socket.listen(Server.BACKLOG)
            print("Chat Room Directory Server Listening on port {} ...".format(Server.PORT))
            
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            ############################################################
            # Keep a list of the current client connections.
            self.connected_clients = []
            ############################################################

            # The main loop that we execute forever.
            while True:
                self.check_for_new_connections()
                self.service_connected_clients()

        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)
                
    def check_for_new_connections(self):                
        try:
            # Check if a new connection is available.
            new_client = self.socket.accept()
            new_connection, new_address_port = new_client

            # Announce that a new connection has been accepted.
            print("\nConnection received from {}.".format(new_address_port))

            # Set the new socket to non-blocking. 
            new_connection.setblocking(False)

            # Add the new connection to our connected_clients
            # list.
            self.connected_clients.append(new_client)
            
        except socket.error:
            # If an exception occurs, there are no new
            # connections. Continue on.
            pass

    def service_connected_clients(self):

        # Iterate through the list of connected clients, servicing
        # them one by one. Since we may delete from the list, make a
        # copy of it first.
        current_client_list = self.connected_clients.copy()

        for client in current_client_list:
            connection, address_port = client
            try:
                # Check for available incoming data.
                
                # Check if the client has said "bye" or if the client
                # has closed the connection.
                _,cmd_field = recv_bytes(connection, CMD_FIELD_LEN)
                cmd = int.from_bytes(cmd_field, byteorder='big')
                
                if cmd == int.from_bytes(CMD['makeroom'], byteorder='big'):
                    self.make_room()
                    #self.connected_clients.remove(client)
                    #connection.close()
                    #continue
                # Echo back what we received.
                #connection.sendall(recvd_bytes)
                # print("\nEcho: ", recvd_str)
            except socket.error:
                # If no bytes are available, catch the
                # exception. Continue on so that we can check
                # other connections.
                pass

    def make_room(self, connection):
        # Decoding Chat Room Name  
        chatRoomNameSizeInBytes = recv_bytes(connection, CHATROOMSIZEBYTES)
        chatRoomNameSize = int(chatRoomNameSizeInBytes.decode(Server.MSG_ENCODING))
        
        chatRoomNameBytes = recv_bytes(connection, chatRoomNameSize)
        chatRoomName = chatRoomNameBytes.decode(Server.MSG_ENCODING)

        # Decoding Multicast I.P address 
        IPaddressBytes = recv_bytes(connection, IP)


        # Decoding 


class Client:

    # Set the server to connect to. If the server and client are running
    # on the same machine, we can use the current hostname.
    # SERVER_HOSTNAME = socket.gethostname()
    # SERVER_HOSTNAME = "192.168.1.22"
    SERVER_HOSTNAME = "localhost"
    
    # Try connecting to the compeng4dn4 echo server. You need to change
    # the destination port to 50007 in the connect function below.
    # SERVER_HOSTNAME = 'compeng4dn4.mooo.com'

    RECV_BUFFER_SIZE = 1024 # Used for recv.    
    # RECV_BUFFER_SIZE = 5 # Used for recv.    


    def __init__(self):
        self.get_socket()
        #self.connect_to_server()
        # self.send_console_input_forever()
        

    def get_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Allow us to bind to the same port right away.            
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind the client socket to a particular address/port.
            # self.socket.bind((Server.HOSTNAME, 40000))

            # Wait for client to enter "CONNECT" command before calling connect_to_server()
            self.user_input_text= input("Enter a command ")
            if(self.user_input_text == "connect"):
                self.connect_to_server()
            else:
                pass        
        
        
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        try:
            # Connect to the server using its socket address tuple.
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))
            print("Connected to \"{}\" on port {}".format(Client.SERVER_HOSTNAME, Server.PORT))
            self.get_console_input()
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered, i.e., ignore blank lines.
        print("You are connected to the Chat Room Directory Server (CRDS)\n")
        self.input_text = input("CRDS Input: ")
        if self.input_text == "getdir":
            pass
        elif "makeroom" in self.input_text:
            command_str = self.input_text.split()
            name = command_str[1]
            ip = command_str[2]
            port = command_str[3]
            self.makeroom(name,ip,port) #add input arguments
            
        elif "deleteroom" in self.input_text:
            command_str = self.input_text.split()
            name = command_str[1]
            self.deleteroom(name)
            pass
        elif(self.input_text=="bye"):
            pass
        else:
            print("Error")

    def makeroom(self, chatRoomName, ip, port):
        # Build and send the command packet
        cmd_field = CMD["makeroom"]
        
        get_chatRoomName_size = len(chatRoomName.encode(Server.MSG_ENCODING))
        get_chatRoomName_size_pkt = get_chatRoomName_size.to_bytes(CHATROOMSIZEBYTES,byteorder='big')

        #args_field = f"{chatRoomName} {ip} {port}".encode(Server.MSG_ENCODING)
        args_field = (chatRoomName +ip+port).encode(Server.MSG_ENCODING)
        pkt = cmd_field + get_chatRoomName_size_pkt + args_field

        #self.socket.sendall(pkt)
        #print(pkt)

        print(len(ip.encode(Server.MSG_ENCODING)))

                
    def connection_send(self):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            self.socket.sendall(self.input_text.encode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)

            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            print("Received: ", recvd_bytes.decode(Server.MSG_ENCODING))

        except Exception as msg:
            print(msg)
            sys.exit(1)

########################################################################




########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################






