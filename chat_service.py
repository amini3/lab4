#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time
import json
import threading
import asyncio
import pprint

########################################################################
# Echo Server class
########################################################################

CMD_FIELD_LEN =1
IP_ADDR_LEN = 4
IP_PORT_LEN = 3
CHATROOMSIZEBYTES=4

CMD = {
    "getdir"        : b'\x01',
    "makeroom"      : b'\x02',
    "deleteroom"    : b'\x03',
    "grabserver"    : b'\x04',
    "bye"           : b'\x05'
}

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
        # print("recv_bytes: Recv socket timeout!")
        return (False, b'')

class Server:

    HOSTNAME = "0.0.0.0"
    PORT = 50000

    RECV_SIZE = 256
    BACKLOG = 10
    
    MSG_ENCODING = "utf-8"

    roomDirectory = {}

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
                    self.make_room(connection)
                elif cmd == int.from_bytes(CMD['deleteroom'], byteorder='big'):
                    self.deleteRoom(connection)
                elif cmd == int.from_bytes(CMD['getdir'], byteorder='big'):
                    self.getDir(connection)
                elif cmd == int.from_bytes(CMD['grabserver'], byteorder='big'):
                    self.get_chat_room_info(connection)
                    #self.connected_clients.remove(client)
                    #connection.close()
                    #continue
                elif cmd == int.from_bytes(CMD['bye'], byteorder='big'):
                    print()
                    print("Closing {} connection ...".format(address_port))
                    self.connected_clients.remove(client)
                    connection.close()
                    continue
            except socket.error:
                # If no bytes are available, catch the
                # exception. Continue on so that we can check
                # other connections.
                pass

    def get_chat_room_info(self, connection):
        # Decoding Chat Room Name
        _, chatRoomNameSizeInBytes = recv_bytes(connection, CHATROOMSIZEBYTES)
        chatRoomNameSize = int.from_bytes(chatRoomNameSizeInBytes, byteorder='big')

        _, chatRoomNameBytes = recv_bytes(connection, chatRoomNameSize)
        chatRoomName = chatRoomNameBytes.decode(Server.MSG_ENCODING)

        ip = ''
        port = ''
        
        for key, value in self.roomDirectory.items():
            if value['name'] == chatRoomName:
                ip = self.roomDirectory[key]['address']
                port = self.roomDirectory[key]['port']
                break
            else:
                 ip = "NAN"
                 port = "-111"

        IP_pkt = ip.encode(Server.MSG_ENCODING)
        get_IP_size = len(ip.encode(Server.MSG_ENCODING))
        get_IP_size_pkt = get_IP_size.to_bytes(IP_ADDR_LEN,byteorder='big')

        
        port_pkt = port.encode(Server.MSG_ENCODING)
        get_port_size = len(port.encode(Server.MSG_ENCODING))
        get_port_size_pkt = get_port_size.to_bytes(IP_PORT_LEN,byteorder='big')

        pkt = get_IP_size_pkt + IP_pkt + get_port_size_pkt + port_pkt
        connection.sendall(pkt)
        return
        


    def make_room(self, connection):
        # Decoding Chat Room Name  
        _, chatRoomNameSizeInBytes = recv_bytes(connection, CHATROOMSIZEBYTES)
        chatRoomNameSize = int.from_bytes(chatRoomNameSizeInBytes, byteorder='big')
        
        _, chatRoomNameBytes = recv_bytes(connection, chatRoomNameSize)
        chatRoomName = chatRoomNameBytes.decode(Server.MSG_ENCODING)

        # Decoding Multicast I.P address 
        _, IPaddressSizeInBytes = recv_bytes(connection, IP_ADDR_LEN)
        IPaddressSize = int.from_bytes(IPaddressSizeInBytes, byteorder='big')

        _, IPaddressBytes = recv_bytes(connection, IPaddressSize)
        IPaddress = IPaddressBytes.decode(Server.MSG_ENCODING)

        # Decoding Port
        _, PortSizeInBytes = recv_bytes(connection, IP_PORT_LEN)
        PortSize = int.from_bytes(PortSizeInBytes, byteorder='big')

        _, PortBytes = recv_bytes(connection, PortSize)
        Port = PortBytes.decode(Server.MSG_ENCODING) 

        # Updating Our Global Directory
        self.updateDir(chatRoomName, IPaddress, Port, connection) 
        return

         

    def updateDir(self, name, address, port, connection):
        
        dirSize = len(self.roomDirectory)
        flag = 1

        for dir_id, dir_info in self.roomDirectory.items():
            if (self.roomDirectory[dir_id]['address'] == address or self.roomDirectory[dir_id]['port'] == port):
                flag = 0
                flag_bytes = flag.to_bytes(1, byteorder='big')
                print(flag_bytes)
                connection.sendall(flag_bytes)
                return

        self.roomDirectory[dirSize] = {}
        
        self.roomDirectory[dirSize]['name'] = name
        self.roomDirectory[dirSize]['address'] = address
        self.roomDirectory[dirSize]['port'] = port

        flag_bytes = flag.to_bytes(1, byteorder='big')
        connection.sendall(flag_bytes)



        return

    def getDir(self, connection):

        # Serializing Dictionary
        json_data = json.dumps(self.roomDirectory)

        # Encoding Json
        json_data_bytes = json_data.encode('utf-8')

        # Sending Json String
        connection.sendall(json_data_bytes)

        return
        

    def deleteRoom(self, connection):

        _, chatRoomNameSizeInBytes = recv_bytes(connection, CHATROOMSIZEBYTES)
        chatRoomNameSize = int.from_bytes(chatRoomNameSizeInBytes, byteorder='big')
        
        _, chatRoomNameBytes = recv_bytes(connection, chatRoomNameSize)
        chatRoomName = chatRoomNameBytes.decode(Server.MSG_ENCODING)
        
        
        for key, value in self.roomDirectory.items():
            if value['name'] == chatRoomName:
                last_key = list(self.roomDirectory.keys())[-1]
                if(self.roomDirectory[last_key] == self.roomDirectory[key]):
                    self.roomDirectory.pop(last_key)
                else:
                    del self.roomDirectory[key]
                    self.roomDirectory[key]= self.roomDirectory.pop(last_key)
                return

        # for dir_id, dir_info in self.roomDirectory.items():
        #     print("\nChat Room", str(dir_id) + ":")
        #     for key in dir_info:
        #         print('\t'+ key + ':', dir_info[key])

        # return
    

class Client:

    # Set the server to connect to. If the server and client are running
    # on the same machine, we can use the current hostname.
    # SERVER_HOSTNAME = socket.gethostname()
    # SERVER_HOSTNAME = "192.168.1.22"
    SERVER_HOSTNAME = "localhost"
    RX_BIND_ADDRESS = "0.0.0.0"
    RX_IFACE_ADDRESS = "127.0.0.1"
    CLIENTNAME = "Amaan"

    TTL = 1 # multicast hop count
    TTL_BYTE = TTL.to_bytes(1, byteorder='big')
    # Try connecting to the compeng4dn4 echo server. You need to change
    # the destination port to 50007 in the connect function below.
    # SERVER_HOSTNAME = 'compeng4dn4.mooo.com'

    RECV_BUFFER_SIZE = 1024 # Used for recv.    
    # RECV_BUFFER_SIZE = 5 # Used for recv.    

    RX_FLAG = False

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

            # Create Intial Multicast Socket That We Will Bind To Later
            self.rx_multiCastSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            self.rx_multiCastSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            

    

            

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
        
        try:
            
            while True:
                self.input_text = input("CRDS Input: ")

                if self.input_text == "getdir":
                    self.getDir()
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
                    # print('Closing connection from the server\n')
                    # Send The Bye Packet 
                    self.socket.sendall(CMD['bye'])
                    self.socket.close()
                    self.get_socket()
                elif "name" in self.input_text:
                    command_str = self.input_text.split()
                    self.CLIENTNAME = command_str[1] # This Will Be Appended To Every Message That Is Sent
                elif "chat" in self.input_text:
                    command_str = self.input_text.split()
                    name = command_str[1]
                    self.chatroom(name)
                else:
                    print("Error")
                    
        except KeyboardInterrupt:
            print("program closed")

    def create_recieve_socket(self, multicast_IP, multicast_PORT):
        MULTICAST_ADDRESS = multicast_IP # TEMPORARY
        # Binding Socket To Multicast Address
        RX_BIND_ADDRESS_PORT = (Client.RX_BIND_ADDRESS, multicast_PORT)
        self.rx_multiCastSocket.bind(RX_BIND_ADDRESS_PORT)

        multicast_group_bytes = socket.inet_aton(MULTICAST_ADDRESS)

        # Set up the interface to be used.
        multicast_iface_bytes = socket.inet_aton(Client.RX_IFACE_ADDRESS)

        # Form the multicast request.
        multicast_request = multicast_group_bytes + multicast_iface_bytes

        # Issue the Multicast IP Add Membership request.
        print("Adding membership (address/interface): ", MULTICAST_ADDRESS,"/", Client.RX_IFACE_ADDRESS)
        self.rx_multiCastSocket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
        return

    def create_send_socket(self):
            try:
                self.tx_multiCastSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                ############################################################
                # Set the TTL for multicast.

                self.tx_multiCastSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)

                # self.socket.bind((IFACE_ADDRESS, 30000)) # Bind to port 30000.
                self.tx_multiCastSocket.bind((Client.RX_IFACE_ADDRESS, 0)) # Have the system pick a port number.
                return

            except Exception as msg:
                print(msg)
                sys.exit(1)

    def receive_chat(self): 
        # self.rx_multiCastSocket.settimeout(SOCKET_TIMEOUT)
        try:
            while True:
                data, address_port = self.rx_multiCastSocket.recvfrom(Server.RECV_SIZE)
                rx_ip, rx_port = address_port
                ### ADD LOGIC TO NOT PRINT OUT IF ADDRESS IS SAME AS OUR OWN
                tx_ip, tx_port = self.tx_multiCastSocket.getsockname()
                if (rx_ip == tx_ip) and (rx_port == tx_port):
                    pass
                else:
                    print("{}".format(data.decode('utf-8')))
                    print(self.CLIENTNAME + ": ")


        except Exception as msg:
            print(msg)
            sys.exit(1)
    
    def getChatRoomInfo(self, clientName):
        # Sending Request Packet To Server
        cmd_byte = CMD['grabserver']

        chatRoomName_pkt = clientName.encode(Server.MSG_ENCODING)
        get_chatRoomName_size = len(clientName.encode(Server.MSG_ENCODING))
        get_chatRoomName_size_pkt = get_chatRoomName_size.to_bytes(CHATROOMSIZEBYTES,byteorder='big')

        pkt = cmd_byte+get_chatRoomName_size_pkt+chatRoomName_pkt
        self.socket.sendall(pkt)

        # Wait & Recv the Chat Room Info Packet From Server
        # Decoding Multicast I.P address 
        _, IPaddressSizeInBytes = recv_bytes(self.socket, IP_ADDR_LEN)
        IPaddressSize = int.from_bytes(IPaddressSizeInBytes, byteorder='big')
        _, IPaddressBytes = recv_bytes(self.socket, IPaddressSize)
        IPaddress = IPaddressBytes.decode(Server.MSG_ENCODING)
        # Decoding Port
        _, PortSizeInBytes = recv_bytes(self.socket, IP_PORT_LEN)
        PortSize = int.from_bytes(PortSizeInBytes, byteorder='big')

        _, PortBytes = recv_bytes(self.socket, PortSize)
        Port = int(PortBytes.decode(Server.MSG_ENCODING))

        if IPaddress == "NAN":
            print("Chat Room Not Found!: Try Again\n")
            self.get_console_input()
        
        
        return IPaddress, Port


        

        
    def chatroom(self, clientName):
        # Grabbing chatroom data from server
        multicast_ip, multicast_port = self.getChatRoomInfo(clientName)

        
        # Intializing RX & TX sockets
        self.create_send_socket()
        self.create_recieve_socket(multicast_ip, multicast_port)
       
        

        rx_thread = threading.Thread(target=self.receive_chat, args=())
        rx_thread.daemon = True
        rx_thread.start()

        print("Chat Room: \n")
        try: 
            while True:
                # Get User Message 
                print(self.CLIENTNAME + ": ")
                tx_chatText = input()
                
                tx_chatText = self.CLIENTNAME+": "+tx_chatText # Placing Name In Front Of Chat Message
                tx_chatTextBytes = tx_chatText.encode('utf-8')

                # Send Chat 
                ADDRESS_PORT_INFUNC = (multicast_ip, multicast_port) # FIX LATER 
                self.tx_multiCastSocket.sendto(tx_chatTextBytes, ADDRESS_PORT_INFUNC) # CHANGE TO CHAT 
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\nCtrl+C detected. Program will continue")
            #self.rx_multiCastSocket.close()
            #self.tx_multiCastSocket.close()
            self.get_console_input()


            

        
            


    def makeroom(self, chatRoomName, ip, port):
        # Build and send the command packet
        cmd_field = CMD["makeroom"]
        
        chatRoomName_pkt = chatRoomName.encode(Server.MSG_ENCODING)
        get_chatRoomName_size = len(chatRoomName.encode(Server.MSG_ENCODING))
        get_chatRoomName_size_pkt = get_chatRoomName_size.to_bytes(CHATROOMSIZEBYTES,byteorder='big')


        IP_pkt = ip.encode(Server.MSG_ENCODING)
        get_IP_size = len(ip.encode(Server.MSG_ENCODING))
        get_IP_size_pkt = get_IP_size.to_bytes(IP_ADDR_LEN,byteorder='big')

        
        port_pkt = port.encode(Server.MSG_ENCODING)
        get_port_size = len(port.encode(Server.MSG_ENCODING))
        get_port_size_pkt = get_port_size.to_bytes(IP_PORT_LEN,byteorder='big')

        pkt = cmd_field + get_chatRoomName_size_pkt + chatRoomName_pkt + get_IP_size_pkt + IP_pkt + get_port_size_pkt + port_pkt

        self.socket.sendall(pkt)

        # Wait For ACK packet
        _, ACKBytes = recv_bytes(self.socket, 1)
        ACK = int.from_bytes(ACKBytes, byteorder='big')

        if ACK == 1:
            print("Make Room Succesful!")
        elif ACK == 0:
            print("Make Room Fail!")
        
        return

    def deleteroom(self, chatRoomName):
        # Build and send the command packet
        cmd_field = CMD["deleteroom"]
        
        chatRoomName_pkt = chatRoomName.encode(Server.MSG_ENCODING)
        get_chatRoomName_size = len(chatRoomName.encode(Server.MSG_ENCODING))
        get_chatRoomName_size_pkt = get_chatRoomName_size.to_bytes(CHATROOMSIZEBYTES,byteorder='big')


        pkt = cmd_field + get_chatRoomName_size_pkt + chatRoomName_pkt

        self.socket.sendall(pkt)
        return
    
    def getDir(self):
        # Sending Request Packet To Server
        cmd_field = CMD['getdir']
        self.socket.sendall(cmd_field)

        # Wait & Recv the Directory Packet From Server
        dir_data_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)
        dir_data_decoded = dir_data_bytes.decode('utf-8')

        # Read the received message as JSON.
        dir_object = json.loads(dir_data_decoded)

        # Pretty Printing
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(dir_object)
        # print(dir_object)



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






