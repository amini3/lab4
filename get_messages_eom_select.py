#!/usr/bin/env python3

########################################################################

import socket
import argparse
import time
import sys
import base64
import random
import select

import StringSamples

########################################################################
# CLIENT
########################################################################

class Client:

    SERVER_HOSTNAME = 'localhost'
    RECV_SIZE = 512

    NUMBER_OF_DOWNLOADS = 10
    TIME_BETWEEN_GETS = 2 # seconds

    def __init__(self):
        self.get_socket()
        self.connect_to_server()
        self.download_messages()

    def download_messages(self):
        for n in range(1, Client.NUMBER_OF_DOWNLOADS+1):
            print("-" * 72)
            print("Download number ", n)
            print("-" * 72)
            self.download_message()
            time.sleep(Client.TIME_BETWEEN_GETS)

    def get_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg); exit()

    def connect_to_server(self):
        try:
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg); exit()

    def download_message(self):
        # Send the download request string to the server.
        self.socket.sendall(GET_REQUEST)
        # self.socket.sendall(b'...GET...')        

        # recvd_pkt_bytes is used to accumulate bytes received over
        # the connection.
        recvd_pkt_bytes = bytearray()

        try:
            while True:
                recvd_pkt_bytes += self.socket.recv(Client.RECV_SIZE)

                # If the last bytes read is terminated by the
                # Server.EOM_BYTE, we are finished. Remove that byte
                # and break out of recv loop.
                #sends random messages
                if recvd_pkt_bytes[-1:] == Server.EOM_BYTE:
                    recvd_msg_bytes = recvd_pkt_bytes[:-1]
                    msg = base64.b64decode(recvd_msg_bytes).decode('utf-8')
                    print(msg)
                    break
        except KeyboardInterrupt:
            print()
            self.print_msg(recvd_bytes)
            self.socket.close()

    def print_msg(self, msg_bytes):
        print("-" * 72)
        print("Received message: \n", msg_bytes.decode(Server.MSG_ENCODING))

########################################################################
# SERVER
########################################################################

GET_REQUEST = b'GET'
GET_REQUEST_SIZE = len(GET_REQUEST)

class Server:

    HOSTNAME = "127.0.0.1" # socket.gethostname()
    PORT = 50000

    BACKLOG = 5
    
    # Use a zero byte to encode the end of the message. It is not a
    # valid Base64 encoding output.
    EOM_BYTE = b"\0"

    MSG_ENCODING = "utf-8"

    def __init__(self):
        self.create_listen_socket()
        self.set_select_lists()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.bind((Server.HOSTNAME, Server.PORT))
            self.listen_socket.listen(Server.BACKLOG)
            print("Listening on port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg); exit()

    def set_select_lists(self):
        ################################################################
        # Set the initial lists of read and write sockets that will be
        # passed to the select module. Initially, the read_list will
        # contain only the listen socket that we create.
        ################################################################
        #sockets for select        
        self.read_list = [self.listen_socket]
        self.write_list = []

    def get_random_encoded_msg_bytes(self):
        msg = random.choice(StringSamples.MSG_LIST)
        msg_bytes = msg.encode(Server.MSG_ENCODING)
        msg_bytes_base64 = base64.b64encode(msg_bytes)
        return(msg_bytes_base64 + Server.EOM_BYTE)

    def process_connections_forever(self):
        self.command_list = {}
        try:
            while True:
                ########################################################
                # Get the current lists of read, write and exception
                # ready sockets from the select module. Note that
                # select blocks until something is ready to be done
                # unless we include a timeout argument.
                ######################################################## 
                #sockets readty to be written, read, and exception sockets               
                read_ready, write_ready, except_ready = select.select(
                    self.read_list, self.write_list, [])

                ########################################################
                # There is work to be done. Check both lists that
                # select has returned to us.
                ########################################################
                #processes read and write sockets
                # select blocks until task is done
                self.process_read_sockets(read_ready)
                self.process_write_sockets(write_ready)

        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.listen_socket.close()

                
    def process_read_sockets(self, read_ready):
        ################################################################
        # Iterate through the read_ready sockets, processing
        # each one in turn.
        ################################################################        
        for read_socket in read_ready:
            if read_socket is self.listen_socket:
                ########################################################
                # If the listen socket is ready for reading, it means
                # that there is a new client connection. Accept it and
                # then append the client socket to the select
                # read_list.
                ########################################################
                client, address = read_socket.accept()
                print("-" * 72)
                print("Connection received from {}.".format(address))
                self.read_list.append(client)

                ########################################################
                # In this version we read incoming bytes on the client
                # connection and concatenate them into a client
                # specific byte array. Define a dictionary entry for
                # the byte array of the new client.
                ########################################################
                self.command_list[client] = b''
            else:
                ########################################################                
                # If the read_socket is not the listen socket, then it
                # must be a client. Read from the client and see if
                # the proper request message is sent. If so, add the
                # socket to the write list. If not, leave the socket
                # on the read list and wait for more input.
                ########################################################
                request_bytes = read_socket.recv(GET_REQUEST_SIZE)
                # request_bytes = read_socket.recv(1) 
                if request_bytes:
                    print("New request bytes: ", request_bytes)
                    self.command_list[read_socket] += request_bytes

                    if len(self.command_list[read_socket]) >= GET_REQUEST_SIZE and \
                    GET_REQUEST in self.command_list[read_socket]:
                        print("Valid GET_REQUEST received.")
                        ################################################
                        # Reset the command list for the next request
                        # from the same client.
                        ################################################                        
                        self.command_list[read_socket] = b''
                        self.write_list.append(read_socket)
                else:
                    ####################################################
                    # We got a zero length recv. Reset and shutdown
                    # this client.
                    ####################################################                    
                    del self.command_list[read_socket]
                    self.read_list.remove(read_socket)
                    print("Closing client socket ...")
                    read_socket.close()
                   
    def process_write_sockets(self, write_ready):
        ################################################################
        # Iterate through the write_ready socket list. If there is
        # something there, it is a client waiting for its
        # download. Send it and remove the client from the write list.
        ################################################################  
        #gets a random message in the write socket      
        for write_socket in write_ready:
            write_socket.sendall(self.get_random_encoded_msg_bytes())
            self.write_list.remove(write_socket)

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






