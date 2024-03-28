#!/usr/bin/env python3

########################################################################
#
# Simple File Request/Download Protocol
#
########################################################################
#
# When the client connects to the server and wants to request a file
# download, it sends the following message: 1-byte GET command + 1-byte
# filename size field + requested filename, e.g., 

# ------------------------------------------------------------------
# | 1 byte GET command  | 1 byte filename size | ... file name ... |
# ------------------------------------------------------------------

# The server checks for the GET and then transmits the requested file.
# The file transfer data from the server is prepended by an 8 byte
# file size field as follows:

# -----------------------------------
# | 8 byte file size | ... file ... |
# -----------------------------------

# The server needs to have REMOTE_FILE_NAME defined as a text file
# that the client can request. The client will store the downloaded
# file using the filename LOCAL_FILE_NAME. This is so that you can run
# a server and client from the same directory without overwriting
# files.

########################################################################

import socket
import argparse
import time
import os
import sys

########################################################################

# Define all of the packet protocol field lengths.

CMD_FIELD_LEN            = 1 # 1 byte commands sent from the client.
FILENAME_SIZE_FIELD_LEN  = 1 # 1 byte file name size field.
FILESIZE_FIELD_LEN       = 8 # 8 byte file size field.
    
# Define a dictionary of commands. The actual command field value must
# be a 1-byte integer. For now, we only define the "GET" command,
# which tells the server to send a file.

CMD = {
    "get" : b'\x01',
    "put" : b'\x02',
    "list" : b'\x03',
    "bye" : b'\x04'
}


MSG_ENCODING = "utf-8"
SOCKET_TIMEOUT = 4

########################################################################
# recv_bytes frontend to recv
########################################################################

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

########################################################################
# SERVER
########################################################################

class Server:

    HOSTNAME = "127.0.0.1"
    ALL_IF_ADDRESS = "0.0.0.0"
    
    FILE_SHARING_PORT = 50000
    SERVICE_SCAN_PORT = 30000
    
    RECV_SIZE = 1024
    BACKLOG = 5

    ACCEPT_TIMEOUT = 3
    RECV_TIMEOUT = 1
    
    ADDRESS_PORT = (ALL_IF_ADDRESS, SERVICE_SCAN_PORT)

    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"

    MSG_ENCODING = "utf-8"    
    
    SCAN_CMD = "SERVICE DISCOVERY"
    SCAN_CMD_ENCODED = SCAN_CMD.encode(MSG_ENCODING)
    
    MSG = "Amaan, Muaz & Ishmam's File Sharing Service"
    MSG_ENCODED = MSG.encode(MSG_ENCODING)

    # This is the file that the client will request using a GET.
    # REMOTE_FILE_NAME = "greek.txt"
    # REMOTE_FILE_NAME = "twochars.txt"
    REMOTE_FILE_NAME = "ocanada_greek.txt"
    # REMOTE_FILE_NAME = "ocanada_english.txt"

    def __init__(self):
        print("Remote File Sharing Directory: ", os.listdir(os.path.join(os.getcwd(), "remote_dir"))) # Printing Files Intially Available For Sharing
        self.create_sockets()
        self.process_connections_forever()

    def create_sockets(self):
        try:
            # Create the TCP socket for File Sharing.
            self.socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket_tcp.bind((Server.HOSTNAME, Server.FILE_SHARING_PORT))
            self.socket_tcp.listen(Server.BACKLOG)

            # Create the UDP socket for Service Scan
            self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket_udp.bind((Server.ALL_IF_ADDRESS, Server.SERVICE_SCAN_PORT))
            self.socket_udp.settimeout(Server.ACCEPT_TIMEOUT)

            ############################################################
            # Set the (listen) socket to non-blocking mode.
            self.socket_tcp.setblocking(False)
            ############################################################        

            print("Listening for service discovery messages on SDP port {} ...".format(Server.SERVICE_SCAN_PORT))
            print("Listening for file sharing connections on port {} ...".format(Server.FILE_SHARING_PORT))

        except Exception as msg:
            print(msg)
            exit()

    def process_connections_forever(self):
        try:
            # Keep a list of the current client connections.
            self.connected_clients = []

            # The main loop that we execute forever.
            while True:
                self.check_for_new_connections()
                self.service_connected_clients()

                # Periodically output the current number of connections.
                # print("{} \n".format(len(self.connected_clients)))
                # time.sleep(0.1)
        
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket_tcp.close()
            sys.exit(1)

        
    def check_for_new_connections(self):   
        try:
            while True:
                # Check For Incoming UDP Scan Requests
                self.udp_receive_broadcast()

                # Check if a new connection is available.
                new_client = self.socket_tcp.accept()
                new_connection, new_address_port = new_client

                # Announce that a new connection has been accepted.
                print("\nConnection received from {}.".format(new_address_port))    

                # Set the new socket to non-blocking. 
                new_connection.setblocking(False)           

                # Add the new connection to our connected_clients
                # list.
                self.connected_clients.append(new_client)

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
                #print(cmd_field)
                # Read the command and see what it is
                _,cmd_field = recv_bytes(connection, CMD_FIELD_LEN)
                cmd = int.from_bytes(cmd_field, byteorder='big')
                #recvd_bytes = connection.recv(Server.RECV_SIZE)
                #recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)

                if cmd == int.from_bytes(CMD['list'], byteorder='big'):
                    print("Recieved List Command!")
                    self.send_curr_directory_list(connection)

                elif cmd == int.from_bytes(CMD['put'], byteorder='big'):
                    print("Recieved Put Command!")
                    self.put_file(connection)
                    # self.send_curr_directory_list(connection)         
                elif cmd == int.from_bytes(CMD['get'], byteorder='big'):
                    print("Recieved Get Command!")
                    self.get_file(connection)            

                # Check if the client has said "bye" or if the client
                # has closed the connection.
                elif cmd == int.from_bytes(CMD['bye'], byteorder='big'):
                    print()
                    print("Closing {} connection ...".format(address_port))
                    print("Closing connection to \"{}\" on port {}".format(Server.HOSTNAME, Server.FILE_SHARING_PORT))
                    self.connected_clients.remove(client)
                    connection.close()
                    continue
   
            except socket.error:
                # If no bytes are available, catch the
                # exception. Continue on so that we can check
                # other connections.
                pass

    def send_curr_directory_list(self, connection):
        curr_directory = str(os.listdir(os.path.join(os.getcwd(), "remote_dir")))
        curr_directory_bytes = curr_directory.encode(MSG_ENCODING)
        curr_directory_size_bytes = len(curr_directory_bytes)
        curr_directory_size_field = curr_directory_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

        # Create the packet to be sent with the header field.
        pkt = curr_directory_size_field + curr_directory_bytes
        
        try:
            # Send the packet to the connected client.
            connection.sendall(pkt)
            return
            # time.sleep(20)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing THE client connection ...")
            connection.close()
            return 
        
    def put_file(self, connection):
        try:
            # Extract Filename Size
            _, filename_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
            filename_size = int.from_bytes(filename_size_field, byteorder='big')

            # Extract Filename
            _, filename_bytes = recv_bytes(connection, filename_size)
            filename = filename_bytes.decode(MSG_ENCODING)
            print('Requested filename = ', filename)

            # Extract File Size
            _, file_size_bytes = recv_bytes(connection, FILESIZE_FIELD_LEN)
            file_size = int.from_bytes(file_size_bytes, byteorder='big')

            # Extract File
            _, file_byteform = recv_bytes(connection, file_size)
            file = file_byteform.decode(MSG_ENCODING)

            file_path = "remote_dir"
            file_full_location = os.path.join(file_path, filename)

            try:
                with open(file_full_location, 'w') as f:
                    f.write(file)
            except (IOError, OSError):
                print("Error writing to file")
                return
            
            return    
        except KeyboardInterrupt:
            print("File Upload Interupted")
            connection.close()

            



    def get_file(self, connection):
        
        # Extract Filename Size
        _, filename_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
        filename_size = int.from_bytes(filename_size_field, byteorder='big')

        # Extract Filename
        _, filename_bytes = recv_bytes(connection, filename_size)
        filename = filename_bytes.decode(MSG_ENCODING)
        print('Requested filename = ', filename)
        
        # See if we can open the requested file. If so, send it.
        
        # If we can't find the requested file, shutdown the connection
        # and wait for someone else.

        file_path = "remote_dir"
        file_full_location = os.path.join(file_path, filename)
        try:
            with open(file_full_location, 'r') as file:
                file_content = file.read()
        except FileNotFoundError:
            print(Server.FILE_NOT_FOUND_MSG)
            connection.close()                   
            return
        
        # Encode the file contents into bytes, record its size and
        # generate the file size field used for transmission.
        file_bytes = file_content.encode(MSG_ENCODING)
        file_size_bytes = len(file_bytes)
        file_size_field = file_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

        # Create the packet to be sent with the header field.
        pkt = file_size_field + file_bytes
        
        try:
            # Send the packet to the connected client.
            connection.sendall(pkt)
            print("Sending file: ", filename)
            print("file size field: ", file_size_field.hex(), "\n")
            # time.sleep(20)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            connection.close()
            return
        finally:
            #connection.close()
            return        
            
        

    def udp_receive_broadcast(self):
        try:
            recvd_bytes, address = self.socket_udp.recvfrom(Server.RECV_SIZE)

            print("Received: ", recvd_bytes.decode('utf-8'), " Address:", address)
        
            # Decode the received bytes back into strings.
            recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)

            # Check if the received packet contains a service scan
            # command.

            
            if Server.SCAN_CMD in recvd_str:
                # Send the service advertisement message back to
                # the client.
                self.socket_udp.sendto(Server.MSG_ENCODED, address)
                
        except socket.timeout:
            pass
        
########################################################################
# CLIENT
########################################################################

class Client:

    RECV_SIZE = 1024

    # Define the local file name where the downloaded file will be
    # saved.
    DOWNLOADED_FILE_NAME = "filedownload.txt"

    def __init__(self):
        try:
            self.get_socket()
            while True:
                # self.connect_to_server()
                self.userInput=input("Welcome to the file sharing service, enter an input command - llist, scan, connect: ")
                #if(self.userInput=="rlist"):
                #    self.get_remote_list()
                if(self.userInput=="llist"):
                    print("Local File Sharing Directory: ", os.listdir(os.path.join(os.getcwd(), "local_dir")))
                #elif(self.userInput=="bye"):
                    #print("Closing the connection, goodbye")
                    #self.socket.close()
                elif(self.userInput=="scan"):
                    self.scan_for_service() 
                elif "connect" in self.userInput:
                    command_str = self.userInput.split()
                    ip = command_str[1]
                    port = int(command_str[2])
                    self.connect_to_server(ip, port)       
                else:
                    print("Invalid command")
        except KeyboardInterrupt:
            print("closing connection...")

        

    def get_socket(self):

        try:
            self.socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.UDP_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            self.UDP_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Arrange to send a broadcast service discovery packet.
            self.UDP_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.UDP_socket.settimeout(5)

        except Exception as msg:
            print(msg)
            exit()

    def connect_to_server(self, ip, port):
        try:
            #Setup TCP connection 
            # Create an IPV4 TCP Socket
            #self.socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
            # Connect To Server
            # Send a service discovery broadcast.
            print("Sending broadcast scan ")     
            self.socket_tcp.connect((ip, port))
            print("Connected to the file sharing service at IP Address \"{}\" on port {}".format(ip, port))
            while True:
                self.userInput=input("Enter a server input command - rlist, put or get: ")
                if(self.userInput=="rlist"):
                    self.get_remote_list()
                elif "put" in self.userInput:
                    command_str = self.userInput.split()
                    filename = command_str[1]
                    self.put_file(filename)
                    self.get_remote_list()
                elif "get" in self.userInput:
                    command_str = self.userInput.split()
                    filename = command_str[1]
                    self.get_file(filename)
                    print("Local File Sharing Directory: ", os.listdir(os.path.join(os.getcwd(), "local_dir")))
                elif(self.userInput=="bye"):
                    # 
                    print('Restarting Application - Start From The Beginning\n')
                    # Send The Bye Packet 
                    self.socket_tcp.sendall(CMD['bye'])
                    self.socket_tcp.close()
                    self.get_socket()
                    return


        except Exception as msg:
            print(msg)
            exit()


    def get_remote_list(self):

        cmd_field = CMD['list']

        # Send the request packet to the server.
        self.socket_tcp.sendall(cmd_field)

        # Read the list size field returned by the server.
        status, file_size_bytes = recv_bytes(self.socket_tcp, FILESIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")            
            self.socket_tcp.close()
            return

        if len(file_size_bytes) == 0:
            self.socket_tcp.close()
            return

        # Make sure that you interpret it in host byte order.
        resp_bytes_length = int.from_bytes(file_size_bytes, byteorder='big')
                                 
        status, recvd_bytes_total = recv_bytes(self.socket_tcp, resp_bytes_length)
        if not status:
            print("Closing connection ...")            
            self.socket_tcp.close()
            return
        
        remote_dir = eval(recvd_bytes_total.decode(MSG_ENCODING))
        #print("directory size = ", len(remote_dir))
        print(remote_dir)
        return

    def scan_for_service(self):
        # Collect our scan results in a list.
        scan_results = []
        SCAN_MSG ="SERVICE DISCOVERY"
        # Send a service discovery broadcast.
        print("Sending broadcast scan: '{}'".format(SCAN_MSG))            
        self.UDP_socket.sendto(SCAN_MSG.encode(MSG_ENCODING), ('255.255.255.255',30000))#port 30000 for broadcasting
        # Place In For Loop Just In Case
        while True:
            try:
                recvd_bytes, address_port = self.UDP_socket.recvfrom(Client.RECV_SIZE) # socket configured to use timeout
                recvd_msg = recvd_bytes.decode(MSG_ENCODING)
                # Record only unique services that are found.
                if (recvd_msg, address_port) not in scan_results:
                    scan_results.append((recvd_msg, address_port))
                    continue
            # If we timeout listening for a new response, we are finished
            except socket.timeout:
                break

        # Output all of our scan results, if any
        if scan_results:
            for result in scan_results:
                print(result)
        else:
            print("No services found.")

        #return scan_results

    def put_file(self, filename):
        
        # Upload File To Remote Server
        cmd_field = CMD['put']
        
        # File Name To Bytes
        
        filename_bytes = filename.encode(MSG_ENCODING)

        # Create File Name Size Field
        filename_size_bytes = len(filename_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')
        #print('client',len(filename_size_bytes))
    
        # Open The Requested File
        file_path = "local_dir"
        file_full_location = os.path.join(file_path, filename)

        try:
            file = open(file_full_location, 'r').read()
            print("Opened File Succesfully")
            
        except FileNotFoundError:
            print(Server.FILE_NOT_FOUND_MSG)
            self.socket_tcp.close()                   
            return

        # Create File In Bytes
        file_bytes = file.encode(MSG_ENCODING)
    
        # Create File Size Field
        file_size_bytes = len(file_bytes).to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

        # Create Packet To Send
        pkt = cmd_field + filename_size_bytes + filename_bytes + file_size_bytes + file_bytes

        try:
            # Send the packet to the connected client.
            self.socket_tcp.sendall(pkt)
            print("Sending File: ", filename)
            # time.sleep(20)
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            self.socket_tcp.close()
            return
        finally:
            # self.socket_tcp.close()
            return       
        


    def get_file(self, filename):

        ################################################################
        # Generate a file transfer request to the server
        
        # Create the packet cmd field.
        cmd_field = CMD['get']

        # Create the packet filename field.
        filename_field_bytes = filename.encode(MSG_ENCODING)

        # Create the packet filename size field.
        filename_size_field = len(filename_field_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')
        
        pkt = cmd_field + filename_size_field + filename_field_bytes

        # Send the request packet to the server.
        self.socket_tcp.sendall(pkt)

        ################################################################
        # Process the file transfer repsonse from the server
        
        # Read the file size field returned by the server.
        status, file_size_bytes = recv_bytes(self.socket_tcp, FILESIZE_FIELD_LEN)
        if not status:
            print("Closing connection ...")            
            self.socket_tcp.close()
            return

        #print("File size bytes = ", file_size_bytes.hex())
        if len(file_size_bytes) == 0:
            self.socket_tcp.close()
            return

        # Make sure that you interpret it in host byte order.
        file_size = int.from_bytes(file_size_bytes, byteorder='big')
        #print("File size = ", file_size)

        # self.socket.settimeout(4)                                  
        status, recvd_bytes_total = recv_bytes(self.socket_tcp, file_size)
        if not status:
            print("Closing connection ...")            
            self.socket_tcp.close()
            return
        # print("recvd_bytes_total = ", recvd_bytes_total)
        # Receive the file itself.

        file_path = "local_dir"
        file_full_location = os.path.join(file_path, filename)
        
        try:
            # Create a file using the received filename and store the
            # data.
            print("Received {} bytes. Creating file: {}" \
                  .format(len(recvd_bytes_total), filename))

            with open(file_full_location, 'w') as f:
                recvd_file = recvd_bytes_total.decode(MSG_ENCODING)
                f.write(recvd_file)
            #print(recvd_file)
            return
        except KeyboardInterrupt:
            print()
            exit(1)
            
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






