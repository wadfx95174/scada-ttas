import socket, ssl
from threading import Thread 
import json
import jwt, hashlib
import time
import os
from enum import Enum
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# address enumerate
class AddrType(Enum):
    TBAS_IP = "192.168.1.100"
    TBAS_PORT = 8001
    CP_IP = "192.168.1.101"
    CP_PORT = 8001

class MACAddr(Enum):
    CP = "dca6329152a7"
    Pi = "dca6329153d6"

# temporary database
class TempAccount(Enum):
    account = "a"
    passwd = "48c8947f69c054a5caa934674ce8881d02bb18fb59d5a63eeaddff735b0e9801e87294783281ae49fc8287a0fd86779b27d7972d3e84f0fa0d826d7cb67dfefc"
    key = "456"

class ServerThread(Thread):

    def __init__(self, conn, addr):
        Thread.__init__(self)
        self._conn = conn
        self._addr = addr

    def run(self):
        while True:
            dataFromClient = self._conn.recv(2048).decode("utf-8")
            
            # if client send "close", then close connection
            if dataFromClient == "close":
                self._conn.close()
                print(self._addr, "disconnect!")
                break
            
            print ("From", self._addr, ": " + dataFromClient)
            # convert str to json
            jsonDataFromClient = json.loads(dataFromClient)

            # generate private/public key pair
            key = rsa.generate_private_key(
                backend=default_backend(),
                public_exponent=65537,
                key_size=2048)

            # get private key from key
            private_key  = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())

            # get public key from key
            public_key = key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo)

            # decode to string
            private_key_str = private_key.decode('utf-8')
            public_key_str = public_key.decode('utf-8')

            # connect from control program
            if self._addr[0] == AddrType.CP_IP.value:
                if "hostname" in jsonDataFromClient and "mac_addr" in jsonDataFromClient and \
                    "Pi_ip" in jsonDataFromClient and "Pi_port" in jsonDataFromClient:
                    if jsonDataFromClient["hostname"] == "controlprogram" and jsonDataFromClient["mac_addr"] == MACAddr.CP.value:

                        encoded = jwt.encode({"iss": AddrType.TBAS_IP.value, "iat": int(time.time()), "exp": int(time.time()) + 10
                                , "aud": self._addr[0], "public_key": public_key_str, "hostname": jsonDataFromClient["hostname"]
                                , "mac_addr": jsonDataFromClient["mac_addr"], "converter_ip": jsonDataFromClient["converter_ip"]
                                , "converter_port": jsonDataFromClient["converter_port"], "slave_id": jsonDataFromClient["slave_id"]
                                , "function_code": jsonDataFromClient["function_code"], "starting_address": jsonDataFromClient["starting_address"]
                                , "quantity_of_x": jsonDataFromClient["quantity_of_x"], "priority": "1"
                                , "service_type": "verification_machine"}, private_key_str, algorithm='RS256', headers={'test': 'header'})
                        print("To control program : ", encoded)
                        self._conn.sendall(encoded)
                        # send JWT to Raspberry Pi
                        connectTheOtherClient(jsonDataFromClient["Pi_ip"], jsonDataFromClient["Pi_port"], encoded)
                        
                    else:
                        self._conn.sendall("Your message has something wrong!".encode("utf-8"))
                else:
                    self._conn.sendall("Your message has something missing!".encode("utf-8"))
            # connect from Raspberry Pi
            else:
                if "response" in jsonDataFromClient and "hostname" in jsonDataFromClient and "mac_addr" in jsonDataFromClient and \
                    "CP_ip" in jsonDataFromClient and "CP_port" in jsonDataFromClient:
                    if jsonDataFromClient["hostname"] == "verificationmachine" and jsonDataFromClient["mac_addr"] == MACAddr.Pi.value:
                        encoded = jwt.encode({"iss": AddrType.TBAS_IP.value, "iat": int(time.time()), "exp": int(time.time()) + 10
                                , "aud": self._addr[0], "public_key": public_key_str, "hostname": jsonDataFromClient["hostname"]
                                , "mac_addr": jsonDataFromClient["mac_addr"], "response": jsonDataFromClient["response"]
                                , "priority": "1", "service_type": "verification_machine"}, private_key_str, algorithm='RS256'
                                , headers={'test': 'header'})
                        print("To Raspberry Pi : ", encoded)
                        # send JWT to control program
                        connectTheOtherClient(jsonDataFromClient["CP_ip"], jsonDataFromClient["CP_port"], encoded)
                        self._conn.sendall(encoded)
                    else:
                        self._conn.sendall("Your message has something wrong!".encode("utf-8"))
                else:
                    self._conn.sendall("Your message has something missing!".encode("utf-8"))

            # # check account, passwd, key are exist or not
            # if "account" in jsonDataFromClient and "passwd" in jsonDataFromClient:
            #     sha3_512 = hashlib.sha3_512()
            #     sha3_512.update(jsonDataFromClient["passwd"].encode('utf-8'))
                
            #     # check account and password are correct or not
            #     if jsonDataFromClient["account"] == TempAccount.account.value and sha3_512.hexdigest() == TempAccount.passwd.value:
                    
            #         # generate private/public key pair
            #         key = rsa.generate_private_key(
            #             backend=default_backend(), 
            #             public_exponent=65537,
            #             key_size=2048)

            #         # get private key from key
            #         private_key  = key.private_bytes(
            #             encoding=serialization.Encoding.PEM,
            #             format=serialization.PrivateFormat.PKCS8,
            #             encryption_algorithm=serialization.NoEncryption())

            #         # get public key from key
            #         public_key = key.public_key().public_bytes(
            #             serialization.Encoding.PEM,
            #             serialization.PublicFormat.SubjectPublicKeyInfo)

            #         # decode to string
            #         private_key_str = private_key.decode('utf-8')
            #         public_key_str = public_key.decode('utf-8')


            #         # with open("private_key.pem") as private_key:
            #         #     with open("public_key.pem") as public_key:
            #         #         encoded = jwt.encode({"iss": AddrType.IP.value, "iat": int(time.time()), "exp": int(time.time()) + 30
            #         #             , "aud": self.addr[0],"public_key": public_key.read(), "machine_id": "c_00001", "mac_addr": "00:0C:29:01:98:27"
            #         #             , "priority": "1", "service_type": "verification_machine"}, private_key.read(), algorithm='RS256'
            #         #             , headers={'test': 'header'})
                    
            #         encoded = jwt.encode({"iss": AddrType.IP.value, "iat": int(time.time()), "exp": int(time.time()) + 10
            #                     , "aud": self._addr[0], "public_key": public_key_str, "hostname": "c_00001", "mac_addr": "00:0C:29:01:98:27"
            #                     , "priority": "1", "service_type": "verification_machine"}, private_key_str, algorithm='RS256'
            #                     , headers={'test': 'header'})
            #         # Simultaneously send JWT to control program and Raspberry Pi
            #         connectTheOtherClient(jsonDataFromClient["ip"], jsonDataFromClient["port"], encoded)
            #         self._conn.sendall(encoded)
            #     else:
            #         self._conn.sendall("Your account or password is wrong!".encode("utf-8"))
            # else:
            #     self._conn.sendall("Your message has no account or password!".encode("utf-8"))

# connect control program or Raspberry Pi
def connectTheOtherClient(clientHost, clientPort, encoded):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./key/certificate.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)

    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.connect((clientHost, clientPort))
            sock.sendall(encoded)
            dataFromServer = sock.recv(1024).decode("utf-8")
            print(dataFromServer)
        except socket.error:
            print ("Connect error")
        
        

def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # load private key and certificate file
    context.load_cert_chain("./key/certificate.pem", "./key/privkey.pem")
    # prohibit the use of TLSv1.0, TLSv1.1, TLSv1.2 -> use TLSv1.3
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)

    # open, bind, listen socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((AddrType.TBAS_IP.value, AddrType.TBAS_PORT.value))
        sock.listen(15)
        print ("Server start at: %s:%s" %(AddrType.TBAS_IP.value, AddrType.TBAS_PORT.value))
        print ("Wait for connection...")

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    conn, addr = ssock.accept()
                    # multi-thread
                    newThread = ServerThread(conn, addr)
                    newThread.start()
                    newThread.join()
                except KeyboardInterrupt:
                    break

if __name__ == "__main__":
    main()