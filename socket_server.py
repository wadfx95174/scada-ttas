import socket, ssl
from threading import Thread 
import json
import jwt, hashlib
import time
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import defines

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
            
            # check source IP
            if self._addr[0] == defines.CP_IP or self._addr[0] == defines.TVM_IP:
                # check dict from source IP is exist or not
                if "hostname" in jsonDataFromClient and "mac_addr" in jsonDataFromClient \
                    and "ip" in jsonDataFromClient and "port" in jsonDataFromClient:
                    # check hostname and mac address from source IP is correct or not
                    if (jsonDataFromClient["hostname"] == defines.CP_hostname and jsonDataFromClient["mac_addr"] == defines.CP_MAC_ADDR) \
                        or (jsonDataFromClient["hostname"] == defines.TVM_hostname and jsonDataFromClient["mac_addr"] == defines.TVM_MAC_ADDR):

                        encoded = jwt.encode({"iss": defines.TTAS_IP, "iat": int(time.time()), "exp": int(time.time()) + 60
                                , "aud": self._addr[0], "public_key": public_key_str, "hostname": jsonDataFromClient["hostname"]
                                , "mac_addr": jsonDataFromClient["mac_addr"], "priority": "1", "service_type": "verification_machine"}
                                , private_key_str, algorithm='RS256', headers={'test': 'header'})
                        print("To control program or to TVM : ", encoded)
                        self._conn.sendall(encoded)
                        connectTheOtherClient(jsonDataFromClient["ip"], jsonDataFromClient["port"], encoded)
                        
                    else:
                        self._conn.sendall("Your message has something wrong!".encode("utf-8"))
                else:
                    self._conn.sendall("Your message has something missing!".encode("utf-8"))
            else:
                self._conn.sendall("Your IP is wrong!".encode("utf-8"))
                
# connect control program or TVM
def connectTheOtherClient(clientIP, clientPort, encoded):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./key/certificate.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            print(clientIP)
            print(clientPort)
            sock.connect((clientIP, clientPort))
            
            sock.sendall(encoded)
            dataFromServer = sock.recv(1024).decode("utf-8")
            print(dataFromServer)
            sock.close()
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
        # avoid continuous port occupation
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((defines.TTAS_IP, defines.TTAS_PORT))
        sock.listen(15)
        print ("Server start at: %s:%s" %(defines.TTAS_IP, defines.TTAS_PORT))
        print ("Wait for connection...")

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    conn, addr = ssock.accept()
                    # multi-thread
                    newThread = ServerThread(conn, addr)
                    newThread.start()
                    # newThread.join()

                except KeyboardInterrupt:
                    break

if __name__ == "__main__":
    main()