import socket, ssl
from threading import Thread
import json
import jwt, hashlib
import time
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import defines
import logging

logging.basicConfig(
    filename="./log/logfile.log",
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class ServerThread(Thread):

    def __init__(self, conn, addr, sock):
        Thread.__init__(self)
        self._conn = conn
        self._addr = addr
        self._sock = sock

    def run(self):
        while True:
            try:
                dataFromClient = self._conn.recv(2048).decode("utf-8")
                # if client send "close", then close connection
                if dataFromClient == "close":
                    self._conn.shutdown(self._sock.SHUT_RDWR)
                    self._conn.close()
                    break
                jsonDataFromClient = json.loads(dataFromClient)
                # check source IP and dict from sender is exist or not
                if (self._addr[0] == defines.SS_IP or self._addr[0] == defines.TVM_IP or self._addr[0] == defines.BEMS_IP) \
                    and "hostname" in jsonDataFromClient and "mac_addr" in jsonDataFromClient \
                    and "ip" in jsonDataFromClient and "port" in jsonDataFromClient \
                    and "dst_hostname" in jsonDataFromClient and "dst_mac_addr" in jsonDataFromClient:

                    # check hostname and mac address from src and ip, port, hostname and mac address from dst is correct or not
                    if (jsonDataFromClient["hostname"] == defines.SS_hostname and jsonDataFromClient["mac_addr"] == defines.SS_MAC_ADDR \
                        and jsonDataFromClient["ip"] == defines.TVM_IP and jsonDataFromClient["port"] == defines.TVM_PORT \
                        and jsonDataFromClient["dst_hostname"] == defines.TVM_hostname and jsonDataFromClient["dst_mac_addr"] == defines.TVM_MAC_ADDR) \
                        or (jsonDataFromClient["hostname"] == defines.SS_hostname and jsonDataFromClient["mac_addr"] == defines.SS_MAC_ADDR \
                        and jsonDataFromClient["ip"] == defines.BEMS_IP and jsonDataFromClient["port"] == defines.BEMS_PORT \
                        and jsonDataFromClient["dst_hostname"] == defines.BEMS_hostname and jsonDataFromClient["dst_mac_addr"] == defines.BEMS_MAC_ADDR) \
                        or (jsonDataFromClient["hostname"] == defines.TVM_hostname and jsonDataFromClient["mac_addr"] == defines.TVM_MAC_ADDR \
                        and jsonDataFromClient["ip"] == defines.SS_IP and jsonDataFromClient["port"] == defines.SS_PORT \
                        and jsonDataFromClient["dst_hostname"] == defines.SS_hostname and jsonDataFromClient["dst_mac_addr"] == defines.SS_MAC_ADDR) \
                        or (jsonDataFromClient["hostname"] == defines.BEMS_hostname and jsonDataFromClient["mac_addr"] == defines.BEMS_MAC_ADDR \
                        and jsonDataFromClient["ip"] == defines.SS_IP and jsonDataFromClient["port"] == defines.SS_PORT \
                        and jsonDataFromClient["dst_hostname"] == defines.SS_hostname and jsonDataFromClient["dst_mac_addr"] == defines.SS_MAC_ADDR):

                        # generate private/public key pair
                        key = ec.generate_private_key(
                            ec.SECP384R1(), default_backend()
                        )

                        # get private key from key
                        private_key = key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        )

                        # get public key from key
                        public_key = key.public_key().public_bytes(
                            serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo
                        )

                        # decode to string
                        private_key_str = private_key.decode('utf-8')
                        public_key_str = public_key.decode('utf-8')

                        encoded = jwt.encode({"iss": defines.TTAS_IP, "iat": int(time.time()), "exp": int(time.time()) + 600
                                , "aud": self._addr[0], "public_key": public_key_str, "hostname": jsonDataFromClient["hostname"]
                                , "mac_addr": jsonDataFromClient["mac_addr"]}, private_key_str, algorithm='ES256')

                        connectTheOtherClient(jsonDataFromClient["ip"], jsonDataFromClient["port"], encoded)
                        self._conn.sendall(encoded)

                    else:
                        logging.info("The requested information has something wrong.")
                        self._conn.sendall("Your request message has something wrong.".encode("utf-8"))
                else:
                    logging.info("The requested source IP is wrong or has something missing.")
                    self._conn.sendall("Your IP is wrong or has something wrong!".encode("utf-8"))
            except BlockingIOError:
                logging.warning("The connection block error.")
            except ConnectionResetError:
                logging.warning("The connection reset error.")
            except Exception as e:
                self._conn.shutdown(self._sock.SHUT_RDWR)
                self._conn.close()
                logging.warning("The connection has something wrong.")
                break



# connect SCADA Server or TVM
def connectTheOtherClient(clientIP, clientPort, encoded):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./key/certificate.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)

    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.connect((clientIP, clientPort))
            sock.sendall(encoded)
            dataFromServer = sock.recv(1024).decode("utf-8")
            sock.close()
        except socket.error:
            logging.info("Connect SCADA Server or TVM error.")

def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # load private key and certificate file
    context.load_cert_chain("./key/certificate.pem", "./key/privkey.pem")
    # prohibit the use of TLSv1.0, TLSv1.1, TLSv1.2 -> use TLSv1.3
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        # avoid continuous port occupation
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((defines.TTAS_IP, defines.TTAS_PORT))
        sock.listen(30)

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    conn, addr = ssock.accept()
                    # multi-thread
                    newThread = ServerThread(conn, addr, socket)
                    newThread.start()
                except Exception as e:
                    logging.warning("The connection accept error.")
                except KeyboardInterrupt:
                    break

if __name__ == "__main__":
    main()
