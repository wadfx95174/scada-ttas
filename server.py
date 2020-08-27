import socket

HOST = '192.168.87.128'
PORT = 8001

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
    print("Something error!")

s.bind((HOST, PORT))
s.listen(5)
s.settimeout(10)

print ("Server start at: %s:%s" %(HOST, PORT))
print ("Wait for connection...")

while True:
    try:
        conn, addr = s.accept()
        print ("Connected by ", addr)
    except socket.timeout:
        print("Timeout!")
        s.close()
        break

    while True:
        data = conn.recv(1024)
        if data.decode("utf-8") == "close":
            conn.close()
            print(addr, " disconnect!")
            break
        print ("From client : " + data.decode("utf-8"))

        conn.sendall("Server received you message : ".encode("utf-8") + data)
        
# s.close()