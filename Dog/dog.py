import ast
import astunparse
import base64
import random
import string
import sys
import time
import builtins
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class Dog(ast.NodeTransformer):
    """Principal class for the obfuscator"""
    def __init__(self):
        self.var_map = {}
        self.key = get_random_bytes(32)
        self.iv = get_random_bytes(16)  

    def obfuscate_name(self, name):
        """Obfuscates names of variables and functions"""
        if name not in self.var_map:
            length = random.randint(2, 20)
            first_char = random.choice(string.ascii_letters + '_')
            patterns = [
                string.ascii_letters,
                string.ascii_letters + string.digits,
                string.ascii_letters + '_',
                string.ascii_letters + string.digits + '_'
            ]
            rest_chars = ''.join(random.choice(random.choice(patterns)) for _ in range(length-1))
            new_name = first_char + rest_chars
            self.var_map[name] = new_name
        return self.var_map[name]

    def encrypt_string(self, text):
        """Encrypts string using AES and multiple encoding layers"""
        data = text.encode()
        xor_key = get_random_bytes(len(data))
        xored = bytes(a ^ b for a, b in zip(data, xor_key))
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        encrypted = cipher.encrypt(pad(xored, AES.block_size))
        final = base64.b85encode(encrypted).decode()
        return (final, xor_key)

    def visit_Str(self, node):
        """Obfuscate string literals"""
        encrypted_str, xor_key = self.encrypt_string(node.s)
        xor_key_str = base64.b85encode(xor_key).decode()
        decrypt_code = f"""(lambda s, k, i: (lambda x: x.decode())(bytes(
            a ^ b for a, b in zip(
                AES.new({self.key}, AES.MODE_CBC, {self.iv}).decrypt(base64.b85decode(s)),
                base64.b85decode(k)
            )
        )))({repr(encrypted_str)}, {repr(xor_key_str)}, {repr(self.iv)})"""
        return ast.parse(decrypt_code).body[0].value

    def visit_Name(self, node):
        """"Renames variables and functions and checks for built-ins"""
        if isinstance(node.ctx, (ast.Store, ast.Load)):
            builtin_names = dir(builtins) if isinstance(__builtins__, dict) else dir(__builtins__)
            
            # gambiarra to avoid name collision with built-in names
            common_names = [
                'datetime', 'AES', 'random', 'base64', 'time', 'now',
                'sys', 'os', 'json', 'math', 'numpy', 'pandas',
                'pickle', 'requests', 're', 'collections', 'func',
                'float', 'int', 'list', 'dict', 'tuple', 'set',
                'str', 'bool', 'bytes', 'range', 'zip', 'enumerate',
                'sleep', 'decode', 'encode', 'load', 'dumps', 'loads'
            ]
            
            if (node.id in builtin_names or 
                node.id in sys.modules or 
                node.id in common_names):
                return node
                
            if node.id in self.var_map:
                node.id = self.var_map[node.id]
            else:
                node.id = self.obfuscate_name(node.id)
        return node

    def insert_dead_code(self, context="general"):
        """Generate contextual dead code."""
        
        dead_code_patterns = [
            
            """
_obf_var1 = random.randint(1, 1000)
_obf_var2 = _obf_var1 * 2
_obf_var3 = _obf_var2 // 2
if _obf_var3 == _obf_var1:
    pass  
else:
    raise Exception("To be or not to be?")  
""",
            
            """
_obf_check = False
if _obf_check and datetime.now().year > 3000:
    print("Meow meow!")
""",

            """
def _obf_func():
    _obf_data = []
    for i in range(random.randint(10, 20)):
        _obf_data.append(i * i)
    return _obf_data

_obf_func()
""",

            """
_obf_str = "".join([chr(ord(c) + 1) for c in "complex string"]) 
_obf_str = "".join([chr(ord(c) - 1) for c in _obf_str])  
""",
            
            """
def _obf_transform(x):
    x = 2
    x = x * 2
    x = x / 2
    x = x + 10
    x = x - 10
    x = int(x)
    x = x ^ 0xFF
    x = x ^ 0xFF
    return x

_obf_result = _obf_transform(42)
"""
        ]
        
        pattern = random.choice(dead_code_patterns)
        
        pattern = pattern.replace("_obf_var", f"_obf_var{random.randint(1000, 9999)}")
        pattern = pattern.replace("_obf_func", f"_obf_func{random.randint(1000, 9999)}")
        pattern = pattern.replace("_obf_check", f"_obf_check{random.randint(1000, 9999)}")
        pattern = pattern.replace("_obf_str", f"_obf_str{random.randint(1000, 9999)}")
        pattern = pattern.replace("_obf_result", f"_obf_result{random.randint(1000, 9999)}")
        
        return ast.parse(pattern).body

    def visit_FunctionDef(self, node):
        """Obfuscate function names and insert dead code"""
        original_name = node.name
        node.name = self.obfuscate_name(original_name)
        
        if random.random() < 0.7:  
            dead_code = self.insert_dead_code()
            node.body = dead_code + node.body
        
        if len(node.body) > 2 and random.random() < 0.5:
            insert_pos = random.randint(1, len(node.body) - 1)
            more_dead_code = self.insert_dead_code()
            node.body[insert_pos:insert_pos] = more_dead_code
        
        for field, old_value in ast.iter_fields(node):
            if isinstance(old_value, list):
                new_values = []
                for value in old_value:
                    if isinstance(value, ast.AST):
                        value = self.visit(value)
                        if value is None:
                            continue
                        elif not isinstance(value, ast.AST):
                            new_values.extend(value)
                            continue
                    new_values.append(value)
                old_value[:] = new_values
            elif isinstance(old_value, ast.AST):
                new_node = self.visit(old_value)
                if new_node is None:
                    delattr(node, field)
                else:
                    setattr(node, field, new_node)
        return node


def obfuscate_code(code):
    """Obfuscates the given code using the Dog class"""
    
    imports = """
import base64
import random
from datetime import datetime
from Crypto.Cipher import AES
"""
    code = imports + code
    
    tree = ast.parse(code)
    obfuscator = Dog()
    obfuscated_tree = obfuscator.visit(tree)
    print(obfuscator.var_map)
    return astunparse.unparse(obfuscated_tree)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python dog.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, "r") as f:
        code = f.read()

    obfuscated_code = obfuscate_code(code)

    with open(output_file, "w") as f:
        f.write(obfuscated_code)

    print(f"Woof woof! Code obfuscated successfully: {output_file}")