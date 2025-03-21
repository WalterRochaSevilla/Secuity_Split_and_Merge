import os
import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

def split_and_encrypt(input_path, chunk_size, base_password):
    base, ext = os.path.splitext(input_path)
    part_num = 1
    
    with open(input_path, 'rb') as infile:
        while True:
            chunk = infile.read(chunk_size)
            if not chunk:
                break
            
            # Generar clave única para esta parte (base_password + part_num)
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(f"{base_password}{part_num}".encode()))
            cipher = Fernet(key)
            encrypted_chunk = cipher.encrypt(chunk)
            part_name = f"{base}_part{part_num}{ext}.enc"
            with open(part_name, 'wb') as outfile:
                outfile.write(salt + encrypted_chunk)
            
            part_num += 1
    
    print(f"Archivo dividido y cifrado en {part_num-1} partes.")

if __name__ == "__main__":
    # Configurar el parser de argumentos
    parser = argparse.ArgumentParser(description="Cifrar y dividir un archivo en partes.")
    parser.add_argument("input_path", type=str, help="Ruta del archivo a cifrar")
    parser.add_argument("chunk_size", type=int, help="Tamaño de cada parte en bytes")
    parser.add_argument("base_password", type=str, help="Contraseña base para el cifrado")

    # Obtener los argumentos
    args = parser.parse_args()

    # Ejecutar la función principal
    split_and_encrypt(args.input_path, args.chunk_size, args.base_password)