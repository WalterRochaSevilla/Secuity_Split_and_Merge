import os
import re
import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

def decrypt_and_merge(first_part_path, output_path, base_password):
    dir_path = os.path.dirname(first_part_path) or '.'  # Usa '.' si la ruta es vacía
    base_ext = os.path.basename(first_part_path)
    
    # Extraer nombre base, número de parte y extensión
    match = re.match(r'^(.*?)_part(\d+)(\..+\.enc)$', base_ext)
    if not match:
        raise ValueError("Formato incorrecto. Ejemplo esperado: nombre_part1.zip.enc")
    base_name = match.group(1)
    ext = match.group(3)
    
    # Buscar todas las partes en el directorio correcto
    part_files = []
    for f in os.listdir(dir_path):  # Ahora dir_path es '.' si está vacío
        full_path = os.path.join(dir_path, f)
        if os.path.isfile(full_path) and f.startswith(f"{base_name}_part") and f.endswith(ext):
            part_num = int(re.search(r'_part(\d+)' + re.escape(ext) + '$', f).group(1))
            part_files.append((part_num, full_path))
    
    # Verificar partes secuenciales
    part_files.sort()
    expected_parts = list(range(1, part_files[-1][0] + 1)) if part_files else []
    missing = [p for p in expected_parts if p not in [pf[0] for pf in part_files]]
    if missing:
        raise ValueError(f"Partes faltantes: {missing}")
    
    # Descifrar y unir
    with open(output_path, 'wb') as outfile:
        for part_num, part_path in part_files:
            with open(part_path, 'rb') as infile:
                data = infile.read()
                salt, encrypted_chunk = data[:16], data[16:]
                
                # Regenerar clave
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(f"{base_password}{part_num}".encode()))
                cipher = Fernet(key)
                
                # Descifrar
                decrypted_chunk = cipher.decrypt(encrypted_chunk)
                outfile.write(decrypted_chunk)
    for _, part_path in part_files:
            os.remove(part_path)
    print(f"Archivo fusionado: {output_path}")

if __name__ == "__main__":
    # Configurar el parser de argumentos
    parser = argparse.ArgumentParser(description="Descifrar y unir partes de un archivo.")
    parser.add_argument("first_part_path", type=str, help="Ruta de la primera parte cifrada")
    parser.add_argument("output_path", type=str, help="Ruta de salida del archivo descifrado")
    parser.add_argument("base_password", type=str, help="Contraseña base para el descifrado")

    # Obtener los argumentos
    args = parser.parse_args()

    # Ejecutar la función principal
    decrypt_and_merge(args.first_part_path, args.output_path, args.base_password)