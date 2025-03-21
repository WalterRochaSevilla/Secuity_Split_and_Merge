import argparse
from encrypt import split_and_encrypt
from decrypt import decrypt_and_merge

def main():
    parser = argparse.ArgumentParser(description="Herramienta para dividir y cifrar archivos.")
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')

    # Subcomando para cifrar
    encrypt_parser = subparsers.add_parser('encrypt', help='Cifrar un archivo')
    encrypt_parser.add_argument('input_path', type=str, help='Ruta del archivo a cifrar')
    encrypt_parser.add_argument('chunk_size', type=int, help='Tamaño de cada parte en bytes')
    encrypt_parser.add_argument('base_password', type=str, help='Contraseña base para el cifrado')

    # Subcomando para descifrar
    decrypt_parser = subparsers.add_parser('decrypt', help='Descifrar un archivo')
    decrypt_parser.add_argument('first_part_path', type=str, help='Ruta de la primera parte cifrada')
    decrypt_parser.add_argument('output_path', type=str, help='Ruta de salida del archivo descifrado')
    decrypt_parser.add_argument('base_password', type=str, help='Contraseña base para el descifrado')

    args = parser.parse_args()

    if args.command == 'encrypt':
        split_and_encrypt(args.input_path, args.chunk_size, args.base_password)
    elif args.command == 'decrypt':
        decrypt_and_merge(args.first_part_path, args.output_path, args.base_password)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()