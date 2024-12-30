import click
from cryptography import classic_ciphers, modern_ciphers, file_operations

@click.group()
def cli():
    """CryptoTool - A comprehensive cryptography toolkit"""
    pass

@cli.command()
@click.option('--algorithm', type=click.Choice(['caesar', 'vigenere', 'aes', 'rsa']), required=True)
@click.option('--mode', type=click.Choice(['encrypt', 'decrypt']), required=True)
@click.option('--input', required=True, help='Input text or file path')
@click.option('--key', required=True, help='Encryption/Decryption key')
def process(algorithm, mode, input, key):
    """Encrypt or decrypt data using various algorithms"""
    if algorithm in ['caesar', 'vigenere']:
        processor = classic_ciphers
    else:
        processor = modern_ciphers
    
    result = processor.process(algorithm, mode, input, key)
    click.echo(f"Result: {result}")

if __name__ == '__main__':
    cli()
