import binascii
import math
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from PIL import Image

def split_data(secret_data, num_users):
    """Split the secret data into N chunks for multi-user steganography."""
    chunk_size = math.ceil(len(secret_data) / num_users)  # Calculate the chunk size for each user
    return [secret_data[i:i + chunk_size] for i in range(0, len(secret_data), chunk_size)]

def generate_rsa_keys(user_id):
    """Generate RSA public/private keys for each user and save them."""
    key = RSA.generate(2048)
    private_key = key.export_key()  # Export the private key
    public_key = key.publickey().export_key()  # Export the public key
    
    with open(f'keys/{user_id}_private.pem', 'wb') as f:
        f.write(private_key)
    
    with open(f'keys/{user_id}_public.pem', 'wb') as f:
        f.write(public_key)
        
    print(f"RSA keys for user {user_id} generated.")

def encrypt_data(data, public_key_path):
    """Encrypt the given data using the user's public RSA key."""
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(public_key)

    # Convert the data to binary
    binary_data = text_to_bin(data)

    # Max size of the data that can be encrypted with a 2048-bit RSA key (256 bytes)
    max_block_size = 2048 // 8  # 256 bytes for 2048-bit key

    # Split binary data into chunks of appropriate size
    chunks = [binary_data[i:i + max_block_size * 8] for i in range(0, len(binary_data), max_block_size * 8)]

    encrypted_data = b""
    for chunk in chunks:
        chunk_bytes = int(chunk, 2).to_bytes((len(chunk) + 7) // 8, byteorder='big')
        encrypted_data += cipher.encrypt(chunk_bytes)

    return encrypted_data

def text_to_bin(text):
    """Convert text or bytes into a binary string."""
    if isinstance(text, str):  
        return ''.join(format(ord(char), '08b') for char in text)
    elif isinstance(text, bytes):  
        return ''.join(format(byte, '08b') for byte in text)
    else:
        raise TypeError("Input must be either a string or bytes")

def bin_to_text(binary_data):
    """Convert binary data back to text."""
    binary_data = binary_data.zfill((len(binary_data) + 7) // 8 * 8)  # Ensure the binary string length is a multiple of 8
    text = ''.join(chr(int(binary_data[i:i + 8], 2)) for i in range(0, len(binary_data), 8))
    return text

def embed_data(image_path, data, user_id):
    """Embed encrypted data into an image."""
    # Open the image
    img = Image.open(image_path)
    
    # Convert the data to binary
    binary_data = text_to_bin(data)
    print(f"Data to embed: {binary_data[:64]}... (Total length: {len(binary_data)} bits)")
    
    # Calculate the required number of pixels to store the data
    required_pixels = math.ceil(len(binary_data) / 3)  # Since 1 pixel stores 3 bits
    img_width, img_height = img.size
    total_pixels = img_width * img_height
    
    print(f"Required pixels: {required_pixels}, Total pixels in image: {total_pixels}")
    
    # Check if the image has enough pixels to embed the data
    if required_pixels > total_pixels:
        raise ValueError(f"Image not large enough to hold the data. Required {required_pixels} pixels, but the image only has {total_pixels} pixels.")
    
    # Get image data (list of RGB tuples)
    img_data = img.getdata()
    
    # List to store new image data
    new_img_data = []
    
    # Data embedding logic
    data_index = 0
    for pixel in img_data:
        r, g, b = pixel
        
        if data_index < len(binary_data):
            r = (r & 0xFE) | int(binary_data[data_index])  # Embed data in red channel (LSB)
            data_index += 1
        if data_index < len(binary_data):
            g = (g & 0xFE) | int(binary_data[data_index])  # Embed data in green channel (LSB)
            data_index += 1
        if data_index < len(binary_data):
            b = (b & 0xFE) | int(binary_data[data_index])  # Embed data in blue channel (LSB)
            data_index += 1
        
        new_img_data.append((r, g, b))  # Append the modified pixel
        
        if data_index == len(binary_data):
            break
    
    # Update the image with the new pixel data
    img.putdata(new_img_data)
    
    # Save the modified image
    img.save(f"data/embedded_image_{user_id}.png")
    print(f"User {user_id}'s data embedded in the image.")

def extract_data(image_path, expected_data_length):
    """Extract encrypted data from an image."""
    img = Image.open(image_path)
    img_data = img.getdata()
    
    binary_data = ''
    for pixel in img_data:
        r, g, b = pixel
        binary_data += str(r & 1)
        binary_data += str(g & 1)
        binary_data += str(b & 1)
        
        if len(binary_data) >= expected_data_length * 8:
            break

    # If the length of the binary string is less than expected, we might need to pad
    if len(binary_data) < expected_data_length * 8:
        print(f"Warning: Extracted data is shorter than expected. Data length: {len(binary_data)//8} bytes.")
    
    # Convert binary data back to bytes
    encrypted_data_bytes = int(binary_data, 2).to_bytes((len(binary_data) + 7) // 8, byteorder='big')
    
    return encrypted_data_bytes

