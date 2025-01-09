from utils import generate_rsa_keys, encrypt_data, embed_data, extract_data, split_data
import os

def generate_keys_for_users(num_users):
    """Generate RSA keys for multiple users."""
    for user_id in range(1, num_users + 1):
        generate_rsa_keys(user_id)

def prepare_data_for_embedding(secret_data, num_users):
    """Split the secret data and encrypt each chunk for a specific user."""
    data_chunks = split_data(secret_data, num_users)
    encrypted_chunks = []

    for user_id, chunk in enumerate(data_chunks, start=1):
        encrypted_chunk = encrypt_data(chunk, f"keys/{user_id}_public.pem")
        encrypted_chunks.append(encrypted_chunk)
    
    return encrypted_chunks

def embed_data_in_image(image_path, encrypted_chunks, num_users):
    """Embed encrypted data for each user into the image."""
    for user_id in range(1, num_users + 1):
        # Take the corresponding chunk for the user
        encrypted_data = encrypted_chunks[user_id - 1]
        # Embed the data into the image
        embed_data(image_path, encrypted_data, user_id)

def extract_data_for_user(image_path, user_id, data_length):
    """Extract encrypted data for a specific user from the image."""
    encrypted_data = extract_data(image_path, data_length)
    return encrypted_data

def main():
    # Setup
    num_users = 4  # Example: 4 users
    secret_data = "This is a secret message that needs to be split and encrypted."
    image_path = ".\\data\\3a61c0d5192356a24312cfcb9af3f45b.jpg"
    
    # Generate RSA keys for each user
    generate_keys_for_users(num_users)
    
    # Prepare the encrypted data for embedding
    encrypted_chunks = prepare_data_for_embedding(secret_data, num_users)
    
    # Embed encrypted data in the image
    embed_data_in_image(image_path, encrypted_chunks, num_users)
    
    # Assume user 1 is extracting their data
    data_length = len(secret_data) // num_users
    extracted_data = extract_data_for_user(image_path, 1, data_length)
    
    
    print(f"User 1 extracted encrypted data: {extracted_data}")
   

if __name__ == "__main__":
    main()
