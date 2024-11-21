import random
import hashlib
import os

class RSA:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None

    def is_prime(self, n, k=5):
        """Miller-Rabin primality test"""
        if n <= 1 or n == 4:
            return False
        if n <= 3:
            return True
        
        # Write n as 2^r * d + 1
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Witness loop
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            is_composite = True
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    is_composite = False
                    break
            
            if is_composite:
                return False
        
        return True

    def generate_large_prime(self, bits):
        """Generate a large prime number"""
        while True:
            candidate = random.getrandbits(bits)
            # Ensure the number is odd and has the right number of bits
            candidate |= (1 << bits - 1) | 1
            if self.is_prime(candidate):
                return candidate

    def generate_keypair(self):
        """Generate RSA key pair"""
        # Generate two large prime numbers
        p = self.generate_large_prime(self.key_size // 2)
        q = self.generate_large_prime(self.key_size // 2)
        
        # Compute n and totient
        n = p * q
        phi = (p - 1) * (q - 1)
        
        # Choose public exponent (typically 65537)
        e = 65537
        
        # Compute private key
        d = pow(e, -1, phi)
        
        self.public_key = (e, n)
        self.private_key = (d, n)
        
        return self.public_key, self.private_key

    def encrypt(self, message, public_key):
        """Encrypt message using public key"""
        e, n = public_key
        # Convert message to integer
        message_int = int.from_bytes(message.encode(), 'big')
        # Encrypt
        encrypted = pow(message_int, e, n)
        return encrypted

    def decrypt(self, encrypted_message):
        """Decrypt message using private key"""
        if not self.private_key:
            raise ValueError("Private key not generated")
        
        d, n = self.private_key
        # Decrypt
        decrypted_int = pow(encrypted_message, d, n)
        # Convert back to string
        decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')
        return decrypted_bytes.decode()

class PublicKeyAuthority:
    """Simulated Public Key Authority"""
    def __init__(self):
        self.registered_keys = {}

    def register_public_key(self, entity_id, public_key):
        """Register public key for an entity"""
        self.registered_keys[entity_id] = public_key
        print(f"Registered public key for {entity_id}")
        return True

    def get_public_key(self, entity_id):
        """Retrieve public key for an entity"""
        key = self.registered_keys.get(entity_id)
        if key:
            print(f"Retrieved public key for {entity_id}")
        else:
            print(f"No public key found for {entity_id}")
        return key

# Global Public Key Authority instance
public_key_authority = PublicKeyAuthority()