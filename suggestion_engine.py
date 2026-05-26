"""Password suggestion generator."""

import random
import string


class SuggestionEngine:
    """Generates strong password suggestions."""

    def __init__(self):
        """Initialize suggestion engine."""
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        self.memorable_words = [
            'Alpha', 'Bravo', 'Charlie', 'Delta', 'Echo', 'Foxtrot',
            'Galaxy', 'Horizon', 'Infinite', 'Journey', 'Kinetic', 'Lunar',
        ]

    def generate_suggestions(self, count=3, length=14):
        """Generate multiple strong password suggestions.
        
        Args:
            count: Number of suggestions to generate
            length: Length of suggested passwords
            
        Returns:
            list: List of suggested passwords
        """
        suggestions = []
        for _ in range(count):
            suggestions.append(self.generate_random_password(length))
        return suggestions

    def generate_random_password(self, length=14):
        """Generate a random strong password.
        
        Args:
            length: Password length
            
        Returns:
            str: Generated password
        """
        # Ensure at least one of each character type
        password_chars = [
            random.choice(self.uppercase),
            random.choice(self.lowercase),
            random.choice(self.digits),
            random.choice(self.special),
        ]

        # Fill remaining length with random chars from all sets
        all_chars = self.lowercase + self.uppercase + self.digits + self.special
        password_chars.extend(
            random.choice(all_chars) for _ in range(length - 4)
        )

        # Shuffle to avoid predictable patterns
        random.shuffle(password_chars)
        return ''.join(password_chars)

    def generate_memorable_password(self, length=14):
        """Generate a memorable but strong password using words and numbers.
        
        Args:
            length: Approximate password length
            
        Returns:
            str: Generated password
        """
        # Pick 2 memorable words
        word1 = random.choice(self.memorable_words)
        word2 = random.choice(self.memorable_words)
        
        # Add numbers and special chars
        number = random.randint(10, 99)
        special_char = random.choice(self.special)
        
        password = f"{word1}{special_char}{word2}{number}"
        return password

    def generate_passphrase(self):
        """Generate a passphrase-style password.
        
        Returns:
            str: Generated passphrase
        """
        words = random.sample(self.memorable_words, 3)
        number = random.randint(100, 999)
        special_char = random.choice(self.special)
        
        passphrase = f"{'-'.join(words)}{special_char}{number}"
        return passphrase
