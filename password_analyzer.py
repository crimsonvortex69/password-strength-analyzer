"""Main password analyzer module."""

import re
import math
from strength_calculator import StrengthCalculator
from suggestion_engine import SuggestionEngine
from database import PasswordDatabase


class PasswordAnalyzer:
    """Analyzes password strength and provides recommendations."""

    def __init__(self, use_database=False):
        """Initialize the analyzer.
        
        Args:
            use_database: Whether to track password history
        """
        self.strength_calculator = StrengthCalculator()
        self.suggestion_engine = SuggestionEngine()
        self.database = PasswordDatabase() if use_database else None
        self.common_patterns = self._compile_patterns()

    @staticmethod
    def _compile_patterns():
        """Compile regex patterns for common weak password patterns."""
        return {
            'sequential': re.compile(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)'),
            'repeated': re.compile(r'(.)\1{2,}'),  # 3+ repeated chars
            'keyboard': re.compile(r'(qwert|asdf|zxcv|qaz|wsx|edc)'),
            'dates': re.compile(r'(19|20)\d{2}'),
            'common_words': re.compile(r'(password|admin|letmein|welcome|monkey|dragon)'),
        }

    def analyze(self, password, user_email=None):
        """Analyze a password and return detailed results.
        
        Args:
            password: The password to analyze
            user_email: Optional email to check against history
            
        Returns:
            dict: Analysis results with score, strength, feedback, and suggestions
        """
        if not password:
            return self._error_result("Password cannot be empty")

        # Check password history if database is enabled
        if self.database and user_email:
            if self.database.is_password_reused(user_email, password):
                return self._error_result("This password has been used before. Please choose a different one.")

        # Calculate base metrics
        metrics = self._calculate_metrics(password)
        score = self.strength_calculator.calculate_score(metrics)
        strength = self.strength_calculator.get_strength_level(score)
        feedback = self._generate_feedback(metrics, password)
        suggestions = self.suggestion_engine.generate_suggestions()

        # Store in database if enabled
        if self.database and user_email:
            self.database.add_password(user_email, password)

        return {
            'password': '*' * len(password),  # Don't return plaintext
            'score': score,
            'strength': strength,
            'length': len(password),
            'metrics': metrics,
            'feedback': feedback,
            'suggestions': suggestions,
            'is_secure': score >= 70,
        }

    def _calculate_metrics(self, password):
        """Calculate password metrics.
        
        Args:
            password: The password to analyze
            
        Returns:
            dict: Password metrics
        """
        length = len(password)
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_numbers = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:,.<>?]', password))
        entropy = self._calculate_entropy(password)

        return {
            'length': length,
            'has_lowercase': has_lowercase,
            'has_uppercase': has_uppercase,
            'has_numbers': has_numbers,
            'has_special': has_special,
            'entropy': entropy,
            'complexity': sum([has_lowercase, has_uppercase, has_numbers, has_special]),
        }

    @staticmethod
    def _calculate_entropy(password):
        """Calculate password entropy (Shannon entropy).
        
        Args:
            password: The password to analyze
            
        Returns:
            float: Entropy value in bits
        """
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:,.<>?]', password):
            charset_size += 32

        if charset_size == 0:
            return 0

        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)

    def _generate_feedback(self, metrics, password):
        """Generate feedback on password weaknesses.
        
        Args:
            metrics: Password metrics
            password: The password to analyze
            
        Returns:
            list: List of feedback messages
        """
        feedback = []

        # Length feedback
        if metrics['length'] < 8:
            feedback.append("❌ Password is too short. Use at least 8 characters.")
        elif metrics['length'] < 12:
            feedback.append("⚠️  Consider using 12+ characters for better security.")
        else:
            feedback.append("✅ Good password length.")

        # Complexity feedback
        if not metrics['has_uppercase']:
            feedback.append("❌ Add uppercase letters (A-Z).")
        if not metrics['has_lowercase']:
            feedback.append("❌ Add lowercase letters (a-z).")
        if not metrics['has_numbers']:
            feedback.append("❌ Add numbers (0-9).")
        if not metrics['has_special']:
            feedback.append("❌ Add special characters (!@#$%^&*).")

        # Pattern detection
        for pattern_name, pattern in self.common_patterns.items():
            if pattern.search(password.lower()):
                feedback.append(f"⚠️  Avoid {pattern_name} patterns.")

        # Entropy feedback
        if metrics['entropy'] < 50:
            feedback.append("❌ Low entropy - password is predictable.")
        elif metrics['entropy'] < 70:
            feedback.append("⚠️  Medium entropy - could be stronger.")
        else:
            feedback.append("✅ Good entropy - password is unpredictable.")

        return feedback if feedback else ["✅ Password looks good!"]

    @staticmethod
    def _error_result(error_message):
        """Create an error result dictionary.
        
        Args:
            error_message: The error message
            
        Returns:
            dict: Error result
        """
        return {
            'error': error_message,
            'score': 0,
            'strength': 'Error',
            'is_secure': False,
        }
