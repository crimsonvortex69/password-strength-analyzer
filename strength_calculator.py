"""Password strength scoring algorithm."""


class StrengthCalculator:
    """Calculates password strength score based on metrics."""

    # Strength levels and their thresholds
    STRENGTH_LEVELS = {
        'Very Weak': (0, 20),
        'Weak': (20, 40),
        'Fair': (40, 60),
        'Good': (60, 75),
        'Strong': (75, 90),
        'Very Strong': (90, 101),
    }

    def calculate_score(self, metrics):
        """Calculate overall password strength score (0-100).
        
        Args:
            metrics: Dictionary of password metrics from PasswordAnalyzer
            
        Returns:
            int: Strength score (0-100)
        """
        score = 0

        # Length scoring (max 30 points)
        length = metrics['length']
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 10:
            score += 20
        elif length >= 8:
            score += 15
        elif length >= 6:
            score += 10
        else:
            score += max(0, length * 2)

        # Complexity scoring (max 40 points)
        complexity = metrics['complexity']
        complexity_scores = {
            1: 10,   # Only lowercase or uppercase
            2: 20,   # Two types
            3: 30,   # Three types
            4: 40,   # All four types
        }
        score += complexity_scores.get(complexity, 0)

        # Entropy scoring (max 30 points)
        entropy = metrics['entropy']
        if entropy >= 80:
            score += 30
        elif entropy >= 60:
            score += 25
        elif entropy >= 50:
            score += 20
        elif entropy >= 40:
            score += 15
        elif entropy >= 30:
            score += 10
        else:
            score += max(0, int(entropy / 3))

        return min(100, score)  # Cap at 100

    def get_strength_level(self, score):
        """Get strength level name from score.
        
        Args:
            score: Numerical strength score
            
        Returns:
            str: Strength level name
        """
        for level, (min_score, max_score) in self.STRENGTH_LEVELS.items():
            if min_score <= score < max_score:
                return level
        return 'Very Strong'

    def get_color_indicator(self, score):
        """Get color indicator for score visualization.
        
        Args:
            score: Numerical strength score
            
        Returns:
            str: Color code
        """
        colors = {
            'Very Weak': '🔴',
            'Weak': '🟡',
            'Fair': '🟡',
            'Good': '🟢',
            'Strong': '💙',
            'Very Strong': '💎',
        }
        level = self.get_strength_level(score)
        return colors.get(level, '⚪')
