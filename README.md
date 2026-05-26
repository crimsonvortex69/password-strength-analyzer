# Password Strength Analyzer

A comprehensive tool that evaluates the strength of user-entered passwords and provides security recommendations.

## Features

✅ **Password Strength Evaluation**
- Length analysis
- Complexity checking (uppercase, lowercase, numbers, special characters)
- Pattern detection (sequential, repeated characters, common patterns)
- Entropy calculation

✅ **Strength Scoring System**
- Numerical score (0-100)
- Visual strength indicator (Very Weak, Weak, Fair, Good, Strong, Very Strong)
- Detailed feedback on weaknesses

✅ **Password Suggestions**
- Generate stronger password alternatives
- Customizable length and complexity
- Memorable but secure suggestions

✅ **Password History (Optional)**
- SQLite database integration
- Prevent reuse of old passwords
- Track password change history

## Installation

```bash
git clone https://github.com/crimsonvortex69/password-strength-analyzer.git
cd password-strength-analyzer
pip install -r requirements.txt
```

## Usage

### Command Line

```bash
python main.py
```

### As a Module

```python
from password_analyzer import PasswordAnalyzer

analyzer = PasswordAnalyzer()
result = analyzer.analyze('MyP@ssw0rd')
print(result)
```

## Project Structure

```
.
├── main.py                 # CLI entry point
├── password_analyzer.py    # Core analyzer logic
├── strength_calculator.py  # Strength scoring algorithm
├── suggestion_engine.py    # Password suggestion generator
├── database.py            # Password history database
├── requirements.txt       # Project dependencies
└── README.md             # This file
```

## Learning Outcomes

- Understanding password security best practices
- Implementing entropy and complexity calculations
- Basic cryptography concepts (hashing with bcrypt)
- Database design for secure storage
- Algorithm design for pattern recognition

## Security Notes

- Passwords are hashed using bcrypt before storage
- No plaintext passwords are stored
- Entropy calculations follow NIST guidelines
- Regular expression patterns detect common weaknesses

## Future Enhancements

- Integration with HaveIBeenPwned API
- Machine learning for pattern detection
- Multi-language support
- Web interface
- 2FA integration

## License

MIT License - See LICENSE file for details
