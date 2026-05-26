#!/usr/bin/env python3
"""Command-line interface for Password Strength Analyzer."""

import sys
from password_analyzer import PasswordAnalyzer
from strength_calculator import StrengthCalculator


def print_header():
    """Print application header."""
    print("\n" + "=" * 60)
    print(" " * 15 + "🔐 PASSWORD STRENGTH ANALYZER 🔐")
    print("=" * 60 + "\n")


def print_separator():
    """Print a separator line."""
    print("-" * 60)


def display_analysis(result):
    """Display analysis results in a formatted way.
    
    Args:
        result: Analysis result from PasswordAnalyzer
    """
    if 'error' in result:
        print(f"\n❌ Error: {result['error']}\n")
        return

    strength_calc = StrengthCalculator()
    score = result['score']
    strength = result['strength']
    color = strength_calc.get_color_indicator(score)

    print(f"\n{color} STRENGTH ANALYSIS RESULTS {color}")
    print_separator()
    print(f"Password Length: {result['length']} characters")
    print(f"Strength Score:  {score}/100")
    print(f"Strength Level:  {strength}")
    print(f"Overall Status:  {'✅ SECURE' if result['is_secure'] else '❌ WEAK'}")

    print("\n📊 METRICS:")
    metrics = result['metrics']
    print(f"  • Lowercase letters:     {'✅' if metrics['has_lowercase'] else '❌'}")
    print(f"  • Uppercase letters:     {'✅' if metrics['has_uppercase'] else '❌'}")
    print(f"  • Numbers:               {'✅' if metrics['has_numbers'] else '❌'}")
    print(f"  • Special characters:    {'✅' if metrics['has_special'] else '❌'}")
    print(f"  • Complexity score:      {metrics['complexity']}/4")
    print(f"  • Entropy (bits):        {metrics['entropy']}")

    print("\n💡 FEEDBACK:")
    for feedback_item in result['feedback']:
        print(f"  {feedback_item}")

    print("\n🎯 SUGGESTED STRONGER PASSWORDS:")
    for i, suggestion in enumerate(result['suggestions'], 1):
        print(f"  {i}. {suggestion}")

    print()


def interactive_mode():
    """Run the analyzer in interactive mode."""
    analyzer = PasswordAnalyzer(use_database=False)
    print_header()

    while True:
        try:
            password = input("Enter a password to analyze (or 'quit' to exit): ")

            if password.lower() == 'quit':
                print("\nThank you for using Password Strength Analyzer! 👋\n")
                break

            if not password:
                print("❌ Please enter a password.\n")
                continue

            result = analyzer.analyze(password)
            display_analysis(result)

        except KeyboardInterrupt:
            print("\n\nExiting... 👋\n")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}\n")


def demo_mode():
    """Run the analyzer in demo mode with sample passwords."""
    analyzer = PasswordAnalyzer(use_database=False)
    print_header()

    test_passwords = [
        "123456",
        "password",
        "MyPassword123",
        "P@ssw0rd!Secure#2024",
    ]

    print("Running demo analysis on sample passwords...\n")
    print_separator()

    for password in test_passwords:
        print(f"\nAnalyzing: {'*' * len(password)}")
        result = analyzer.analyze(password)
        display_analysis(result)
        print_separator()


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        if sys.argv[1] == '--demo':
            demo_mode()
        elif sys.argv[1] == '--help':
            print("""
Password Strength Analyzer - Usage:

  python main.py              Interactive mode (analyze passwords interactively)
  python main.py --demo       Demo mode (test with sample passwords)
  python main.py --help       Show this help message

Features:
  - Analyze password strength (length, complexity, entropy)
  - Get strength score (0-100) and level classification
  - Receive detailed feedback and suggestions
  - Optional: Track password history and prevent reuse

""")
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Use 'python main.py --help' for usage information.\n")
    else:
        interactive_mode()


if __name__ == '__main__':
    main()
