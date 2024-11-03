from typing import Tuple
import random
import math
from collections import Counter

PASSWORD_CRITERIA = {
    # Length-related issues
    "TOO_SHORT": {
        "score": -30,
        "message": "Password is too short (minimum 8 characters required)",
        "example": "pass",
    },
    "RECOMMENDED_LONGER": {
        "score": -5,
        "message": "Password could be stronger with at least 12 characters",
        "example": "Password10!",
    },
    # Character composition
    "NO_UPPERCASE": {
        "score": -10,
        "message": "Missing uppercase letters",
        "example": "password123!",
    },
    "NO_LOWERCASE": {
        "score": -10,
        "message": "Missing lowercase letters",
        "example": "PASSWORD123!",
    },
    "NO_NUMBERS": {"score": -10, "message": "Missing numbers", "example": "Password!"},
    "NO_SPECIAL": {
        "score": -10,
        "message": "Missing special characters",
        "example": "Password123",
    },
    # Patterns and sequences
    "KEYBOARD_PATTERN": {
        "score": -20,
        "message": "Contains keyboard pattern (e.g., qwerty, asdf)",
        "example": "qwerty123",
    },
    "NUMERICAL_SEQUENCE": {
        "score": -15,
        "message": "Contains simple number sequence (e.g., 123, 987)",
        "example": "Password123",
    },
    "ALPHABETICAL_SEQUENCE": {
        "score": -15,
        "message": "Contains alphabetical sequence (e.g., abc, xyz)",
        "example": "Passwordabc!",
    },
    "REPEATED_CHARS": {
        "score": -15,
        "message": "Contains repeated characters (e.g., aaa, 111)",
        "example": "Password111!",
    },
    # Common substitutions
    "PREDICTABLE_SUBSTITUTIONS": {
        "score": -5,
        "message": "Uses common character substitutions (e.g., a->@, i->1)",
        "example": "P@ssw0rd",
    },
    # Structure
    "ONLY_LETTERS": {
        "score": -20,
        "message": "Contains only letters",
        "example": "Password",
    },
    "ONLY_NUMBERS": {
        "score": -25,
        "message": "Contains only numbers",
        "example": "12345678",
    },
    "COMMON_STRUCTURE": {
        "score": -10,
        "message": "Uses common password structure (e.g., Capitalize1!)",
        "example": "Password1!",
    },
    # Context and dictionary
    "COMMON_PASSWORD": {
        "score": -50,
        "message": "Matches commonly used password",
        "example": "admin",
    },
    "COMMON_WORD": {
        "score": -20,
        "message": "Contains common dictionary word",
        "example": "monkey123",
    },
    "YEAR_PATTERN": {
        "score": -15,
        "message": "Contains year-like pattern",
        "example": "Password1990!",
    },
    # Entropy
    "LOW_ENTROPY": {
        "score": -15,
        "message": "Low character diversity",
        "example": "aaaaaa123",
    },
    # Positive criteria
    "GOOD_LENGTH": {
        "score": 20,
        "message": "Good password length",
        "example": "ThisIsALongPassword123!",
    },
    "STRONG_VARIETY": {
        "score": 20,
        "message": "Good character variety",
        "example": "P@ssw0rd$123",
    },
    "HIGH_ENTROPY": {
        "score": 20,
        "message": "High character diversity",
        "example": "P@s$w0rd#123",
    },
}


def length_related_issues(password: str) -> str:
    length_of_password = len(password)

    if length_of_password < 8:
        return "TOO_SHORT"
    elif 8 <= length_of_password <= 11:
        return "RECOMMENDED_LONGER"


def character_composition(password: str) -> list[str]:
    character_composition = []

    if len([letter for letter in password if letter.isupper()]) == 0:
        character_composition.append("NO_UPPERCASE")
    if len([letter for letter in password if letter.islower()]) == 0:
        character_composition.append("NO_LOWERCASE")
    if len([letter for letter in password if letter.isdigit()]) == 0:
        character_composition.append("NO_NUMBERS")
    if len([letter for letter in password if not letter.isalnum()]) == 0:
        character_composition.append("NO_SPECIAL")

    return character_composition


def sequences(password: str, sequence: str, pattern_type: str) -> str:
    sequence_list = []
    for i in range(0, len(sequence) - 1):
        for j in range(i + 1, len(sequence)):
            sequence_list.append(sequence[i : j + 1])


    for sequence in sequence_list:
        if sequence in password:
            return pattern_type


def patterns_and_sequences(password: str) -> list[str]: 
    patterns_and_sequences = []
    for sequence, type in [
        ["qwertyuiopasdfghjklzxcvbnm", "KEYBOARD_PATTERN"],
        ["0123456789", "NUMERICAL_SEQUENCE"],
        ["abcdefghijklmnopqrstuvwxyz", "ALPHABETICAL_SEQUENCE"],
    ]:
        pattern_type = sequences(password, sequence, type)
        if pattern_type is not None:
            patterns_and_sequences.append(pattern_type)

        reversed_sequence = ''.join(reversed(sequence))

        pattern_type = sequences(password, reversed_sequence, type)
        if pattern_type is not None and pattern_type not in patterns_and_sequences:
            patterns_and_sequences.append(pattern_type)

    for letter in set(list(password)):
        flag = False
        for num in range(2, len(password) + 1):
            if letter * num in password:
                patterns_and_sequences.append("REPEATED_CHARS")
                flag = True
                break
        if flag:
            break

    return patterns_and_sequences


def common_substitutions(password: str) -> str:
    for i in range(len(password) - 2):
        if (
            password[i].isalpha()
            and ((not password[i + 1].isalnum()) or password[i + 1].isdigit())
            and password[i + 2].isalpha()
        ):
            return "PREDICTABLE_SUBSTITUTIONS"


def structure(password: str) -> str:

    if password.isdigit():
        return "ONLY_NUMBERS"
    else:
        if password[0].isupper() and password[:-2].isalpha():
            if not password[-1].isalnum():
                if password[-2].isdigit():
                    return "COMMON_STRUCTURE"


def context_and_dictionary(password: str) -> list[str]:
    context_and_dictionary = []
    common_used_passwords = [
        "admin",
        "root",
        "user",
        "password",
        "welcome",
        "login",
        "monkey",
        "superman",
        "princess",
        "letmein",
        "super",
        "jesus",
        "shadow",
        "football",
        "ninja",
        "dragon",
        "sunshine",
        "flower",
        "master",
    ]
    if (
        password.lower() in common_used_passwords
    ):
        context_and_dictionary.append("COMMON_PASSWORD")
    else:
        for word in common_used_passwords:
            if word in password.lower():
                context_and_dictionary.append("COMMON_WORD")
                break

        if password[0].isupper():  
            if not password[-1].isalnum():
                if (
                    password[-5:-1].isdigit()
                    and (not password[-6].isdigit())
                    or password[-3:-1].isdigit()
                    and (not password[-4].isdigit())
                ):
                    context_and_dictionary.append("YEAR_PATTERN")
            else:
                if (
                    password[-4:].isdigit()
                    and (not password[-5].isdigit())
                    or password[-2:].isdigit()
                    and (not password[-3].isdigit())
                ):
                    context_and_dictionary.append("YEAR_PATTERN")

    return context_and_dictionary


def calculate_entropy(password: str) -> float:
    char_count = Counter(password)
    length = len(password)

    entropy = 0.0
    for count in char_count.values():
        encounter_percent = count / length
        entropy -= encounter_percent * math.log2(encounter_percent)

    return entropy


def access_entropy(password: str) -> str:
    if calculate_entropy(password) < 2.5:
        return "LOW_ENTROPY"


def detect_patterns(password: str) -> list[str]:

    password_criteria_detected = [
        length_related_issues(password),
        *character_composition(password),
        *patterns_and_sequences(password),
        common_substitutions(password),
        structure(password),
        *context_and_dictionary(password),
        access_entropy(password),
    ]
    return [criteria for criteria in password_criteria_detected if criteria is not None]


def assess_password(password: str) -> Tuple[int, list[str]]:
    if password == "":
        return (0, [])

    password_criteria_detected = detect_patterns(password)
    score = 0
    issues = []

    for criteria in password_criteria_detected:
        score = score + PASSWORD_CRITERIA[criteria]["score"]
        issues.append(f'{criteria}: {PASSWORD_CRITERIA[criteria]["message"]}')


    if (
        "TOO_SHORT" not in password_criteria_detected
        and "RECOMMENDED_LONGER" not in password_criteria_detected
    ):
        score += 20
    else:
        if "TOO_SHORT" in password_criteria_detected:
            password_criteria_detected.remove("TOO_SHORT")
        elif "RECOMMENDED_LONGER" in password_criteria_detected:
            password_criteria_detected.remove("RECOMMENDED_LONGER")

    if "LOW_ENTROPY" not in password_criteria_detected:
        score += 20
    else:
        password_criteria_detected.remove("LOW_ENTROPY")

    if password_criteria_detected == []:
        score += 20

    return (score, issues)


def get_structural_fingerprint(password: str) -> dict:
    structural_fingerprint = {
        "character_types": [],
        "length": len(password),
        "uppercase_positions": [],
        "special_positions": [],
        "number_positions": [],
    }

    for i, char in enumerate(password):
        if char.isupper():
            structural_fingerprint["character_types"].append("upper")
            structural_fingerprint["uppercase_positions"].append(i)
        elif not char.isalnum():
            structural_fingerprint["character_types"].append("special")
            structural_fingerprint["special_positions"].append(i)
        elif char.isdigit():
            structural_fingerprint["character_types"].append("digit")
            structural_fingerprint["number_positions"].append(i)

    return structural_fingerprint


def generate_twin(password: str) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    numbers = "0123456789"
    special_characters = "!@#$%^&*()_+=-"

    structural_fingerprint = get_structural_fingerprint(password)
    twin = [False] * structural_fingerprint["length"]

    for char_type in structural_fingerprint["character_types"]:
        if char_type == "upper":
            for i in structural_fingerprint["uppercase_positions"]:
                twin[i] = random.choice(alphabet).upper()
        elif char_type == "digit":
            for i in structural_fingerprint["number_positions"]:
                twin[i] = random.choice(numbers)
        elif char_type == "special":
            for i in structural_fingerprint["special_positions"]:
                twin[i] = random.choice(special_characters)

    for char in range(structural_fingerprint["length"]):
        if not twin[char]:
            twin[char] = random.choice(alphabet)

    return "".join(twin)


password = "KK986gh"
score, issues = assess_password(password)
twin = generate_twin(password)
score_twin, issues_twin = assess_password(twin)
print(f"Original: {password}, Score: {score}")
print(f"Issues: {issues}")
print(f"Twin: {twin}, Score: {score_twin}")
print(f"Issues: {issues_twin}")
