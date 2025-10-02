import re

COMMON_PATTERNS = [
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).{12,}$',
]

def check_password_strength(pw: str, common_passwords_path: str = None):
    issues = []
    score = 0

    if len(pw) >= 12:
        score += 2
    elif len(pw) >= 8:
        score += 1
    else:
        issues.append('Very short (recommend >= 12 chars)')

    if re.search(r'[A-Z]', pw):
        score += 1
    else:
        issues.append('No uppercase letters')

    if re.search(r'[a-z]', pw):
        score += 1
    else:
        issues.append('No lowercase letters')

    if re.search(r'\d', pw):
        score += 1
    else:
        issues.append('No digits')

    if re.search(r'\W', pw):
        score += 1
    else:
        issues.append('No symbols')

    if common_passwords_path:
        try:
            with open(common_passwords_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if line.strip() and line.strip() == pw:
                        issues.append('Password exists in provided common-passwords file')
                        score = 0
                        break
        except Exception as e:
            issues.append(f"Couldn't open common passwords file: {e}")

    verdict = 'Weak'
    if score >= 6 and not issues:
        verdict = 'Strong'
    elif score >= 4:
        verdict = 'Moderate'
    else:
        verdict = 'Weak'

    return {'score': score, 'verdict': verdict, 'issues': issues}
