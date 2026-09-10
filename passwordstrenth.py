
import re, sqlite3, os, hashlib, secrets, string
from datetime import datetime
from pathlib import Path


class PasswordStrengthChecker:
    """Checks password strength: length, complexity, patterns, uniqueness."""
    
    MIN_LENGTHS = [8, 10, 12, 16]
    
    def __init__(self, db_path=None):
        self.db_path = db_path
        if db_path:
            self._init_db()
    
    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.execute('''CREATE TABLE IF NOT EXISTS password_history 
            (id INTEGER PRIMARY KEY, password_hash TEXT UNIQUE, username TEXT, created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        conn.commit()
        conn.close()
    
    def _hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def check_length(self, password):
        length = len(password)
        thresholds = [(8, 0), (10, 1), (12, 2), (16, 3)]
        score = 4 if length >= 16 else next((s for t, s in thresholds if length < t), 4)
        feedback = {0: f'Too short ({length})', 1: f'Short ({length})', 2: f'Moderate ({length})', 3: f'Good ({length})', 4: f'Excellent ({length})'}
        return {'score': score, 'feedback': feedback[score]}
    
    def check_complexity(self, password):
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_\-+=\[\]{};:\'",.<>?/\\|`~]', password))
        
        count = sum([has_lower, has_upper, has_digit, has_special])
        missing = []
        if not has_lower: missing.append('lowercase')
        if not has_upper: missing.append('UPPERCASE')
        if not has_digit: missing.append('digits')
        if not has_special: missing.append('special')
        
        feedback = ['No diversity', 'One type', 'Two types', 'Three types', 'All types']
        return {'score': count, 'character_types': count, 'missing': missing, 'feedback': feedback[count]}
    
    def check_patterns(self, password):
        issues = []
        if re.search(r'abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|123|234|345|456|567|678|789', password.lower()):
            issues.append('Sequential chars')
        if re.search(r'(.)\1{2,}', password):
            issues.append('Repeated chars')
        for pattern in ['qwerty', 'asdf', 'zxcv', 'qazwsx', '123456', 'abc123']:
            if pattern in password.lower(): issues.append(f'Keyboard: {pattern}')
        for word in ['password', 'admin', 'letmein', 'welcome', 'monkey', 'dragon']:
            if word in password.lower(): issues.append(f'Common: {word}')
        return {'has_issues': len(issues) > 0, 'issues': issues}
    
    def check_uniqueness(self, password, username=None):
        if not self.db_path:
            return {'is_unique': True, 'feedback': 'DB not configured', 'can_store': False}
        try:
            conn = sqlite3.connect(self.db_path)
            result = conn.execute('SELECT username FROM password_history WHERE password_hash = ?', (self._hash_password(password),)).fetchone()
            conn.close()
            return {'is_unique': not result, 'feedback': f'Used by {result[0]}' if result else 'Unique', 'can_store': not result}
        except Exception as e:
            return {'is_unique': True, 'feedback': f'Error: {e}', 'can_store': False}
    
    def store_password(self, password, username):
        if not self.db_path: return False
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('INSERT INTO password_history (password_hash, username) VALUES (?, ?)', (self._hash_password(password), username))
            conn.commit()
            conn.close()
            return True
        except: return False
    
    def calculate_overall_strength(self, length_score, complexity_score, has_pattern_issues):
        score = (length_score * 10 + complexity_score * 10) - (20 if has_pattern_issues else 0)
        score = max(0, score)
        strength_map = [(20, 'WEAK'), (40, 'FAIR'), (65, 'GOOD'), (85, 'STRONG')]
        strength = next((s for t, s in strength_map if score < t), 'VERY_STRONG')
        return {'strength': strength, 'score': score}
    
    def analyze_password(self, password, username=None):
        l = self.check_length(password)
        c = self.check_complexity(password)
        p = self.check_patterns(password)
        u = self.check_uniqueness(password, username)
        o = self.calculate_overall_strength(l['score'], c['score'], p['has_issues'])
        return {'length': l, 'complexity': c, 'patterns': p, 'uniqueness': u, 'overall': o}
    
    def suggest_stronger_password(self, password, length=16):
        base = re.sub(r'[^a-zA-Z0-9]', '', password)[:6]
        chars = string.ascii_letters + string.digits + string.punctuation
        pwd = list(base) + [secrets.choice(chars) for _ in range(length - len(base))]
        secrets.SystemRandom().shuffle(pwd)
        return ''.join(pwd)
    
    def generate_strong_password(self, length=16, use_special_chars=True):
        length = max(12, length)
        chars = string.ascii_letters + string.digits + (string.punctuation if use_special_chars else '')
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def display_analysis(self, analysis):
        o = analysis['overall']
        print(f"\n{'='*50}\nSTRENGTH: {o['strength']} ({o['score']}/100)\n{'='*50}")
        print(f"Length: {analysis['length']['feedback']}")
        print(f"Complexity: {analysis['complexity']['feedback']}")
        if analysis['patterns']['has_issues']:
            print(f"Patterns: {', '.join(analysis['patterns']['issues'])}")
        print()


def main():
    checker = PasswordStrengthChecker()
    tests = [('weak123', 'Weak'), ('MyPass123', 'Medium'), ('Sec2024@Pass!', 'Strong'), ('Xp9@mKz#vL2nRw5', 'VeryStrong')]
    for pwd, desc in tests:
        print(f"\n{desc}: {pwd}")
        checker.display_analysis(checker.analyze_password(pwd))

if __name__ == '__main__':
    main()
 