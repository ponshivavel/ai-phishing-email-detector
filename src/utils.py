import re
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import PorterStemmer
import tldextract
import Levenshtein
from typing import List, Tuple, Dict

# Download required NLTK data (run once)
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('punkt')
    nltk.download('stopwords')

STOP_WORDS = set(stopwords.words('english'))
STEMMER = PorterStemmer()
TRUSTED_AI_DOMAINS = [
    'openai.com', 'chat.openai.com', 'platform.openai.com', 'chatgpt.com',
    'google.com', 'gemini.google.com', 'bard.google.com',
    'anthropic.com', 'claude.ai', 'claude.anthropic.com',
    'microsoft.com', 'copilot.microsoft.com', 'bing.com',
    'huggingface.co', 'midjourney.com'
]

def analyze_domain(url: str) -> Dict[str, any]:
    """
    Advanced domain spoof detection.
    Returns: spoof_detected, similarity_score, reason
    """
    parsed = tldextract.extract(url)
    domain = f"{parsed.domain}.{parsed.suffix}"
    
    similarity = domain_similarity(domain, TRUSTED_AI_DOMAINS)
    spoof_detected = similarity > 0.65  # Lowered for .co, subdomains
    
    reason = ""
    if spoof_detected:
        closest = max(TRUSTED_AI_DOMAINS, key=lambda x: Levenshtein.ratio(domain, x))
        reason = f"Similar to {closest} (score: {similarity:.2f}) - Possible spoof"
    else:
        reason = "No trusted domain similarity detected"
    
    return {
        "spoof_detected": spoof_detected,
        "domain": domain,
        "similarity_score": round(similarity, 3),
        "reason": reason,
        "subdomain": parsed.subdomain,
        "full_url": url
    }

def clean_email(text: str) -> str:
    """
    Comprehensive email preprocessing pipeline.
    Steps: lowercase → remove punctuation → tokenize → remove stopwords → stemming
    """
    # 1. Lowercase
    text = text.lower()
    
    # 2. Remove punctuation
    text = re.sub(r'[^\w\s]', ' ', text)
    
    # 3. Tokenize
    tokens = word_tokenize(text)
    
    # 4. Remove stopwords + short words
    tokens = [t for t in tokens if t not in STOP_WORDS and len(t) > 2]
    
    # 5. Stemming
    stemmed = [STEMMER.stem(token) for token in tokens]
    
    return ' '.join(stemmed)

def extract_urls(text: str) -> List[str]:
    """Extract all URLs from email text using improved regex."""
    # Better URL regex for phishing URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;%=]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text, re.IGNORECASE)

def get_domain(url: str) -> str:
    """Extract registered domain from URL using tldextract."""
    parsed = tldextract.extract(url)
    return f"{parsed.domain}.{parsed.suffix}"

def domain_similarity(suspicious_domain: str, trusted_domains: List[str]) -> float:
    """
    Calculate minimum Levenshtein similarity to trusted domains.
    Returns similarity ratio (0-1, higher = more similar/suspicious)
    """
    max_similarity = 0
    for trusted in trusted_domains:
        ratio = Levenshtein.ratio(suspicious_domain.lower(), trusted.lower())
        max_similarity = max(max_similarity, ratio)
    return max_similarity

def is_suspicious_domain(domain: str, trusted_domains: List[str], threshold: float = 0.65) -> bool:
    """Check if domain is suspiciously similar to trusted brands (lower threshold for .co etc.)."""
    similarity = domain_similarity(domain, trusted_domains)
    return similarity > threshold

def detect_ai_brands(text: str) -> List[str]:
    """Detect AI brand mentions (case-insensitive substring match)."""
    ai_brands = [
        "chatgpt", "openai", "gemini", "google ai", "ai assistant", 
        "claude", "bard", "microsoft ai", "copilot", "huggingface", 
        "anthropic", "midjourney"
    ]
    text_lower = text.lower()
    return [brand for brand in ai_brands if brand in text_lower]

# Example usage and testing
if __name__ == "__main__":
    test_email = """
    ChatGPT Premium expired. Verify your OpenAI account now!
    Click: http://chatgpt-security.com/verify?login=yourpassword
    Urgent action required!
    """
    
    print("1. Cleaned:", clean_email(test_email))
    print("2. URLs:", extract_urls(test_email))
    print("3. AI Brands:", detect_ai_brands(test_email))
    
    fake_url = "http://openai-security.com/login"
    domain = get_domain(fake_url)
    print("4. Domain:", domain)
    print("5. Suspicious?", is_suspicious_domain(domain, TRUSTED_AI_DOMAINS))
    print("6. Similarity:", domain_similarity(domain, TRUSTED_AI_DOMAINS))

