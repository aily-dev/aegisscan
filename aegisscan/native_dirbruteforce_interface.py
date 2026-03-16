"""
Bridge / abstraction layer for directory bruteforce helpers that can be
accelerated with C++.

Right now this module focuses on offloading **URL generation** for very large
wordlists to a C++ helper (aegis_native.dir_wordgen). HTTP requests و منطق
تحلیل پاسخ همچنان در Python و داخل `EnhancedDirectoryBruteforcer` انجام می‌شود.
"""

from typing import List

import logging

from .utils.wordlists import WordlistManager

logger = logging.getLogger(__name__)

try:
    from aegis_native import dir_wordgen as native_dir_wordgen

    HAS_NATIVE_DIR = True
except Exception:  # pragma: no cover - optional optimization
    native_dir_wordgen = None
    HAS_NATIVE_DIR = False


def generate_candidate_urls(
    base_url: str,
    words: List[str],
    extensions: List[str],
    max_exts_per_word: int = 10,
) -> List[str]:
    """
    Generate candidate URLs for directory bruteforce.

    If the native C++ helper is available, use it for faster generation on
    very large wordlists. Otherwise fall back to the pure Python logic
    equivalent to what `EnhancedDirectoryBruteforcer` used to do inline.
    """
    # Ensure base_url ends with '/'
    if not base_url.endswith("/"):
        base_url = base_url + "/"

    if HAS_NATIVE_DIR:
        try:
            return native_dir_wordgen.generate_paths(
                base_url,
                list(words),
                list(extensions),
                int(max_exts_per_word),
            )
        except Exception as e:  # pragma: no cover - defensive
            logger.debug(f"Native dir_wordgen failed, falling back to Python: {e}")

    # Pure Python fallback
    urls: List[str] = []
    for word in words:
        urls.append(f"{base_url}{word}/")
        urls.append(f"{base_url}{word}")
        for ext in extensions[:max_exts_per_word]:
            urls.append(f"{base_url}{word}.{ext}")

    return urls


