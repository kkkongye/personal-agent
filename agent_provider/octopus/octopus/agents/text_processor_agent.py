"""
Text Processing Agent - Example agent for text analysis and processing.

Enhancements:
- Better multilingual tokenization with optional jieba for Chinese.
- Chinese stopwords and sentiment lexicon support.
- Sentence splitting supports Chinese punctuation.
"""

import re
from collections import Counter
from typing import Any

from octopus.agents.base_agent import BaseAgent
from octopus.router.agents_router import agent_interface, register_agent

# -----------------------------
# Utilities for tokenization
# -----------------------------

_CJK_RANGE = "[\u4e00-\u9fff]"  # Basic CJK Unified Ideographs


def _contains_cjk(text: str) -> bool:
    return bool(re.search(_CJK_RANGE, text))


def _tokenize(text: str) -> list[str]:
    """Tokenize text for both Latin and CJK scripts.

    Strategy:
    - If CJK is detected, try jieba; fallback to contiguous CJK sequences.
    - Else, use a simple alnum-based tokenizer for Latin languages.
    - Trim empty tokens.
    """
    text = text.strip()
    if not text:
        return []

    if _contains_cjk(text):
        # Prefer jieba for Chinese tokenization if available
        try:
            import jieba  # type: ignore

            tokens = [t.strip() for t in jieba.lcut(text, cut_all=False)]
            tokens = [t for t in tokens if t]
        except Exception:
            # Fallback: split into contiguous CJK sequences (coarse-grained)
            tokens = re.findall(rf"{_CJK_RANGE}+", text)
    else:
        # Latin-based tokenization (case-insensitive)
        tokens = re.findall(r"[A-Za-z0-9']+", text.lower())

    return tokens


def _remove_stopwords(tokens: list[str]) -> list[str]:
    """Remove simple English and Chinese stopwords.

    Note: Keep this list small and safe for demo purposes; users can extend.
    """
    if not tokens:
        return tokens

    if any(re.search(_CJK_RANGE, t) for t in tokens):
        # Minimal Chinese stopwords suitable for demos
        zh_stop = {
            "的",
            "了",
            "在",
            "是",
            "我",
            "也",
            "很",
            "和",
            "就",
            "都",
            "而",
            "及",
            "与",
            "或",
            "一个",
            "没有",
            "我们",
            "你",
            "他",
            "她",
            "它",
            "这",
            "那",
            "之",
        }
        return [t for t in tokens if t not in zh_stop]
    else:
        en_stop = {
            "the",
            "a",
            "an",
            "and",
            "or",
            "but",
            "in",
            "on",
            "at",
            "to",
            "for",
            "of",
            "with",
            "by",
            "is",
            "was",
            "are",
            "were",
        }
        return [t for t in tokens if t not in en_stop and len(t) > 1]


def _split_sentences(text: str) -> list[str]:
    """Split text into sentences, supporting both Latin and Chinese punctuation."""
    # Include Chinese punctuation: 。！？； as well as English .!?
    sentences = re.split(r"[。！？.!?]+", text)
    return [s.strip() for s in sentences if s and s.strip()]


@register_agent(
    name="text_processor",
    description="Text processing and analysis agent",
    version="1.0.0",
    tags=["text", "nlp", "analysis"],
)
class TextProcessorAgent(BaseAgent):
    """Agent specialized in text processing and analysis tasks."""

    def __init__(self):
        """Initialize the text processor agent."""
        super().__init__(
            name="TextProcessor",
            description="Handles text analysis and processing tasks",
        )

    @agent_interface(
        description="Count words in text",
        parameters={"text": {"description": "Text to analyze"}},
        returns="dict",
    )
    def count_words(self, text: str) -> dict[str, int]:
        """
        Count words in the given text.

        Args:
            text: Input text

        Returns:
            Dictionary with word count statistics
        """
        # Use robust tokenizer; for Chinese this avoids treating the whole
        # sentence as one token.
        words = _remove_stopwords(_tokenize(text))
        return {
            "total_words": len(words),
            "unique_words": len(set(words)),
            "average_word_length": sum(len(word) for word in words) / len(words)
            if words
            else 0,
        }

    @agent_interface(
        description="Extract keywords from text",
        parameters={
            "text": {"description": "Text to extract keywords from"},
            "top_n": {"description": "Number of top keywords to return"},
        },
        returns="list",
    )
    def extract_keywords(self, text: str, top_n: int = 10) -> list[dict[str, Any]]:
        """
        Extract top keywords from text based on frequency.

        Args:
            text: Source text
            top_n: Number of keywords to extract

        Returns:
            List of keywords with frequencies
        """
        # Tokenize and remove stopwords. Works for both English and Chinese.
        words = _remove_stopwords(_tokenize(text))

        # Simple heuristic: drop very short Latin tokens again (already handled),
        # keep Chinese tokens as-is since many are single-character words.
        word_freq = Counter(words)

        # Get top keywords
        top_keywords = word_freq.most_common(top_n)

        return [{"keyword": word, "frequency": freq} for word, freq in top_keywords]

    @agent_interface(
        description="Analyze text sentiment (simplified)",
        parameters={"text": {"description": "Text to analyze sentiment"}},
        returns="dict",
    )
    def analyze_sentiment(self, text: str) -> dict[str, Any]:
        """
        Perform simple sentiment analysis on text.

        Args:
            text: Text to analyze

        Returns:
            Sentiment analysis results
        """
        # Simple sentiment analysis using keyword matching (EN + ZH)
        en_positive = {
            "good",
            "great",
            "excellent",
            "amazing",
            "wonderful",
            "fantastic",
            "happy",
            "joy",
            "love",
            "best",
            "like",
        }
        en_negative = {
            "bad",
            "terrible",
            "awful",
            "horrible",
            "worst",
            "hate",
            "sad",
            "angry",
            "disappointed",
            "poor",
            "dislike",
        }

        zh_positive = {
            "好",
            "很好",
            "喜欢",
            "非常喜欢",
            "优秀",
            "精彩",
            "出色",
            "满意",
            "棒",
            "给力",
            "紧凑",
            "到位",
        }
        zh_negative = {
            "不好",
            "很差",
            "差",
            "失望",
            "糟糕",
            "讨厌",
            "最差",
            "混乱",
            "拉垮",
            "平庸",
        }

        if _contains_cjk(text):
            # For Chinese, do substring matching against the raw text
            positive_count = sum(1 for w in zh_positive if w in text)
            negative_count = sum(1 for w in zh_negative if w in text)
            # Also consider English words if any appear in the text
            tokens = set(_remove_stopwords(_tokenize(text)))
            positive_count += len(tokens.intersection(en_positive))
            negative_count += len(tokens.intersection(en_negative))
        else:
            tokens = set(_remove_stopwords(_tokenize(text)))
            positive_count = len(tokens.intersection(en_positive))
            negative_count = len(tokens.intersection(en_negative))

        total_sentiment_words = positive_count + negative_count

        if total_sentiment_words == 0:
            sentiment = "neutral"
            confidence = 0.5
        else:
            positive_ratio = positive_count / total_sentiment_words
            if positive_ratio > 0.6:
                sentiment = "positive"
                confidence = positive_ratio
            elif positive_ratio < 0.4:
                sentiment = "negative"
                confidence = 1 - positive_ratio
            else:
                sentiment = "neutral"
                confidence = 0.5

        return {
            "sentiment": sentiment,
            "confidence": round(confidence, 2),
            "positive_words": positive_count,
            "negative_words": negative_count,
        }

    @agent_interface(
        description="Summarize text (extractive summary)",
        parameters={
            "text": {"description": "Text to summarize"},
            "num_sentences": {"description": "Number of sentences in summary"},
        },
        returns="dict",
    )
    def summarize_text(self, text: str, num_sentences: int = 3) -> dict[str, Any]:
        """
        Create a simple extractive summary of the text.

        Args:
            text: Text to summarize
            num_sentences: Number of sentences to include in summary

        Returns:
            Summary information
        """
        # Split into sentences (support Chinese punctuation)
        sentences = _split_sentences(text)

        if len(sentences) <= num_sentences:
            return {
                "summary": text,
                "original_sentences": len(sentences),
                "summary_sentences": len(sentences),
            }

        # Simple scoring based on word frequency
        tokens_all = _remove_stopwords(_tokenize(text))
        word_freq = Counter(tokens_all)

        # Score sentences
        sentence_scores = []
        for sentence in sentences:
            words = _remove_stopwords(_tokenize(sentence))
            score = sum(word_freq[word] for word in words) / len(words) if words else 0
            sentence_scores.append((sentence, score))

        # Sort by score and take top sentences
        sentence_scores.sort(key=lambda x: x[1], reverse=True)
        summary_sentences = [s[0] for s in sentence_scores[:num_sentences]]

        # Reorder sentences as they appeared in original text
        summary_sentences = [s for s in sentences if s in summary_sentences]

        return {
            "summary": ". ".join(summary_sentences) + ".",
            "original_sentences": len(sentences),
            "summary_sentences": len(summary_sentences),
        }
