"""
Tests unitaires pour le module llm.
"""

import os
from unittest.mock import patch, MagicMock

from src.tp2.analysis.llm import (
    explain_with_llm,
    call_openai,
    call_gemini,
    _extract_openai_text,
    _extract_gemini_text,
    _safe_get,
)


class TestSafeGet:
    """Tests pour _safe_get helper."""

    def test_when_path_exists_then_return_value(self):
        # Given
        obj = {"a": {"b": {"c": "value"}}}
        path = ["a", "b", "c"]

        # When
        result = _safe_get(obj, path)

        # Then
        assert result == "value"

    def test_when_path_not_exists_then_return_default(self):
        # Given
        obj = {"a": {"b": {}}}
        path = ["a", "b", "c"]

        # When
        result = _safe_get(obj, path, default="default")

        # Then
        assert result == "default"

    def test_when_list_index_valid_then_return_value(self):
        # Given
        obj = {"items": [{"name": "first"}, {"name": "second"}]}
        path = ["items", 1, "name"]

        # When
        result = _safe_get(obj, path)

        # Then
        assert result == "second"

    def test_when_list_index_invalid_then_return_default(self):
        # Given
        obj = {"items": [{"name": "first"}]}
        path = ["items", 5, "name"]

        # When
        result = _safe_get(obj, path, default=None)

        # Then
        assert result is None


class TestExtractOpenaiText:
    """Tests pour _extract_openai_text."""

    def test_when_valid_response_then_extract_content(self):
        # Given
        data = {"choices": [{"message": {"content": "Ceci est l'analyse du shellcode."}}]}

        # When
        result = _extract_openai_text(data)

        # Then
        assert result == "Ceci est l'analyse du shellcode."

    def test_when_empty_choices_then_return_empty(self):
        # Given
        data = {"choices": []}

        # When
        result = _extract_openai_text(data)

        # Then
        assert result == ""

    def test_when_no_content_then_return_empty(self):
        # Given
        data = {"choices": [{"message": {}}]}

        # When
        result = _extract_openai_text(data)

        # Then
        assert result == ""


class TestExtractGeminiText:
    """Tests pour _extract_gemini_text."""

    def test_when_valid_response_then_extract_text(self):
        # Given
        data = {"candidates": [{"content": {"parts": [{"text": "Analyse Gemini du shellcode."}]}}]}

        # When
        result = _extract_gemini_text(data)

        # Then
        assert result == "Analyse Gemini du shellcode."

    def test_when_multiple_parts_then_concat_them(self):
        # Given
        data = {"candidates": [{"content": {"parts": [{"text": "Partie 1."}, {"text": "Partie 2."}]}}]}

        # When
        result = _extract_gemini_text(data)

        # Then
        # Si le premier path réussit, on obtient juste "Partie 1."
        # Sinon on obtient la concaténation
        assert "Partie 1" in result

    def test_when_empty_candidates_then_return_empty(self):
        # Given
        data = {"candidates": []}

        # When
        result = _extract_gemini_text(data)

        # Then
        assert result == ""


class TestCallOpenai:
    """Tests pour call_openai."""

    def test_when_no_api_key_then_return_error_message(self):
        # Given
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False):
            # When
            result = call_openai("test prompt", "test system")

            # Then
            assert "OPENAI_API_KEY" in result
            assert "manquante" in result.lower() or "missing" in result.lower()

    @patch("src.tp2.analysis.llm.requests.post")
    def test_when_api_returns_429_then_return_quota_error(self, mock_post):
        # Given
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=False):
            # When
            result = call_openai("test prompt", "test system")

            # Then
            assert "QUOTA" in result.upper() or "429" in result

    @patch("src.tp2.analysis.llm.requests.post")
    def test_when_api_returns_401_then_return_auth_error(self, mock_post):
        # Given
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=False):
            # When
            result = call_openai("test prompt", "test system")

            # Then
            assert "INVALIDE" in result.upper() or "401" in result

    @patch("src.tp2.analysis.llm.requests.post")
    def test_when_api_returns_valid_response_then_extract_text(self, mock_post):
        # Given
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"choices": [{"message": {"content": "Analyse réussie"}}]}
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=False):
            # When
            result = call_openai("test prompt", "test system")

            # Then
            assert result == "Analyse réussie"


class TestCallGemini:
    """Tests pour call_gemini."""

    def test_when_no_api_key_then_return_error_message(self):
        # Given
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}, clear=False):
            # When
            result = call_gemini("test prompt", "test system")

            # Then
            assert "GEMINI_API_KEY" in result
            assert "manquante" in result.lower() or "missing" in result.lower()

    @patch("src.tp2.analysis.llm.requests.post")
    def test_when_api_returns_429_then_return_quota_error(self, mock_post):
        # Given
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=False):
            # When
            result = call_gemini("test prompt", "test system")

            # Then
            assert "QUOTA" in result.upper() or "429" in result

    @patch("src.tp2.analysis.llm.requests.post")
    def test_when_api_returns_valid_response_then_extract_text(self, mock_post):
        # Given
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": "Analyse Gemini"}]}}]
        }
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=False):
            # When
            result = call_gemini("test prompt", "test system")

            # Then
            assert result == "Analyse Gemini"


class TestExplainWithLlm:
    """Tests pour explain_with_llm."""

    def test_when_provider_is_local_then_return_local_message(self):
        # Given
        with patch.dict(
            os.environ,
            {"OPENAI_API_KEY": "", "GEMINI_API_KEY": "", "TP2_LLM_PROVIDER": ""},
            clear=False,
        ):
            # When
            result = explain_with_llm("test prompt", provider="local")

            # Then
            assert "local" in result.lower()

    def test_when_no_keys_and_no_provider_then_fallback_to_local(self):
        # Given
        with patch.dict(
            os.environ,
            {"OPENAI_API_KEY": "", "GEMINI_API_KEY": "", "TP2_LLM_PROVIDER": ""},
            clear=False,
        ):
            # When
            result = explain_with_llm("test prompt")

            # Then
            assert "local" in result.lower()

    @patch("src.tp2.analysis.llm.call_openai")
    def test_when_provider_is_openai_then_call_openai(self, mock_call):
        # Given
        mock_call.return_value = "OpenAI response"

        # When
        result = explain_with_llm("test prompt", provider="openai")

        # Then
        mock_call.assert_called_once()
        assert result == "OpenAI response"

    @patch("src.tp2.analysis.llm.call_gemini")
    def test_when_provider_is_gemini_then_call_gemini(self, mock_call):
        # Given
        mock_call.return_value = "Gemini response"

        # When
        result = explain_with_llm("test prompt", provider="gemini")

        # Then
        mock_call.assert_called_once()
        assert result == "Gemini response"

    def test_when_env_provider_set_then_use_it(self):
        # Given
        with patch.dict(os.environ, {"TP2_LLM_PROVIDER": "local"}, clear=False):
            # When
            result = explain_with_llm("test prompt")

            # Then
            assert "local" in result.lower()
