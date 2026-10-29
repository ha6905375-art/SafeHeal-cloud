"""Shared pytest fixtures for the AI tests."""

# Re-export the fake network fixture so every test module in ai/tests can use it.
from ai.tests.test_ai_integration import fake_net  # noqa: F401
