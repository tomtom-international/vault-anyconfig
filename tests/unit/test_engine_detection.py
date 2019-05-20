import pytest
from hypothesis import given, example
import hypothesis.strategies as strat

from vault_anyconfig.vault_anyconfig import VaultAnyConfig


@given(contents=strat.text(min_size=1, alphabet=strat.characters(blacklist_categories=("C"))), secret_key=strat.text(min_size=1, alphabet=strat.characters(blacklist_categories=("C"))))
@example(contents="aoeu", secret_key="data")
@example(contents="aoeu", secret_key="metadata")
def test_detect_kv_v1(contents, secret_key, gen_vault_response_kv1, gen_vault_response_kv2):
    """
    Tests that kv1 is detected correctly
    """
    read_response_v1 = gen_vault_response_kv1(contents, secret_key)
    read_response_v2 = gen_vault_response_kv2(contents, secret_key)

    assert VaultAnyConfig._VaultAnyConfig__is_key_value_v1(
        read_response_v1, secret_key)
    assert not VaultAnyConfig._VaultAnyConfig__is_key_value_v1(
        read_response_v2, secret_key)


@given(contents=strat.text(min_size=1, alphabet=strat.characters(blacklist_categories=("C"))), secret_key=strat.text(min_size=1, alphabet=strat.characters(blacklist_categories=("C"))))
@example(contents="aoeu", secret_key="data")
@example(contents="aoeu", secret_key="metadata")
def test_detect_kv_v2(contents, secret_key, gen_vault_response_kv1, gen_vault_response_kv2):
    """
    Tests that kv2 is detected correctly
    """
    read_response_v1 = gen_vault_response_kv1(contents, secret_key)
    read_response_v2 = gen_vault_response_kv2(contents, secret_key)

    assert VaultAnyConfig._VaultAnyConfig__is_key_value_v2(
        read_response_v2)
    assert not VaultAnyConfig._VaultAnyConfig__is_key_value_v2(
        read_response_v1)
