"""Optional fixture dependencies for testing both full and core-only distributions.

These tests exercise a shipped extension, rather than the core's fallback path.
The separate test_core_distribution module always runs and physically removes all
extensions to test that fallback. Unknown tests are never implicitly skipped.
"""
from pathlib import Path
import pytest

HERE = Path(__file__).resolve().parent.parent

# Module/class names are an explicit fixture manifest, not a blanket exclusion.
EXTENSION_FIXTURES = {
    'cliproxy': {
        'test_inspector.py': None,
        'test_review_p2.py': {'ViewProvenanceTest'},
        'test_wiretap.py': {'ProxyEnrichmentTest', 'PollerTest'},
    },
    'unified_sessions': {
        'test_wire_view.py': {'WireViewTypedParts'},
    },
}
EXTENSION_METHODS = {
    'credentials': {'test_wiretap.py': {'test_credential_fingerprint_without_a_proxy',
        'test_named_credential_resolves_to_its_pool_label',
        'test_codex_compressed_bodies_and_several_named_codex_credentials',
        'test_the_final_request_credential_wins',
        'test_retry_then_cross_family_fallback_keeps_one_row_with_the_answering_credential'}},
    'cliproxy': {'test_wiretap.py': {'test_failover_to_another_family_detaches_the_first_familys_proxy_log',
                                   'test_proxy_only_rows_take_the_hermes_provider_of_their_upstream',
                                   'test_repair_clears_proxy_client_tokens'},
                 'test_review_p2.py': {'test_nearer_calls_of_another_family_do_not_crowd_out_the_compatible_one',
                     'test_nearer_same_family_calls_of_another_model_do_not_crowd_out_the_compatible_one'}},
    'unified_sessions': {'test_session_adapter.py': {'test_sender_only_partial_schema_overrides_misleading_text',
        'test_parts_only_partial_schema_supplies_authorship_and_identity',
        'test_lineage_only_partial_schema_labels_child_assignment', 'test_invalid_part_entries_are_ignored'}},
}


def pytest_collection_modifyitems(items):
    for item in items:
        for extension in EXTENSION_FIXTURES.keys() | EXTENSION_METHODS.keys():
            if (HERE/'extensions'/f'{extension}.py').is_file():
                continue
            modules = EXTENSION_FIXTURES.get(extension, {})
            classes = modules.get(item.path.name, ())
            cls = getattr(item, 'cls', None)
            fixture_requires = item.path.name in modules and (classes is None or cls and cls.__name__ in classes)
            methods = EXTENSION_METHODS.get(extension, {}).get(item.path.name, ())
            if fixture_requires or item.originalname in methods:
                item.add_marker(pytest.mark.skip(reason=f'Optional {extension} extension fixture is not shipped in this core-only distribution'))
