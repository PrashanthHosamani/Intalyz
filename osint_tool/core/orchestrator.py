"""
core/orchestrator.py
Central orchestrator — discovers adapters, runs them concurrently,
and hands results to the analysis pipeline.
"""

import logging
import concurrent.futures
from typing import List, Dict, Any

from core.base_adapter import BaseAdapter, AdapterResult

logger = logging.getLogger(__name__)


class Orchestrator:
    """
    Runs all registered adapters in parallel (thread pool) and
    aggregates their AdapterResult objects into a unified findings dict.
    """

    def __init__(self, adapters: List[BaseAdapter], max_workers: int = 6):
        self.adapters    = adapters
        self.max_workers = max_workers

    def run(self, entity: str, entity_type: str) -> Dict[str, Any]:
        """
        Execute every adapter concurrently.

        Returns:
            {
                "entity":       str,
                "entity_type":  str,
                "results":      List[AdapterResult.to_dict()],
                "errors":       List[str],
            }
        """
        logger.info("🔍 Starting OSINT run for: %s (%s)", entity, entity_type)

        all_results: List[Dict] = []
        all_errors:  List[str]  = []

        def _run_adapter(adapter: BaseAdapter):
            try:
                logger.info("  ▶ Running adapter: %s", adapter.ADAPTER_NAME)
                result = adapter.fetch(entity, entity_type)
                logger.info(
                    "  ✔ %s — %d records found",
                    adapter.ADAPTER_NAME, len(result.data)
                )
                return result
            except Exception as exc:
                logger.error("  ✖ %s failed: %s", adapter.ADAPTER_NAME, exc)
                return AdapterResult(
                    adapter_name=adapter.ADAPTER_NAME,
                    category=adapter.CATEGORY,
                    data=[],
                    errors=[str(exc)],
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(_run_adapter, a): a for a in self.adapters}
            for future in concurrent.futures.as_completed(futures):
                result: AdapterResult = future.result()
                all_results.append(result.to_dict())
                all_errors.extend(result.errors)

        logger.info("✅ Orchestration complete — %d adapters ran", len(self.adapters))

        return {
            "entity":      entity,
            "entity_type": entity_type,
            "results":     all_results,
            "errors":      all_errors,
        }
