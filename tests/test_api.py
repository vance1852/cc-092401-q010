from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path

from robot_trials.api import JsonApplication
from robot_trials.clock import FrozenClock
from robot_trials.jsonio import load_json
from robot_trials.service import TrialService


ROOT = Path(__file__).resolve().parents[1]


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = TrialService(self.connection, self.clock, max_analysis_attempts=1)
        self.app = JsonApplication(self.service)

    def tearDown(self) -> None:
        self.connection.close()

    @staticmethod
    def _body(payload: dict) -> bytes:
        return json.dumps(payload).encode("utf-8")

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_json_error_shape(self) -> None:
        response = self.app.handle("POST", "/users", body=b"not-json")
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_user_route(self) -> None:
        payload = json.dumps({"user_id": "u1", "display_name": "操作员", "role": "operator"}).encode()
        response = self.app.handle("POST", "/users", body=payload)
        self.assertEqual(response.status, 201)
        self.assertEqual(response.body["role"], "operator")

    def _sealed_batch(self) -> None:
        self.service.create_user("operator", "操作员", "operator")
        self.service.create_user("stat", "统计负责人", "statistician")
        self.service.register_robot("operator", "robot-a", "A 型", "厂商")
        self.service.register_build("operator", "build-a", "robot-a", "1.0", "b" * 64)
        protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self.service.publish_protocol("stat", protocol)
        self.service.create_batch("operator", "batch-a", protocol["protocol_id"], 1, "build-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.seal_batch("stat", "batch-a", 2)

    def test_job_lifecycle_routes(self) -> None:
        self._sealed_batch()
        claimed = self.app.handle("POST", "/jobs/claim", body=self._body({"worker_id": "w1", "lease_seconds": 10}))
        self.assertEqual(claimed.status, 200)
        job = claimed.body["job"]
        self.assertEqual(job["fencing_token"], 1)

        renewed = self.app.handle(
            "POST",
            f"/jobs/{job['job_id']}/heartbeat",
            body=self._body({"worker_id": "w1", "fencing_token": 1, "lease_seconds": 30}),
        )
        self.assertEqual(renewed.status, 200)
        self.assertGreater(renewed.body["lease_expires_at"], job["lease_expires_at"])

        failed = self.app.handle(
            "POST",
            f"/jobs/{job['job_id']}/fail",
            body=self._body({"worker_id": "w1", "fencing_token": 1, "error": "计算失败"}),
        )
        self.assertEqual(failed.status, 200)
        self.assertEqual(failed.body["state"], "dead")

        dead = self.app.handle("GET", "/jobs/dead", headers={"X-Actor-Id": "stat"})
        self.assertEqual(dead.status, 200)
        self.assertEqual(len(dead.body["dead_jobs"]), 1)
        self.assertEqual(dead.body["dead_jobs"][0]["failures"][0]["error"], "计算失败")

        forbidden = self.app.handle("GET", "/jobs/dead", headers={"X-Actor-Id": "operator"})
        self.assertEqual(forbidden.status, 403)

        requeued = self.app.handle(
            "POST",
            f"/jobs/{job['job_id']}/requeue",
            headers={"X-Actor-Id": "stat"},
            body=self._body({"reason": "环境已修复"}),
        )
        self.assertEqual(requeued.status, 200)
        self.assertEqual(requeued.body["state"], "queued")

        cancelled = self.app.handle(
            "POST",
            f"/jobs/{job['job_id']}/cancel",
            headers={"X-Actor-Id": "stat"},
            body=self._body({"reason": "重复取消"}),
        )
        self.assertEqual(cancelled.status, 409)

        stale = self.app.handle(
            "POST",
            f"/jobs/{job['job_id']}/heartbeat",
            body=self._body({"worker_id": "w1", "fencing_token": 1, "lease_seconds": 30}),
        )
        self.assertEqual(stale.status, 409)


if __name__ == "__main__":
    unittest.main()
