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


def _post(app: JsonApplication, path: str, payload: dict, actor: str | None = None):
    headers = {"Content-Type": "application/json"}
    if actor:
        headers["X-Actor-Id"] = actor
    return app.handle("POST", path, headers, json.dumps(payload).encode())


class JobApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = TrialService(self.connection, self.clock)
        self.app = JsonApplication(self.service)
        for user_id, role in (
            ("operator", "operator"), ("stat", "statistician"),
            ("approver", "approver"), ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.service.register_robot("operator", "robot-a", "A 型", "厂商")
        self.service.register_build("operator", "build-a", "robot-a", "1.0", "b" * 64)
        self.service.publish_protocol("stat", protocol)
        self.service.create_batch("operator", "batch-a", "demo-delivery-v1", 1, "build-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.import_observations("operator", "batch-a", "key-1", self.rows)
        self.service.seal_batch("stat", "batch-a", 2)

    def tearDown(self) -> None:
        self.connection.close()

    def test_heartbeat_and_complete_routes_require_fencing_token(self) -> None:
        claim = _post(self.app, "/jobs/claim", {"worker_id": "w1", "lease_seconds": 30})
        self.assertEqual(claim.status, 200)
        job = claim.body["job"]
        beat = _post(self.app, f"/jobs/{job['job_id']}/heartbeat",
                     {"worker_id": "w1", "lease_token": job["lease_token"], "lease_seconds": 60})
        self.assertEqual(beat.status, 200)
        # 错误凭证：409。
        stale = _post(self.app, f"/jobs/{job['job_id']}/heartbeat",
                      {"worker_id": "w1", "lease_token": "0" * 32, "lease_seconds": 60})
        self.assertEqual(stale.status, 409)
        self.assertEqual(stale.body["error"]["code"], "invalid_state")
        complete = _post(
            self.app, f"/jobs/{job['job_id']}/complete",
            {"worker_id": "w1", "lease_token": job["lease_token"]}, actor="stat",
        )
        self.assertEqual(complete.status, 200)

    def test_dead_letter_requeue_and_cancel_routes(self) -> None:
        # 把任务打到死信。
        for index in range(3):
            claim = _post(self.app, "/jobs/claim", {"worker_id": f"w{index}", "lease_seconds": 30})
            job = claim.body["job"]
            if index < 2:
                fail = _post(self.app, f"/jobs/{job['job_id']}/fail",
                             {"worker_id": f"w{index}", "lease_token": job["lease_token"], "error": f"e{index}"})
                self.assertEqual(fail.status, 200)
            else:
                fail = _post(self.app, f"/jobs/{job['job_id']}/fail",
                             {"worker_id": f"w{index}", "lease_token": job["lease_token"], "error": "e2"})
                self.assertEqual(fail.body["state"], "dead_letter")
                job_id = job["job_id"]
        # 操作员无权查看死信队列。
        denied = self.app.handle("GET", "/dead-letter", {"X-Actor-Id": "operator"})
        self.assertEqual(denied.status, 403)
        listed = self.app.handle("GET", "/dead-letter", {"X-Actor-Id": "stat"})
        self.assertEqual(listed.status, 200)
        self.assertEqual(len(listed.body["jobs"]), 1)
        # 缺理由的重新入队：422。
        no_reason = _post(self.app, f"/jobs/{job_id}/requeue", {"reason": "  "}, actor="stat")
        self.assertEqual(no_reason.status, 422)
        requeue = _post(self.app, f"/jobs/{job_id}/requeue",
                        {"reason": "修复配置", "max_attempts": 1}, actor="stat")
        self.assertEqual(requeue.status, 200)
        self.assertEqual(requeue.body["state"], "queued")
        # 再次打死后永久取消。
        claim = _post(self.app, "/jobs/claim", {"worker_id": "w9", "lease_seconds": 30})
        fail = _post(self.app, f"/jobs/{job_id}/fail",
                     {"worker_id": "w9", "lease_token": claim.body["job"]["lease_token"], "error": "再失败"})
        self.assertEqual(fail.body["state"], "dead_letter")
        cancel = _post(self.app, f"/jobs/{job_id}/cancel", {"reason": "废弃"}, actor="stat")
        self.assertEqual(cancel.status, 200)
        self.assertEqual(cancel.body["state"], "cancelled")
        revive = _post(self.app, f"/jobs/{job_id}/requeue", {"reason": "试图复活"}, actor="stat")
        self.assertEqual(revive.status, 409)


if __name__ == "__main__":
    unittest.main()
