from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from robot_trials.clock import FrozenClock
from robot_trials.errors import Forbidden, InvalidState, ValidationFailed
from robot_trials.jsonio import load_json
from robot_trials.service import TrialService
from robot_trials.storage import connect


ROOT = Path(__file__).resolve().parents[1]
BASE_TIME = datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc)


class AnalysisJobTests(unittest.TestCase):
    """全部通过 FrozenClock 推进时间，不依赖 sleep。"""

    max_attempts = 2

    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(BASE_TIME)
        self.service = TrialService(
            self.connection, self.clock, max_analysis_attempts=self.max_attempts
        )
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.service.register_robot("operator", "robot-a", "A 型", "厂商")
        self.service.register_build("operator", "build-a", "robot-a", "1.0", "b" * 64)
        self.service.publish_protocol("stat", self.protocol)
        self._seal_batch("batch-a", self.protocol["protocol_id"], import_rows=True)

    def tearDown(self) -> None:
        self.connection.close()

    def _seal_batch(self, batch_id: str, protocol_id: str, import_rows: bool = False) -> None:
        self.service.create_batch("operator", batch_id, protocol_id, 1, "build-a")
        self.service.start_batch("operator", batch_id, 1)
        if import_rows:
            self.service.import_observations("operator", batch_id, f"key-{batch_id}", self.rows)
        self.service.seal_batch("stat", batch_id, 2)

    def _job_row(self, job_id: int) -> dict:
        return dict(
            self.connection.execute(
                "SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
        )

    def _audit_events(self, event_type: str) -> list[dict]:
        rows = self.connection.execute(
            "SELECT actor_id,payload_json FROM audit_events WHERE event_type=? ORDER BY event_id",
            (event_type,),
        ).fetchall()
        return [{"actor_id": row[0], "payload": json.loads(row[1])} for row in rows]

    # 续租：心跳延长租约，且续约不得缩短已有期限。
    def test_heartbeat_extends_lease_and_never_shortens(self) -> None:
        job = self.service.claim_job("worker-a", 10)
        self.assertEqual(job["fencing_token"], 1)
        original_expiry = job["lease_expires_at"]
        self.clock.advance(seconds=4)
        renewed = self.service.heartbeat_job("worker-a", job["job_id"], job["fencing_token"], 30)
        self.assertGreater(renewed["lease_expires_at"], original_expiry)
        self.assertEqual(renewed["renewals"], 1)
        extended_expiry = renewed["lease_expires_at"]
        shortened = self.service.heartbeat_job("worker-a", job["job_id"], job["fencing_token"], 1)
        self.assertEqual(shortened["lease_expires_at"], extended_expiry)
        self.assertEqual(shortened["renewals"], 2)
        # 原始租约（10 秒）早已过去，但续约后的租约仍然有效，可以完成。
        self.clock.advance(seconds=20)
        result = self.service.complete_job("worker-a", job["job_id"], job["fencing_token"], "stat")
        self.assertEqual(result["result"]["conclusion"], "pass")
        self.assertEqual(self._job_row(job["job_id"])["state"], "succeeded")

    # 陈旧凭证：租约过期、被接管后，旧持有者的心跳/完成/失败都被拒绝。
    def test_stale_token_rejected_after_takeover(self) -> None:
        job = self.service.claim_job("worker-a", 10)
        self.clock.advance(seconds=11)
        with self.assertRaises(InvalidState):
            self.service.heartbeat_job("worker-a", job["job_id"], job["fencing_token"], 30)
        taken_over = self.service.claim_job("worker-b", 10)
        self.assertEqual(taken_over["fencing_token"], 2)
        with self.assertRaises(InvalidState):
            self.service.heartbeat_job("worker-a", job["job_id"], 1, 30)
        with self.assertRaises(InvalidState):
            self.service.heartbeat_job("worker-b", job["job_id"], 1, 30)
        with self.assertRaises(InvalidState):
            self.service.complete_job("worker-a", job["job_id"], 1, "stat")
        with self.assertRaises(InvalidState):
            self.service.fail_job("worker-a", job["job_id"], 1, "旧进程迟到失败")
        alive = self.service.heartbeat_job("worker-b", job["job_id"], 2, 30)
        self.assertEqual(alive["lease_owner"], "worker-b")

    # 超限：显式失败达到系统配置上限后进入死信，并保存每次失败摘要。
    def test_failures_reaching_limit_move_to_dead_letter_with_summaries(self) -> None:
        first = self.service.claim_job("worker-a", 10)
        retried = self.service.fail_job("worker-a", first["job_id"], 1, "第一次计算失败")
        self.assertEqual(retried["state"], "queued")
        second = self.service.claim_job("worker-b", 10)
        self.assertEqual(second["attempts"], 2)
        exhausted = self.service.fail_job("worker-b", second["job_id"], 2, "第二次计算失败")
        self.assertEqual(exhausted["state"], "dead")
        self.assertIsNone(self.service.claim_job("worker-c", 10))

        dead = self.service.list_dead_jobs("stat")["dead_jobs"]
        self.assertEqual([item["job_id"] for item in dead], [first["job_id"]])
        failures = dead[0]["failures"]
        self.assertEqual([item["attempt"] for item in failures], [1, 2])
        self.assertEqual({item["kind"] for item in failures}, {"worker_failed"})
        self.assertEqual(failures[0]["error"], "第一次计算失败")
        self.assertEqual(failures[1]["error"], "第二次计算失败")
        self.assertEqual(dead[0]["max_attempts"], self.max_attempts)
        # 死信后批次回到封存待调度状态，旧持有者无法复活任务。
        self.assertEqual(self.service.get_batch("batch-a")["state"], "sealed")
        with self.assertRaises(InvalidState):
            self.service.heartbeat_job("worker-b", first["job_id"], 2, 30)
        with self.assertRaises(InvalidState):
            self.service.complete_job("worker-b", first["job_id"], 2, "stat")
        event_types = [
            row[0]
            for row in self.connection.execute(
                "SELECT event_type FROM audit_events WHERE event_type LIKE 'analysis_job.%' ORDER BY event_id"
            ).fetchall()
        ]
        self.assertEqual(
            event_types,
            ["analysis_job.failed", "analysis_job.failed", "analysis_job.dead"],
        )

    # 超限：租约过期同样计入失败，达到上限后死信而不是继续派发。
    def test_lease_expiry_counts_toward_dead_letter_limit(self) -> None:
        first = self.service.claim_job("worker-a", 10)
        self.clock.advance(seconds=11)
        second = self.service.claim_job("worker-b", 10)
        self.assertEqual(second["attempts"], 2)
        self.assertEqual(second["fencing_token"], 2)
        self.clock.advance(seconds=11)
        self.assertIsNone(self.service.claim_job("worker-c", 10))
        dead = self.service.list_dead_jobs("stat")["dead_jobs"]
        self.assertEqual([item["job_id"] for item in dead], [first["job_id"]])
        self.assertEqual(
            [item["kind"] for item in dead[0]["failures"]],
            ["lease_expired", "lease_expired"],
        )
        self.assertEqual(dead[0]["last_error"], "租约到期且达到最大尝试次数")

    # 上限来源：协议声明优先，缺省回落到系统配置。
    def test_protocol_limit_overrides_system_default(self) -> None:
        strict = deepcopy(self.protocol)
        strict["protocol_id"] = "demo-delivery-strict"
        strict["max_analysis_attempts"] = 1
        self.service.publish_protocol("stat", strict)
        self._seal_batch("batch-strict", "demo-delivery-strict")
        default_job = self.service.claim_job("worker-a", 10)
        self.assertEqual(default_job["max_attempts"], self.max_attempts)
        job = self.service.claim_job("worker-b", 10)
        self.assertEqual(job["batch_id"], "batch-strict")
        self.assertEqual(job["max_attempts"], 1)
        outcome = self.service.fail_job("worker-b", job["job_id"], job["fencing_token"], "唯一一次机会失败")
        self.assertEqual(outcome["state"], "dead")

    # 人工恢复：统计负责人查看死信、带理由重新入队后任务可以完成。
    def test_dead_letter_requeue_with_reason_restores_job(self) -> None:
        job = self.service.claim_job("worker-a", 10)
        self.service.fail_job("worker-a", job["job_id"], 1, "环境故障")
        second = self.service.claim_job("worker-a", 10)
        self.service.fail_job("worker-a", second["job_id"], 2, "环境仍故障")
        self.assertEqual(self._job_row(job["job_id"])["state"], "dead")

        with self.assertRaises(Forbidden):
            self.service.list_dead_jobs("operator")
        with self.assertRaises(Forbidden):
            self.service.requeue_job("operator", job["job_id"], "越权操作")
        with self.assertRaises(ValidationFailed):
            self.service.requeue_job("stat", job["job_id"], "  ")

        requeued = self.service.requeue_job("stat", job["job_id"], "计算环境已修复")
        self.assertEqual(requeued["state"], "queued")
        self.assertEqual(requeued["attempts"], 0)
        # fencing 凭证保持单调，不随重新入队重置。
        self.assertEqual(requeued["fencing_token"], 2)

        third = self.service.claim_job("worker-c", 30)
        self.assertEqual(third["fencing_token"], 3)
        self.assertEqual(third["attempts"], 1)
        self.assertEqual(self.service.get_batch("batch-a")["state"], "analyzing")
        with self.assertRaises(InvalidState):
            self.service.heartbeat_job("worker-a", job["job_id"], 2, 30)
        result = self.service.complete_job("worker-c", job["job_id"], 3, "stat")
        self.assertEqual(result["result"]["conclusion"], "pass")
        self.assertEqual(self.service.get_batch("batch-a")["state"], "analyzed")
        requeue_events = self._audit_events("analysis_job.requeued")
        self.assertEqual(len(requeue_events), 1)
        self.assertEqual(requeue_events[0]["actor_id"], "stat")
        self.assertEqual(requeue_events[0]["payload"]["reason"], "计算环境已修复")

    # 人工取消：永久取消是终态，任何接口都不能复活任务。
    def test_cancel_is_terminal_and_visible_in_report(self) -> None:
        job = self.service.claim_job("worker-a", 10)
        self.service.fail_job("worker-a", job["job_id"], 1, "第一次失败")
        second = self.service.claim_job("worker-a", 10)
        self.service.fail_job("worker-a", second["job_id"], 2, "第二次失败")

        with self.assertRaises(ValidationFailed):
            self.service.cancel_job("stat", job["job_id"], "")
        cancelled = self.service.cancel_job("stat", job["job_id"], "确认输入数据不可用")
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertIsNone(self.service.claim_job("worker-b", 10))
        with self.assertRaises(InvalidState):
            self.service.heartbeat_job("worker-a", job["job_id"], 2, 30)
        with self.assertRaises(InvalidState):
            self.service.complete_job("worker-a", job["job_id"], 2, "stat")
        with self.assertRaises(InvalidState):
            self.service.fail_job("worker-a", job["job_id"], 2, "迟到失败")
        with self.assertRaises(InvalidState):
            self.service.requeue_job("stat", job["job_id"], "尝试恢复已取消任务")
        with self.assertRaises(InvalidState):
            self.service.cancel_job("stat", job["job_id"], "重复取消")
        self.assertEqual(self.service.list_dead_jobs("stat")["dead_jobs"], [])
        report = self.service.report("auditor", "batch-a")
        self.assertEqual(report["analysis_job"]["state"], "cancelled")
        self.assertEqual(len(report["analysis_job"]["failures"]), 2)
        cancel_events = self._audit_events("analysis_job.cancelled")
        self.assertEqual(cancel_events[0]["payload"]["reason"], "确认输入数据不可用")

    # 重启恢复：状态、 fencing 凭证与死信在进程重启后保持一致。
    def test_restart_recovers_job_states(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "jobs.sqlite3"
            first_connection = connect(database)
            first_service = TrialService(first_connection, self.clock, max_analysis_attempts=2)
            first_service.create_user("operator", "操作员", "operator")
            first_service.create_user("stat", "统计负责人", "statistician")
            first_service.register_robot("operator", "robot-a", "A 型", "厂商")
            first_service.register_build("operator", "build-a", "robot-a", "1.0", "b" * 64)
            first_service.publish_protocol("stat", self.protocol)
            first_service.create_batch("operator", "batch-a", self.protocol["protocol_id"], 1, "build-a")
            first_service.start_batch("operator", "batch-a", 1)
            first_service.seal_batch("stat", "batch-a", 2)
            claimed = first_service.claim_job("worker-a", 10)
            first_connection.close()

            self.clock.advance(seconds=11)
            second_connection = connect(database)
            second_service = TrialService(second_connection, self.clock, max_analysis_attempts=2)
            reclaimed = second_service.claim_job("worker-b", 10)
            self.assertEqual(reclaimed["job_id"], claimed["job_id"])
            self.assertEqual(reclaimed["fencing_token"], 2)
            self.assertEqual(reclaimed["attempts"], 2)
            outcome = second_service.fail_job("worker-b", reclaimed["job_id"], 2, "重启后仍失败")
            self.assertEqual(outcome["state"], "dead")
            second_connection.close()

            third_connection = connect(database)
            third_service = TrialService(third_connection, self.clock, max_analysis_attempts=2)
            dead = third_service.list_dead_jobs("stat")["dead_jobs"]
            self.assertEqual([item["job_id"] for item in dead], [claimed["job_id"]])
            self.assertEqual(
                [item["kind"] for item in dead[0]["failures"]],
                ["lease_expired", "worker_failed"],
            )
            self.assertIsNone(third_service.claim_job("worker-c", 10))
            third_connection.close()

    # 领取顺序：按可领取时间先进先出，失败延迟重试不插队。
    def test_claim_order_respects_available_time(self) -> None:
        self._seal_batch("batch-b", self.protocol["protocol_id"])
        first = self.service.claim_job("worker-a", 10)
        self.assertEqual(first["batch_id"], "batch-a")
        self.service.fail_job("worker-a", first["job_id"], 1, "延迟重试", retry_seconds=100)
        second = self.service.claim_job("worker-b", 1000)
        self.assertEqual(second["batch_id"], "batch-b")
        self.assertIsNone(self.service.claim_job("worker-c", 10))
        self.clock.advance(seconds=100)
        retried = self.service.claim_job("worker-c", 10)
        self.assertEqual(retried["job_id"], first["job_id"])

    # 批次可分析状态与任务状态机保持一致。
    def test_batch_state_tracks_job_lifecycle(self) -> None:
        self.assertEqual(self.service.get_batch("batch-a")["state"], "sealed")
        job = self.service.claim_job("worker-a", 10)
        self.assertEqual(self.service.get_batch("batch-a")["state"], "analyzing")
        self.service.fail_job("worker-a", job["job_id"], 1, "第一次失败")
        self.assertEqual(self.service.get_batch("batch-a")["state"], "sealed")
        second = self.service.claim_job("worker-b", 10)
        self.assertEqual(self.service.get_batch("batch-a")["state"], "analyzing")
        self.service.fail_job("worker-b", second["job_id"], 2, "第二次失败")
        self.assertEqual(self.service.get_batch("batch-a")["state"], "sealed")
        report = self.service.report("auditor", "batch-a")
        self.assertEqual(report["analysis_job"]["state"], "dead")
        self.assertIsNone(report["analysis"])


if __name__ == "__main__":
    unittest.main()
