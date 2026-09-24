"""分析任务心跳续租、最大尝试次数与死信状态机测试。

全部断言通过可注入的 FrozenClock 推进时间，不使用 sleep。
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from robot_trials.clock import FrozenClock
from robot_trials.errors import Forbidden, InvalidState, NotFound, ValidationFailed
from robot_trials.jsonio import load_json
from robot_trials.service import TrialService
from robot_trials.storage import connect


ROOT = Path(__file__).resolve().parents[1]


class JobLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = TrialService(self.connection, self.clock)
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("auditor", "auditor"),
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

    def _claim(self, worker: str = "worker-a", lease: int = 30):
        job = self.service.claim_job(worker, lease)
        self.assertIsNotNone(job)
        return job

    # ---- 心跳续租 ----------------------------------------------------

    def test_heartbeat_extends_lease_while_token_valid(self) -> None:
        job = self._claim(lease=30)
        self.clock.advance(seconds=20)
        renewed = self.service.heartbeat_job("worker-a", job["job_id"], job["lease_token"], 30)
        # 20s 后续约 30s：到期时刻应为初始到期后 20s，而不是被重置成更短的窗口。
        self.clock.advance(seconds=20)
        self.assertGreater(renewed["lease_expires_at"], self.service._now())
        # 租约未过期，其他工作进程不能接管。
        self.assertIsNone(self.service.claim_job("worker-b", 30))

    def test_heartbeat_never_shortens_existing_deadline(self) -> None:
        job = self._claim(lease=60)
        original_deadline = job["lease_expires_at"]
        self.clock.advance(seconds=10)
        # 用更短的窗口续约：MAX() 保证既有期限不被缩短。
        renewed = self.service.heartbeat_job("worker-a", job["job_id"], job["lease_token"], 5)
        self.assertEqual(renewed["lease_expires_at"], original_deadline)

    def test_long_bootstrap_survives_with_repeated_heartbeats(self) -> None:
        job = self._claim(lease=30)
        # 模拟超过原始租约的长 bootstrap，仅靠心跳保持持有权。
        for _ in range(4):
            self.clock.advance(seconds=20)
            job = self.service.heartbeat_job("worker-a", job["job_id"], job["lease_token"], 30)
        self.assertIsNone(self.service.claim_job("worker-b", 30))
        analysis = self.service.complete_job("worker-a", job["job_id"], "stat", job["lease_token"])
        self.assertEqual(analysis["result"]["conclusion"], "pass")

    # ---- 陈旧凭证拒绝 ------------------------------------------------

    def test_stale_worker_cannot_heartbeat_after_takeover(self) -> None:
        first = self._claim(worker="worker-a", lease=10)
        stale_token = first["lease_token"]
        self.clock.advance(seconds=11)
        second = self._claim(worker="worker-b", lease=10)
        self.assertNotEqual(stale_token, second["lease_token"])
        # 旧进程拿着过期凭证续约，必须被拒绝。
        with self.assertRaises(InvalidState):
            self.service.heartbeat_job("worker-a", first["job_id"], stale_token, 60)
        # 旧进程借完成接口复活任务也必须失败。
        with self.assertRaises(InvalidState):
            self.service.complete_job("worker-a", first["job_id"], "stat", stale_token)
        # 旧进程上报失败同样被拒绝，不能把新持有者的任务推回队列。
        with self.assertRaises(InvalidState):
            self.service.fail_job("worker-a", first["job_id"], "过期上报", lease_token=stale_token)

    def test_wrong_token_is_rejected_even_while_lease_valid(self) -> None:
        job = self._claim(lease=60)
        with self.assertRaises(InvalidState):
            self.service.heartbeat_job("worker-a", job["job_id"], "deadbeef" * 4, 60)
        with self.assertRaises(InvalidState):
            self.service.complete_job("worker-a", job["job_id"], "stat", "deadbeef" * 4)

    # ---- 最大尝试次数与死信 ------------------------------------------

    def test_job_dead_letters_after_protocol_attempt_limit(self) -> None:
        first = self._claim(lease=30)
        self.assertEqual(first["max_attempts"], 3)  # 协议默认上限
        self.service.fail_job("worker-a", first["job_id"], "失败 1", lease_token=first["lease_token"])
        second = self._claim(worker="worker-b", lease=30)
        self.service.fail_job("worker-b", second["job_id"], "失败 2", lease_token=second["lease_token"])
        third = self._claim(worker="worker-c", lease=30)
        result = self.service.fail_job("worker-c", third["job_id"], "失败 3", lease_token=third["lease_token"])
        self.assertEqual(result["state"], "dead_letter")
        # 死信任务不会再被领取，值班视角能直接看到。
        self.assertIsNone(self.service.claim_job("worker-d", 30))
        dead = self.service.list_dead_letter_jobs("stat")
        self.assertEqual([item["job_id"] for item in dead], [first["job_id"]])
        detail = dead[0]
        self.assertEqual(detail["attempts"], 3)
        failures = [item for item in detail["attempt_history"] if item["outcome"] == "failed"]
        self.assertEqual([item["error"] for item in failures], ["失败 1", "失败 2", "失败 3"])
        self.assertIn("达到上限 3", detail["dead_letter_reason"])

    def test_expired_lease_without_fail_report_counts_as_attempt(self) -> None:
        first = self._claim(worker="worker-a", lease=10)
        self.clock.advance(seconds=11)
        second = self._claim(worker="worker-b", lease=10)
        self.assertEqual(second["attempts"], 2)
        detail = self.service.get_job("stat", first["job_id"])
        self.assertEqual(detail["attempt_history"][0]["outcome"], "lease_expired")
        self.clock.advance(seconds=11)
        third = self.service.claim_job("worker-c", 10)
        self.assertEqual(third["attempts"], 3)
        self.clock.advance(seconds=11)
        # 第三次尝试也以过期告终：直接死信，不再发给任何工作进程。
        self.assertIsNone(self.service.claim_job("worker-d", 10))
        detail = self.service.get_job("stat", first["job_id"])
        self.assertEqual(detail["state"], "dead_letter")
        self.assertEqual(detail["attempts"], 3)
        self.assertEqual(detail["attempt_history"][-1]["outcome"], "lease_expired")

    def test_last_attempt_expiring_dead_letters_at_takeover(self) -> None:
        # 前两次显式失败，最后一次工作进程直接死亡（租约过期）。
        for _ in range(2):
            job = self._claim(lease=10)
            self.service.fail_job("worker-a", job["job_id"], "失败", lease_token=job["lease_token"])
        last = self._claim(lease=10)
        self.clock.advance(seconds=11)
        # 接管者不会得到第 4 次执行：任务在领取扫描中直接进入死信。
        self.assertIsNone(self.service.claim_job("worker-b", 10))
        detail = self.service.get_job("stat", last["job_id"])
        self.assertEqual(detail["state"], "dead_letter")
        self.assertEqual(detail["attempts"], 3)
        self.assertEqual(detail["attempt_history"][-1]["outcome"], "lease_expired")

    def test_dead_letter_emits_audit_event(self) -> None:
        job = self._claim(lease=30)
        self.service.fail_job("worker-a", job["job_id"], "x", lease_token=job["lease_token"])
        j2 = self._claim(lease=30)
        self.service.fail_job("worker-a", j2["job_id"], "x", lease_token=j2["lease_token"])
        j3 = self._claim(lease=30)
        self.service.fail_job("worker-a", j3["job_id"], "x", lease_token=j3["lease_token"])
        events = [
            row[0]
            for row in self.connection.execute(
                "SELECT event_type FROM audit_events WHERE entity_type='job' ORDER BY event_id"
            )
        ]
        self.assertIn("job.dead_lettered", events)

    # ---- 人工恢复 ----------------------------------------------------

    def test_statistician_requeues_dead_job_with_reason(self) -> None:
        job = self._drain_to_dead_letter()
        result = self.service.requeue_dead_job("stat", job, "修复数据后重试", max_attempts=2)
        self.assertEqual(result["state"], "queued")
        claimed = self._claim(worker="worker-new", lease=30)
        self.assertEqual(claimed["attempts"], 1)  # 尝试预算已重置
        self.assertEqual(claimed["max_attempts"], 2)
        detail = self.service.get_job("stat", job)
        self.assertEqual(detail["requeued_count"], 1)
        self.assertTrue(any(
            item["outcome"] == "manually_requeued" and item["reason"] == "修复数据后重试"
            for item in detail["attempt_history"]
        ))

    def test_requeue_requires_reason_and_privilege(self) -> None:
        job = self._drain_to_dead_letter()
        with self.assertRaises(ValidationFailed):
            self.service.requeue_dead_job("stat", job, "  ")
        with self.assertRaises(Forbidden):
            self.service.requeue_dead_job("operator", job, "无权重试")
        with self.assertRaises(Forbidden):
            self.service.list_dead_letter_jobs("operator")
        # 审计角色只读。
        self.service.list_dead_letter_jobs("auditor")
        with self.assertRaises(Forbidden):
            self.service.requeue_dead_job("auditor", job, "无权重试")

    def test_cancelled_job_cannot_be_revived(self) -> None:
        job = self._drain_to_dead_letter()
        cancelled = self.service.cancel_dead_job("stat", job, "协议配置错误，废弃本批次")
        self.assertEqual(cancelled["state"], "cancelled")
        with self.assertRaises(InvalidState):
            self.service.requeue_dead_job("stat", job, "试图复活")
        # 任何工作进程都不能领取已取消任务。
        self.assertIsNone(self.service.claim_job("worker-z", 30))
        detail = self.service.get_job("stat", job)
        self.assertEqual(detail["state"], "cancelled")
        self.assertEqual(detail["cancel_actor"], "stat")

    def test_cancel_requires_dead_letter_state(self) -> None:
        job = self._claim(lease=30)
        with self.assertRaises(InvalidState):
            self.service.cancel_dead_job("stat", job["job_id"], "运行中不能取消")

    def test_requeued_then_failed_again_dead_letters_again(self) -> None:
        job = self._drain_to_dead_letter()
        self.service.requeue_dead_job("stat", job, "再试一轮", max_attempts=2)
        j1 = self._claim(lease=30)
        self.service.fail_job("worker-a", j1["job_id"], "再次失败 1", lease_token=j1["lease_token"])
        j2 = self._claim(lease=30)
        again = self.service.fail_job("worker-a", j2["job_id"], "再次失败 2", lease_token=j2["lease_token"])
        self.assertEqual(again["state"], "dead_letter")

    # ---- 领取顺序与批次可分析状态 ------------------------------------

    def test_claim_ordering_prefers_earliest_available(self) -> None:
        # 同一连接无法建第二个批次（fixture 只发布一个协议版本），
        # 直接插入第二条排队任务验证 available_at, job_id 排序。
        now = self.service._now()
        self.connection.execute(
            "INSERT INTO analysis_jobs(batch_id,batch_revision,state,available_at,max_attempts,"
            "created_at,updated_at) VALUES('batch-a',99,'queued',?,?,?,?)",
            (now, 3, now, now),
        )
        first = self.service.claim_job("w", 30)
        self.assertEqual(first["batch_revision"], 3)  # seal 时 revision=3 的既有任务先被领取

    def test_report_reflects_dead_letter_and_recovered_states(self) -> None:
        job = self._drain_to_dead_letter()
        report = self.service.report("auditor", "batch-a")
        self.assertEqual(report["job"]["state"], "dead_letter")
        self.assertEqual(len(report["job"]["attempt_history"]), 3)
        self.service.requeue_dead_job("stat", job, "人工恢复")
        claimed = self._claim(worker="worker-new", lease=30)
        self.service.complete_job("worker-new", claimed["job_id"], "stat", claimed["lease_token"])
        report = self.service.report("auditor", "batch-a")
        self.assertEqual(report["batch"]["state"], "analyzed")
        self.assertEqual(report["job"]["state"], "succeeded")

    # ---- 重启恢复 ----------------------------------------------------

    def test_restart_recovers_jobs_without_sleep_or_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "jobs.sqlite3"
            clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
            connection = connect(database)
            service = TrialService(connection, clock)
            for user_id, role in (
                ("operator", "operator"), ("stat", "statistician"),
                ("approver", "approver"), ("auditor", "auditor"),
            ):
                service.create_user(user_id, user_id, role)
            protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
            service.register_robot("operator", "robot-a", "A 型", "厂商")
            service.register_build("operator", "build-a", "robot-a", "1.0", "b" * 64)
            service.publish_protocol("stat", protocol)
            service.create_batch("operator", "batch-a", "demo-delivery-v1", 1, "build-a")
            service.start_batch("operator", "batch-a", 1)
            service.import_observations("operator", "batch-a", "key-1", self.rows)
            service.seal_batch("stat", "batch-a", 2)
            job = service.claim_job("worker-a", 30)
            # 重启：进程消失，时钟跨过租约期限；死信/排队状态也都应原样保留。
            connection.close()
            clock.advance(seconds=31)
            connection = connect(database)
            restarted = TrialService(connection, clock)
            taken = restarted.claim_job("worker-b", 30)
            self.assertIsNotNone(taken)
            self.assertEqual(taken["job_id"], job["job_id"])
            self.assertEqual(taken["attempts"], 2)
            self.assertEqual(
                restarted.get_job("stat", job["job_id"])["attempt_history"][0]["outcome"],
                "lease_expired",
            )
            connection.close()

    # ---- 辅助 --------------------------------------------------------

    def _drain_to_dead_letter(self) -> int:
        for index in range(3):
            job = self.service.claim_job(f"worker-{index}", 30)
            result = self.service.fail_job(
                f"worker-{index}", job["job_id"], f"失败 {index + 1}", lease_token=job["lease_token"]
            )
        self.assertEqual(result["state"], "dead_letter")
        return job["job_id"]


if __name__ == "__main__":
    unittest.main()
