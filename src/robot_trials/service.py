"""统计准入服务的领域用例。"""

from __future__ import annotations

import json
import secrets
import sqlite3
from datetime import timedelta
from decimal import Decimal
from typing import Any, Iterable, Mapping

from .analysis import ALGORITHM_VERSION, analyze
from .clock import SystemClock, isoformat
from .contracts import Observation, Protocol, ValidationError
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


ROLE_PERMISSIONS = {
    "operator": {
        "catalog.write", "batch.create", "batch.start", "observation.import",
        "exclusion.request", "exclusion.revoke",
    },
    "statistician": {
        "protocol.publish", "batch.seal", "exclusion.review", "analysis.run",
        "analysis.deadletter.read", "analysis.deadletter.requeue", "analysis.deadletter.cancel",
    },
    "approver": {"decision.write"},
    "auditor": {"report.read", "audit.read", "analysis.deadletter.read"},
}

DEFAULT_MAX_ATTEMPTS = 3


class TrialService:
    """在单个 SQLite 连接上提供全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, role, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(payload), self._now()),
        )

    def create_user(self, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,role) VALUES(?,?,?)",
                    (user_id.strip(), display_name.strip(), role),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "role": role}

    def register_robot(
        self, actor_id: str, robot_id: str, model_name: str, vendor: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO robots(robot_id,model_name,vendor,created_at) VALUES(?,?,?,?)",
                    (robot_id, model_name, vendor, self._now()),
                )
                self._audit("robot", robot_id, "robot.registered", actor_id, {"model_name": model_name})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"机器人已存在: {robot_id}") from exc
        return {"robot_id": robot_id, "model_name": model_name, "vendor": vendor}

    def register_build(
        self, actor_id: str, build_id: str, robot_id: str, version: str, content_sha256: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        if len(content_sha256) != 64:
            raise ValidationFailed("构建摘要必须是 64 位 SHA-256")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO builds(build_id,robot_id,version,content_sha256,created_at) VALUES(?,?,?,?,?)",
                    (build_id, robot_id, version, content_sha256.lower(), self._now()),
                )
                self._audit("build", build_id, "build.registered", actor_id, {"robot_id": robot_id, "version": version})
        except sqlite3.IntegrityError as exc:
            raise Conflict("构建编号、版本或摘要冲突") from exc
        return {"build_id": build_id, "robot_id": robot_id, "version": version}

    def publish_protocol(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "protocol.publish")
        try:
            protocol = Protocol.from_dict(raw)
        except ValidationError as exc:
            raise ValidationFailed(str(exc)) from exc
        text = canonical_json(raw)
        digest = content_digest([raw])
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO protocol_catalog(protocol_id,version,title,task_family,canonical_json,content_sha256,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        protocol.protocol_id,
                        protocol.version,
                        protocol.title,
                        protocol.task_family,
                        text,
                        digest,
                        self._now(),
                    ),
                )
                identity = f"{protocol.protocol_id}@{protocol.version}"
                self._audit("protocol", identity, "protocol.published", actor_id, {"sha256": digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("协议版本或内容摘要已经存在") from exc
        return {"protocol_id": protocol.protocol_id, "version": protocol.version, "sha256": digest}

    def _protocol(self, protocol_id: str, version: int) -> tuple[Protocol, str]:
        row = self.connection.execute(
            "SELECT canonical_json,content_sha256 FROM protocol_catalog WHERE protocol_id=? AND version=?",
            (protocol_id, version),
        ).fetchone()
        if row is None:
            raise NotFound("协议版本不存在")
        return Protocol.from_dict(json.loads(row["canonical_json"])), row["content_sha256"]

    def create_batch(
        self,
        actor_id: str,
        batch_id: str,
        protocol_id: str,
        protocol_version: int,
        build_id: str,
    ) -> dict[str, Any]:
        self._require(actor_id, "batch.create")
        self._protocol(protocol_id, protocol_version)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO batches(batch_id,protocol_id,protocol_version,build_id,state,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (batch_id, protocol_id, protocol_version, build_id, "draft", actor_id, self._now()),
                )
                self._audit("batch", batch_id, "batch.created", actor_id, {"build_id": build_id})
        except sqlite3.IntegrityError as exc:
            raise Conflict("批次编号冲突或构建不存在") from exc
        return self.get_batch(batch_id)

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            raise NotFound("批次不存在")
        return dict(row)

    def start_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.start")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE batches SET state='running',revision=revision+1,started_at=? "
                "WHERE batch_id=? AND state='draft' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次不是当前草稿版本")
            self._audit("batch", batch_id, "batch.started", actor_id, {"from_revision": expected_revision})
        return self.get_batch(batch_id)

    def _idempotent_response(self, scope: str, key: str, request_digest: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT request_sha256,response_json FROM idempotency_keys WHERE scope=? AND key=?",
            (scope, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_digest:
            raise Conflict("同一幂等键对应了不同请求内容")
        return json.loads(row["response_json"])

    def import_observations(
        self,
        actor_id: str,
        batch_id: str,
        idempotency_key: str,
        raw_rows: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        self._require(actor_id, "observation.import")
        rows = tuple(raw_rows)
        if not rows:
            raise ValidationFailed("观测数组不能为空")
        request_digest = content_digest(rows)
        scope = f"observations:{batch_id}"
        existing = self._idempotent_response(scope, idempotency_key, request_digest)
        if existing is not None:
            return existing
        batch = self.get_batch(batch_id)
        if batch["state"] != "running":
            raise InvalidState("只有运行中的批次可以导入观测")
        protocol, _ = self._protocol(batch["protocol_id"], batch["protocol_version"])
        parsed: list[Observation] = []
        for raw in rows:
            try:
                item = Observation.from_dict(raw, protocol)
            except ValidationError as exc:
                raise ValidationFailed(str(exc)) from exc
            if item.robot_id != self.connection.execute(
                "SELECT robot_id FROM builds WHERE build_id=?", (batch["build_id"],)
            ).fetchone()["robot_id"]:
                raise ValidationFailed("观测机器人与批次构建不一致")
            parsed.append(item)
        response = {"batch_id": batch_id, "inserted": len(parsed), "request_sha256": request_digest}
        try:
            with transaction(self.connection, immediate=True):
                for item, raw in zip(parsed, rows):
                    self.connection.execute(
                        "INSERT INTO observations(batch_id,source_batch,source_row,robot_id,stratum_key,observed_at," 
                        "metrics_json,content_sha256,imported_by,imported_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (
                            batch_id,
                            item.source_batch,
                            item.source_row,
                            item.robot_id,
                            item.stratum_key,
                            item.observed_at,
                            canonical_json({key: format(value, "f") for key, value in item.metrics.items()}),
                            content_digest([raw]),
                            actor_id,
                            self._now(),
                        ),
                    )
                self.connection.execute(
                    "INSERT INTO idempotency_keys(scope,key,request_sha256,response_json,created_at) VALUES(?,?,?,?,?)",
                    (scope, idempotency_key, request_digest, canonical_json(response), self._now()),
                )
                self._audit("batch", batch_id, "observations.imported", actor_id, response)
        except sqlite3.IntegrityError as exc:
            raise Conflict("来源行重复或幂等键并发冲突") from exc
        return response

    def request_exclusion(self, actor_id: str, observation_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.request")
        observation = self.connection.execute(
            "SELECT observation_id,batch_id FROM observations WHERE observation_id=?", (observation_id,)
        ).fetchone()
        if observation is None:
            raise NotFound("观测不存在")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO exclusion_requests(observation_id,status,reason,requested_by,requested_at) "
                    "VALUES(?,?,?,?,?)",
                    (observation_id, "pending", reason, actor_id, self._now()),
                )
                exclusion_id = cursor.lastrowid
                self._audit("observation", str(observation_id), "exclusion.requested", actor_id, {"reason": reason})
        except sqlite3.IntegrityError as exc:
            raise Conflict("该观测已有待处理或生效排除") from exc
        return {"exclusion_id": exclusion_id, "status": "pending"}

    def review_exclusion(
        self, actor_id: str, exclusion_id: int, approve: bool, note: str
    ) -> dict[str, Any]:
        self._require(actor_id, "exclusion.review")
        row = self.connection.execute(
            "SELECT * FROM exclusion_requests WHERE exclusion_id=?", (exclusion_id,)
        ).fetchone()
        if row is None:
            raise NotFound("排除申请不存在")
        if row["status"] != "pending":
            raise InvalidState("排除申请已经处理")
        if row["requested_by"] == actor_id:
            raise Forbidden("申请人不能复核自己的排除申请")
        status = "approved" if approve else "rejected"
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE exclusion_requests SET status=?,reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE exclusion_id=? AND status='pending'",
                (status, actor_id, self._now(), note, exclusion_id),
            )
            self._audit("exclusion", str(exclusion_id), f"exclusion.{status}", actor_id, {"note": note})
        return {"exclusion_id": exclusion_id, "status": status}

    def revoke_exclusion(self, actor_id: str, exclusion_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.revoke")
        row = self.connection.execute(
            "SELECT e.*,o.batch_id FROM exclusion_requests e "
            "JOIN observations o ON o.observation_id=e.observation_id WHERE e.exclusion_id=?",
            (exclusion_id,),
        ).fetchone()
        if row is None:
            raise NotFound("排除记录不存在")
        if row["status"] != "approved":
            raise InvalidState("只有已批准的排除可以撤销")
        if row["requested_by"] != actor_id:
            raise Forbidden("只有原申请人可以撤销排除")
        batch = self.get_batch(row["batch_id"])
        if batch["state"] != "running":
            raise InvalidState("批次封存后不能改变排除状态")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE exclusion_requests SET status='revoked',review_note=?,reviewed_at=? "
                "WHERE exclusion_id=? AND status='approved'",
                (reason, self._now(), exclusion_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("排除状态已变化")
            self._audit(
                "observation",
                str(row["observation_id"]),
                "exclusion.revoked",
                actor_id,
                {"exclusion_id": exclusion_id, "reason": reason},
            )
        return {"exclusion_id": exclusion_id, "status": "revoked"}

    def seal_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.seal")
        current = self.get_batch(batch_id)
        protocol, _ = self._protocol(current["protocol_id"], current["protocol_version"])
        with transaction(self.connection, immediate=True):
            pending = self.connection.execute(
                "SELECT count(*) FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
                "WHERE o.batch_id=? AND e.status='pending'", (batch_id,)
            ).fetchone()[0]
            if pending:
                raise InvalidState("仍有待复核的排除申请")
            cursor = self.connection.execute(
                "UPDATE batches SET state='sealed',revision=revision+1,sealed_at=? "
                "WHERE batch_id=? AND state='running' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次状态或版本已变化")
            new_revision = expected_revision + 1
            now = self._now()
            self.connection.execute(
                "INSERT INTO analysis_jobs(batch_id,batch_revision,state,available_at,max_attempts,"
                "created_at,updated_at) VALUES(?,?, 'queued', ?,?,?,?)",
                (batch_id, new_revision, now, protocol.max_analysis_attempts, now, now),
            )
            self._audit("batch", batch_id, "batch.sealed", actor_id, {"revision": new_revision})
        return self.get_batch(batch_id)

    def claim_job(self, worker_id: str, lease_seconds: int = 60) -> dict[str, Any] | None:
        if lease_seconds <= 0:
            raise ValidationFailed("租约时长必须大于零")
        now_value = self.clock.now()
        now = isoformat(now_value)
        with transaction(self.connection, immediate=True):
            while True:
                row = self.connection.execute(
                    "SELECT * FROM analysis_jobs WHERE "
                    "(state='queued' AND available_at<=?) OR (state='leased' AND lease_expires_at<=?) "
                    "ORDER BY available_at,job_id LIMIT 1",
                    (now, now),
                ).fetchone()
                if row is None:
                    return None
                if row["state"] == "leased":
                    # 未显式报告失败就过期的尝试同样留下失败摘要，避免静默丢失。
                    history = json.loads(row["attempts_json"])
                    history.append({
                        "attempt": row["attempts"],
                        "worker": row["lease_owner"],
                        "outcome": "lease_expired",
                        "failed_at": now,
                        "error": "租约过期，任务被其他工作进程接管",
                    })
                    if row["attempts"] >= row["max_attempts"]:
                        # 最后一次机会也以过期告终：直接进入死信，继续寻找下一个可领取任务。
                        self.connection.execute(
                            "UPDATE analysis_jobs SET state='dead_letter',lease_owner=NULL,lease_token=NULL,"
                            "lease_expires_at=NULL,attempts_json=?,dead_letter_at=?,dead_letter_reason=?,"
                            "updated_at=? WHERE job_id=?",
                            (canonical_json(history), now,
                             f"连续 {row['attempts']} 次尝试均失败，达到上限 {row['max_attempts']}",
                             now, row["job_id"]),
                        )
                        self._audit(
                            "job", str(row["job_id"]), "job.dead_lettered", "system",
                            {"batch_id": row["batch_id"], "attempts": row["attempts"],
                             "max_attempts": row["max_attempts"], "last_error": "租约过期"},
                        )
                        continue
                else:
                    history = json.loads(row["attempts_json"])
                reclaimed = row["state"] == "leased"
                token = secrets.token_hex(16)
                expires = isoformat(now_value + timedelta(seconds=lease_seconds))
                self.connection.execute(
                    "UPDATE analysis_jobs SET state='leased',attempts=attempts+1,lease_owner=?,lease_token=?,"
                    "lease_expires_at=?,attempts_json=?,updated_at=? WHERE job_id=?",
                    (worker_id, token, expires, canonical_json(history), now, row["job_id"]),
                )
                claimed = self.connection.execute(
                    "SELECT * FROM analysis_jobs WHERE job_id=?", (row["job_id"],)
                ).fetchone()
                self._audit(
                    "job", str(row["job_id"]), "job.reclaimed" if reclaimed else "job.claimed",
                    worker_id,
                    {"batch_id": row["batch_id"], "attempt": claimed["attempts"], "lease_token": token},
                )
                return dict(claimed)

    def heartbeat_job(
        self, worker_id: str, job_id: int, lease_token: str, lease_seconds: int = 60
    ) -> dict[str, Any]:
        """工作进程在 fencing 凭证仍有效时延长租约；延长不会缩短既有期限。"""

        if lease_seconds <= 0:
            raise ValidationFailed("租约时长必须大于零")
        now_value = self.clock.now()
        now = isoformat(now_value)
        expires = isoformat(now_value + timedelta(seconds=lease_seconds))
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE analysis_jobs SET lease_expires_at=MAX(lease_expires_at,?),updated_at=? "
                "WHERE job_id=? AND state='leased' AND lease_owner=? AND lease_token=? "
                "AND lease_expires_at>?",
                (expires, now, job_id, worker_id, lease_token, now),
            )
            if cursor.rowcount != 1:
                raise InvalidState("凭证无效、任务已被接管或租约已过期，续约被拒绝")
            row = self.connection.execute(
                "SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
        return dict(row)

    def _analysis_observations(self, batch_id: str, protocol: Protocol) -> tuple[Observation, ...]:
        rows = self.connection.execute(
            "SELECT o.*,e.reason AS excluded_reason FROM observations o "
            "LEFT JOIN exclusion_requests e ON e.observation_id=o.observation_id AND e.status='approved' "
            "WHERE o.batch_id=? ORDER BY o.observation_id",
            (batch_id,),
        ).fetchall()
        items: list[Observation] = []
        for row in rows:
            metrics = json.loads(row["metrics_json"])
            items.append(Observation(
                source_batch=row["source_batch"],
                source_row=row["source_row"],
                robot_id=row["robot_id"],
                protocol_id=protocol.protocol_id,
                protocol_version=protocol.version,
                stratum_key=row["stratum_key"],
                observed_at=row["observed_at"],
                metrics={key: Decimal(str(value)) for key, value in metrics.items()},
                excluded_reason=row["excluded_reason"],
            ))
        return tuple(items)

    def complete_job(
        self, worker_id: str, job_id: int, statistician_id: str, lease_token: str
    ) -> dict[str, Any]:
        self._require(statistician_id, "analysis.run")
        job = self.connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)).fetchone()
        if job is None:
            raise NotFound("分析任务不存在")
        if (
            job["state"] != "leased"
            or job["lease_owner"] != worker_id
            or job["lease_token"] != lease_token
        ):
            raise InvalidState("任务未由当前工作进程以有效凭证持有")
        if job["lease_expires_at"] <= self._now():
            raise InvalidState("任务租约已经过期")
        batch = self.get_batch(job["batch_id"])
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        observations = self._analysis_observations(batch["batch_id"], protocol)
        snapshot_rows = [
            {
                "source_batch": item.source_batch,
                "source_row": item.source_row,
                "stratum": item.stratum_key,
                "metrics": {key: format(value, "f") for key, value in item.metrics.items()},
                "excluded_reason": item.excluded_reason,
            }
            for item in observations
        ]
        input_digest = content_digest(snapshot_rows)
        result = analyze(protocol, observations)
        with transaction(self.connection, immediate=True):
            existing = self.connection.execute(
                "SELECT analysis_id,result_json FROM analyses WHERE batch_id=? AND batch_revision=? AND input_sha256=?",
                (batch["batch_id"], job["batch_revision"], input_digest),
            ).fetchone()
            if existing is None:
                cursor = self.connection.execute(
                    "INSERT INTO analyses(batch_id,batch_revision,protocol_sha256,input_sha256,algorithm_version,seed,"
                    "result_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        batch["batch_id"], job["batch_revision"], protocol_digest, input_digest,
                        ALGORITHM_VERSION, protocol.seed, canonical_json(result), statistician_id, self._now(),
                    ),
                )
                analysis_id = cursor.lastrowid
            else:
                analysis_id = existing["analysis_id"]
                result = json.loads(existing["result_json"])
            now = self._now()
            history = json.loads(job["attempts_json"])
            history.append({
                "attempt": job["attempts"],
                "worker": worker_id,
                "outcome": "succeeded",
                "finished_at": now,
            })
            # 权威判定：状态、持有者、fencing 凭证与有效期必须同时成立。
            cursor = self.connection.execute(
                "UPDATE analysis_jobs SET state='succeeded',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,"
                "last_error=NULL,attempts_json=?,updated_at=? "
                "WHERE job_id=? AND state='leased' AND lease_owner=? AND lease_token=? AND lease_expires_at>?",
                (canonical_json(history), now, job_id, worker_id, lease_token, now),
            )
            if cursor.rowcount != 1:
                raise InvalidState("任务在分析期间已被接管或进入死信，结果不予接受")
            self.connection.execute(
                "UPDATE batches SET state='analyzed' WHERE batch_id=? AND state IN ('sealed','analyzing')",
                (batch["batch_id"],),
            )
            self._audit(
                "batch",
                batch["batch_id"],
                "analysis.completed",
                statistician_id,
                {"analysis_id": analysis_id, "input_sha256": input_digest},
            )
        return {"analysis_id": analysis_id, "input_sha256": input_digest, "result": result}

    def fail_job(self, worker_id: str, job_id: int, error: str, *, lease_token: str,
                 retry_seconds: int = 0) -> dict[str, Any]:
        if retry_seconds < 0:
            raise ValidationFailed("重试延迟不能为负")
        if not isinstance(lease_token, str) or not lease_token:
            raise ValidationFailed("fail_job 必须提供领取时获得的 fencing 凭证")
        message = error[:1000]
        now_value = self.clock.now()
        now = isoformat(now_value)
        available = isoformat(now_value + timedelta(seconds=retry_seconds))
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            if (
                row is None
                or row["state"] != "leased"
                or row["lease_owner"] != worker_id
                or row["lease_token"] != lease_token
            ):
                raise InvalidState("任务未由当前工作进程持有或凭证不匹配")
            if row["lease_expires_at"] <= now:
                raise InvalidState("任务租约已经过期")
            history = json.loads(row["attempts_json"])
            history.append({
                "attempt": row["attempts"],
                "worker": worker_id,
                "outcome": "failed",
                "failed_at": now,
                "retry_after_seconds": retry_seconds,
                "error": message,
            })
            history_json = canonical_json(history)
            if row["attempts"] >= row["max_attempts"]:
                # 已用尽协议或系统配置的尝试上限：转入死信，保留每次失败摘要。
                self.connection.execute(
                    "UPDATE analysis_jobs SET state='dead_letter',lease_owner=NULL,lease_token=NULL,"
                    "lease_expires_at=NULL,last_error=?,attempts_json=?,"
                    "dead_letter_at=?,dead_letter_reason=?,updated_at=? WHERE job_id=?",
                    (message, history_json, now,
                     f"连续 {row['attempts']} 次尝试均失败，达到上限 {row['max_attempts']}", now, job_id),
                )
                self._audit(
                    "job", str(job_id), "job.dead_lettered", worker_id,
                    {"batch_id": row["batch_id"], "attempts": row["attempts"],
                     "max_attempts": row["max_attempts"], "last_error": message},
                )
                return {"job_id": job_id, "state": "dead_letter", "available_at": None}
            self.connection.execute(
                "UPDATE analysis_jobs SET state='queued',available_at=?,lease_owner=NULL,lease_token=NULL,"
                "lease_expires_at=NULL,last_error=?,attempts_json=?,updated_at=? WHERE job_id=?",
                (available, message, history_json, now, job_id),
            )
        return {"job_id": job_id, "state": "queued", "available_at": available}

    def get_job(self, actor_id: str, job_id: int) -> dict[str, Any]:
        self._require(actor_id, "analysis.deadletter.read")
        row = self.connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise NotFound("分析任务不存在")
        result = dict(row)
        result["attempt_history"] = json.loads(row["attempts_json"])
        return result

    def list_dead_letter_jobs(self, actor_id: str) -> list[dict[str, Any]]:
        """值班视角：列出死信与已取消任务，附全部尝试摘要。"""

        self._require(actor_id, "analysis.deadletter.read")
        rows = self.connection.execute(
            "SELECT * FROM analysis_jobs WHERE state IN ('dead_letter','cancelled') "
            "ORDER BY COALESCE(dead_letter_at,cancelled_at),job_id"
        ).fetchall()
        return [dict(row) | {"attempt_history": json.loads(row["attempts_json"])} for row in rows]

    def requeue_dead_job(
        self, actor_id: str, job_id: int, reason: str, max_attempts: int | None = None
    ) -> dict[str, Any]:
        """授权统计负责人带理由把死信任务重新入队；已取消任务不能由此复活。"""

        self._require(actor_id, "analysis.deadletter.requeue")
        if not reason.strip():
            raise ValidationFailed("重新入队必须填写理由")
        if max_attempts is not None and max_attempts <= 0:
            raise ValidationFailed("最大尝试次数必须大于零")
        now = self._now()
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            if row is None:
                raise NotFound("分析任务不存在")
            if row["state"] == "cancelled":
                raise InvalidState("已永久取消的任务不能重新入队")
            if row["state"] != "dead_letter":
                raise InvalidState("只有死信任务可以人工重新入队")
            new_max = max_attempts or row["max_attempts"]
            history = json.loads(row["attempts_json"])
            history.append({
                "attempt": None,
                "worker": None,
                "outcome": "manually_requeued",
                "at": now,
                "actor": actor_id,
                "reason": reason,
                "new_max_attempts": new_max,
            })
            self.connection.execute(
                "UPDATE analysis_jobs SET state='queued',available_at=?,attempts=0,lease_owner=NULL,"
                "lease_token=NULL,lease_expires_at=NULL,max_attempts=?,requeued_count=requeued_count+1,"
                "dead_letter_at=NULL,dead_letter_reason=NULL,dead_letter_actor=NULL,"
                "attempts_json=?,updated_at=? WHERE job_id=? AND state='dead_letter'",
                (now, new_max, canonical_json(history), now, job_id),
            )
            self._audit(
                "job", str(job_id), "job.requeued", actor_id,
                {"batch_id": row["batch_id"], "reason": reason, "max_attempts": new_max},
            )
        return {"job_id": job_id, "state": "queued", "available_at": now, "max_attempts": new_max}

    def cancel_dead_job(self, actor_id: str, job_id: int, reason: str) -> dict[str, Any]:
        """授权统计负责人带理由永久取消死信任务。"""

        self._require(actor_id, "analysis.deadletter.cancel")
        if not reason.strip():
            raise ValidationFailed("取消必须填写理由")
        now = self._now()
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            if row is None:
                raise NotFound("分析任务不存在")
            if row["state"] == "cancelled":
                raise InvalidState("任务已经取消")
            if row["state"] != "dead_letter":
                raise InvalidState("只有死信任务可以永久取消")
            self.connection.execute(
                "UPDATE analysis_jobs SET state='cancelled',cancelled_at=?,cancel_reason=?,cancel_actor=?,"
                "lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=? "
                "WHERE job_id=? AND state='dead_letter'",
                (now, reason[:1000], actor_id, now, job_id),
            )
            self._audit(
                "job", str(job_id), "job.cancelled", actor_id,
                {"batch_id": row["batch_id"], "reason": reason},
            )
        return {"job_id": job_id, "state": "cancelled", "cancelled_at": now}

    def decide(
        self, actor_id: str, batch_id: str, analysis_id: int, decision: str, reason: str
    ) -> dict[str, Any]:
        self._require(actor_id, "decision.write")
        if decision not in {"needs_more_data", "approved", "rejected"}:
            raise ValidationFailed("未知准入决定")
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE analysis_id=? AND batch_id=?", (analysis_id, batch_id)
        ).fetchone()
        if analysis_row is None:
            raise NotFound("分析版本不存在")
        if analysis_row["created_by"] == actor_id:
            raise Forbidden("统计负责人不能批准自己的分析")
        batch = self.get_batch(batch_id)
        if batch["state"] != "analyzed" or batch["revision"] != analysis_row["batch_revision"]:
            raise InvalidState("分析不是批次当前可审批版本")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO decisions(batch_id,analysis_id,decision,reason,decided_by,decided_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (batch_id, analysis_id, decision, reason, actor_id, self._now()),
                )
                self.connection.execute("UPDATE batches SET state='decided' WHERE batch_id=?", (batch_id,))
                self._audit(
                    "batch",
                    batch_id,
                    "decision.recorded",
                    actor_id,
                    {"decision_id": cursor.lastrowid, "analysis_id": analysis_id, "decision": decision},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该分析版本已经形成决定") from exc
        return {"batch_id": batch_id, "analysis_id": analysis_id, "decision": decision}

    def report(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        user = self._user(actor_id)
        if user["role"] not in {"statistician", "approver", "auditor"}:
            raise Forbidden("当前角色不能读取完整报告")
        batch = self.get_batch(batch_id)
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE batch_id=? ORDER BY analysis_id DESC LIMIT 1", (batch_id,)
        ).fetchone()
        decision_row = None
        if analysis_row is not None:
            decision_row = self.connection.execute(
                "SELECT * FROM decisions WHERE analysis_id=?", (analysis_row["analysis_id"],)
            ).fetchone()
        exclusions = self.connection.execute(
            "SELECT e.exclusion_id,e.observation_id,e.status,e.reason,e.requested_by,e.reviewed_by "
            "FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
            "WHERE o.batch_id=? ORDER BY e.exclusion_id", (batch_id,)
        ).fetchall()
        events = self.connection.execute(
            "SELECT event_type,actor_id,payload_json,created_at FROM audit_events "
            "WHERE entity_type='batch' AND entity_id=? "
            "ORDER BY event_id", (batch_id,)
        ).fetchall()
        job_row = self.connection.execute(
            "SELECT * FROM analysis_jobs WHERE batch_id=? ORDER BY job_id DESC LIMIT 1", (batch_id,)
        ).fetchone()
        job = None if job_row is None else {
            "job_id": job_row["job_id"],
            "state": job_row["state"],
            "attempts": job_row["attempts"],
            "max_attempts": job_row["max_attempts"],
            "lease_owner": job_row["lease_owner"],
            "lease_expires_at": job_row["lease_expires_at"],
            "available_at": job_row["available_at"],
            "last_error": job_row["last_error"],
            "dead_letter_at": job_row["dead_letter_at"],
            "dead_letter_reason": job_row["dead_letter_reason"],
            "cancelled_at": job_row["cancelled_at"],
            "cancel_reason": job_row["cancel_reason"],
            "requeued_count": job_row["requeued_count"],
            "attempt_history": json.loads(job_row["attempts_json"]),
        }
        return {
            "batch": batch,
            "job": job,
            "protocol": {
                "protocol_id": protocol.protocol_id,
                "version": protocol.version,
                "sha256": protocol_digest,
                "seed": protocol.seed,
                "bootstrap_samples": protocol.bootstrap_samples,
            },
            "analysis": None if analysis_row is None else {
                "analysis_id": analysis_row["analysis_id"],
                "input_sha256": analysis_row["input_sha256"],
                "algorithm_version": analysis_row["algorithm_version"],
                "created_by": analysis_row["created_by"],
                "result": json.loads(analysis_row["result_json"]),
            },
            "decision": None if decision_row is None else dict(decision_row),
            "exclusions": [dict(row) for row in exclusions],
            "events": [dict(row) | {"payload": json.loads(row["payload_json"])} for row in events],
        }
