"""异常访问追溯领域服务：按操作人、资产、发生时间从访问日志定位异常访问明细。

解决审计复查中的四个口径问题：
1. 同一人同一时刻对一张表的多列操作只登记一次下载（按 操作人+资产+发生时间 去重）；
2. 字段级分级在访问之后才更正的，按访问发生时点的分级口径判定（point-in-time）；
3. 追溯会话开启时冻结候选集与分页边界，查询期间补报的访问不挤占原分页，只计入补报数；
4. 扫描待办直接由追溯命中生成并按访问序号去重，复查与命中明细保持一致，
   同名操作人在其他资产上的访问不会凭人名混入。
"""
from __future__ import annotations

import time as _time
from typing import Any

from app.services.base import BaseModuleService
from app.services.classification import ClassificationService
from app.store import store


class AuditTraceService(BaseModuleService):
    MODULE = "audit_trace"
    ENTITY = "追溯会话"
    OPERATION_TERM = "校验"
    LIST_FIELDS = ["追溯编号", "操作人", "目标资产", "开始时间", "结束时间", "扫描状态", "命中数", "补报数"]
    REQUIRED_FIELDS = ["追溯编号", "操作人", "目标资产", "开始时间", "结束时间"]
    STATUS_ORDER = ["追溯中", "扫描完成", "已关闭"]
    ACTION_RULES = {"完成扫描": "扫描完成", "关闭追溯": "已关闭"}
    NEGATIVE_ACTIONS: list[str] = []

    SESSION_STATE_PREFIX = "audit_trace:session:"

    # ── 访问日志登记：同人同表同时刻多列只记一次下载 ──────────

    def record_download(
        self,
        operator: str,
        asset_code: str,
        occurred_at: str,
        *,
        columns: list[str] | None = None,
        source_node: str = "workstation",
        fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """登记一次下载访问；同一操作人对同一资产同一时刻的多列操作合并为一条。"""
        occurred_at = self._as_datetime(occurred_at)
        columns = sorted({col for col in (columns or fields or []) if col})

        for row in store.rows("operation_log"):
            if (
                row.get("操作人") == operator
                and row.get("目标资产") == asset_code
                and row.get("操作时间") == occurred_at
            ):
                merged = sorted(set(row.get("访问列", [])) | set(columns))
                row["访问列"] = merged
                row["dedup_merged"] = True
                return row

        log_id = store.next_id("operation_log")
        record = {
            "id": log_id,
            "记录编号": f"OPER-{log_id:04d}",
            "目标资产": asset_code,
            "操作人": operator,
            "操作类型": "下载",
            "操作时间": occurred_at,
            "来源节点": source_node,
            "处理结果": "成功",
            "异常结论": "-",
            "访问列": columns,
            # 访问序号全局单调，历史分级结论按该序号引用，不再随分页/补报漂移。
            "访问序号": self._next_access_seq(),
            "dedup_merged": False,
            "status": "已记录",
            "pending": True,
            "abnormal": False,
            "created_at": _time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        store.rows("operation_log").append(record)
        return record

    def _next_access_seq(self) -> int:
        existing = [int(r.get("访问序号", 0)) for r in store.rows("operation_log") if r.get("访问序号")]
        return max(existing, default=0) + 1

    # ── 追溯会话：冻结候选集与分页边界 ───────────────────────

    def open_trace(
        self,
        operator: str,
        asset_code: str,
        start_time: str,
        end_time: str,
        *,
        page: int = 1,
        size: int = 20,
    ) -> dict[str, Any]:
        """对指定时间段发起一次追溯，候选集在会话开启时即冻结。"""
        start_time = self._as_datetime(start_time)
        end_time = self._as_datetime(end_time)

        candidates = [
            row for row in store.rows("operation_log")
            if row.get("操作人") == operator
            and row.get("目标资产") == asset_code
            and start_time <= str(row.get("操作时间", "")) <= end_time
        ]
        candidates.sort(key=lambda r: (str(r.get("操作时间", "")), int(r.get("id", 0))))
        hits = [self._build_hit(row) for row in candidates]
        hits = [hit for hit in hits if hit["命中"]]

        trace_id = store.next_id(self.MODULE)
        code = f"AUDIT-{trace_id:04d}"
        snapshot_ids = [int(row["id"]) for row in candidates]
        session = {
            "trace_id": trace_id,
            "追溯编号": code,
            "操作人": operator,
            "目标资产": asset_code,
            "开始时间": start_time,
            "结束时间": end_time,
            "page": page,
            "size": size,
            "candidate_ids": snapshot_ids,
            "hit_ids": [hit["日志id"] for hit in hits],
            "hit_count": len(hits),
            "supplement_count": 0,
            "supplement_ids": [],
            "扫描状态": "待扫描",
            "opened_at": _time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        store.set_pipeline_state(f"{self.SESSION_STATE_PREFIX}{trace_id}", session)

        entry = {
            "id": trace_id,
            "追溯编号": code,
            "操作人": operator,
            "目标资产": asset_code,
            "开始时间": start_time,
            "结束时间": end_time,
            "扫描状态": session["扫描状态"],
            "命中数": str(len(hits)),
            "补报数": "0",
            "status": "追溯中",
            "pending": True,
            "abnormal": False,
            "created_at": session["opened_at"],
        }
        store.rows(self.MODULE).append(entry)
        return {"entry": entry, "session": session}

    def get_trace_hits(self, trace_id: int, page: int | None = None, size: int | None = None) -> dict[str, Any]:
        """读取追溯命中；补报访问只进补报清单，不改变原分页边界。"""
        session = self._require_session(trace_id)
        page = session["page"] if page is None else page
        size = session["size"] if size is None else size

        frozen_ids = set(session["candidate_ids"])
        frozen_rows = [
            row for row in store.rows("operation_log")
            if int(row.get("id", 0)) in frozen_ids
        ]
        frozen_rows.sort(key=lambda r: (str(r.get("操作时间", "")), int(r.get("id", 0))))
        hits = [self._build_hit(row) for row in frozen_rows]
        hits = [hit for hit in hits if hit["命中"]]

        # 会话开启后才补报、且本应落入同一段时间窗的访问：保留原分页，单独挂出。
        supplement_rows = [
            row for row in store.rows("operation_log")
            if int(row.get("id", 0)) not in frozen_ids
            and row.get("操作人") == session["操作人"]
            and row.get("目标资产") == session["目标资产"]
            and session["开始时间"] <= str(row.get("操作时间", "")) <= session["结束时间"]
        ]
        supplement_rows.sort(key=lambda r: (str(r.get("操作时间", "")), int(r.get("id", 0))))
        supplement_hits = [self._build_hit(row) for row in supplement_rows]
        supplement_hits = [hit for hit in supplement_hits if hit["命中"]]

        known_supplement = set(session.get("supplement_ids", []))
        new_supplement = [
            int(row["id"]) for row in supplement_rows if int(row["id"]) not in known_supplement
        ]
        if new_supplement:
            session["supplement_ids"] = sorted(known_supplement | set(new_supplement))
            session["supplement_count"] = len(session["supplement_ids"])
            entry = store.find(self.MODULE, trace_id)
            if entry is not None:
                entry["补报数"] = str(session["supplement_count"])
            store.set_pipeline_state(f"{self.SESSION_STATE_PREFIX}{trace_id}", session)

        total = len(hits)
        start = (page - 1) * size
        return {
            "trace_id": trace_id,
            "追溯编号": session["追溯编号"],
            "items": hits[start:start + size],
            "total": total,
            "page": page,
            "size": size,
            "frozen_candidate_count": len(frozen_ids),
            "supplement_hits": supplement_hits,
            "supplement_count": session["supplement_count"],
            "scan_status": session["扫描状态"],
        }

    def close_trace(self, trace_id: int) -> dict[str, Any]:
        session = self._require_session(trace_id)
        session["扫描状态"] = "已关闭"
        store.set_pipeline_state(f"{self.SESSION_STATE_PREFIX}{trace_id}", session)
        entry = store.find(self.MODULE, trace_id)
        if entry is not None:
            entry["status"] = "已关闭"
            entry["pending"] = False
            entry["扫描状态"] = "已关闭"
        return session

    def _require_session(self, trace_id: int) -> dict[str, Any]:
        session = store.get_pipeline_state(f"{self.SESSION_STATE_PREFIX}{trace_id}")
        if session is None:
            raise KeyError(f"追溯会话 {trace_id} 不存在")
        return session

    # ── 命中判定：按访问发生时点的分级口径 ───────────────────

    def _build_hit(self, row: dict[str, Any]) -> dict[str, Any]:
        """为单条访问构建命中结论，逐笔给出薪资表访问被选入的分级依据。"""
        asset_code = str(row.get("目标资产", ""))
        occurred_at = str(row.get("操作时间", ""))
        columns = list(row.get("访问列", [])) or [""]

        classification = ClassificationService()
        high_basis: list[dict[str, Any]] = []
        field_levels: list[dict[str, Any]] = []
        for column in columns:
            if not column:
                level, effective_at = classification.field_level_at(asset_code, "", occurred_at)
            else:
                level, effective_at = classification.field_level_at(asset_code, column, occurred_at)
            field_levels.append({
                "字段": column,
                "时点敏感等级": level or "未分级",
                "分级生效时间": effective_at,
            })
            if level == "高":
                high_basis.append({
                    "字段": column,
                    "时点敏感等级": "高",
                    "分级生效时间": effective_at,
                    "依据": (
                        f"字段{asset_code}.{column}自{effective_at}起为高敏，"
                        f"访问发生于{occurred_at}，按发生时点分级口径命中"
                    ),
                })

        return {
            "命中": bool(high_basis),
            "访问序号": row.get("访问序号"),
            "日志id": int(row.get("id", 0)),
            "记录编号": row.get("记录编号"),
            "操作人": row.get("操作人"),
            "目标资产": asset_code,
            "操作时间": occurred_at,
            "访问列": list(row.get("访问列", [])),
            "字段时点分级": field_levels,
            "分级依据": high_basis,
        }

    @staticmethod
    def _as_datetime(value: str) -> str:
        value = str(value or "").strip()
        if len(value) == 10:
            return f"{value} 00:00:00"
        if len(value) == 16:
            return f"{value}:00"
        return value

    def reset_for_test(self) -> None:
        """测试辅助：清掉追溯会话状态。"""
        for key in list(store._pipeline_state.keys()):
            if key.startswith(self.SESSION_STATE_PREFIX):
                store._pipeline_state.pop(key)
