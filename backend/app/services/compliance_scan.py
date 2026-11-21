"""合规扫描领域服务：数据资产的合规性自动扫描、违规发现和修复追踪。

接收数据契约的Schema验证和操作日志的异常检测作为扫描输入。
"""
from __future__ import annotations

import time as _time
from typing import Any

from app.services.base import BaseModuleService
from app.store import store


class ComplianceScanService(BaseModuleService):
    MODULE = "compliance_scan"
    ENTITY = "扫描任务"
    OPERATION_TERM = "校验"
    LIST_FIELDS = ["任务编号", "目标资产", "合规条款", "检查规则", "扫描范围", "违规发现", "修复意见", "扫描时间"]
    REQUIRED_FIELDS = ["任务编号", "目标资产", "合规条款"]
    STATUS_ORDER = ["待扫描", "扫描中", "已通过", "存在违规"]
    ACTION_RULES = {"启动扫描": "扫描中", "确认通过": "已通过", "标记违规": "存在违规"}
    NEGATIVE_ACTIONS = ["标记违规"]

    def scan_asset(self, asset_code: str, compliance_clause: str, check_rules: list[str]) -> dict[str, Any]:
        """对资产执规扫描（Pipeline 5/8 核心方法）。"""
        scan_id = store.next_id(self.MODULE)
        violations = []

        for rule in check_rules:
            # 根据规则类型检查资产
            if "分类" in rule or "classification" in rule.lower():
                classifications = [
                    c for c in store.rows("classification")
                    if str(c.get("目标字段", "")).startswith(f"{asset_code}.")
                ]
                pending = [c for c in classifications if c.get("status") == "待复核"]
                if pending:
                    violations.append(f"存在{len(pending)}个待复核的分级标签")

            if "脱敏" in rule or "anonym" in rule.lower():
                for c in store.rows("classification"):
                    if str(c.get("目标字段", "")).startswith(f"{asset_code}."):
                        if c.get("敏感等级") == "高" and c.get("status") == "已确认":
                            # 检查是否有对应脱敏规则
                            anonym_rules = store.find_by_field("data_anonym", "目标字段", c.get("目标字段", ""))
                            if not anonym_rules:
                                violations.append(f"高敏感字段{c.get('目标字段','')}缺少脱敏规则")

            if "契约" in rule or "contract" in rule.lower():
                contracts = store.find_by_field("data_contract", "数据资产", asset_code)
                violated = [c for c in contracts if c.get("status") == "已违约"]
                if violated:
                    violations.append(f"存在{len(violated)}个违约契约")

            if "操作" in rule or "log" in rule.lower():
                anomalies = [
                    a for a in store.rows("operation_log")
                    if a.get("目标资产") == asset_code and a.get("status") == "已异常"
                ]
                if anomalies:
                    violations.append(f"存在{len(anomalies)}条异常操作记录需要核实")

        passed = len(violations) == 0

        scan = {
            "id": scan_id,
            "任务编号": f"COMP-{scan_id:04d}",
            "目标资产": asset_code,
            "合规条款": compliance_clause,
            "检查规则": "; ".join(check_rules),
            "扫描范围": "全量",
            "违规发现": "; ".join(violations) if violations else "",
            "修复意见": self._generate_remediation(violations),
            "扫描时间": _time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "已通过" if passed else "存在违规",
            "pending": not passed,
            "abnormal": not passed,
            "created_at": _time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        store.rows(self.MODULE).append(scan)

        # 如果有违规，创建治理问题
        if not passed:
            self._create_compliance_issue(asset_code, violations)

        store.log_change(
            self.MODULE, scan_id, "合规扫描",
            before=None, after=f"{'通过' if passed else '违规'}: {len(violations)}项违规",
            source="pipeline_5", scope="compliance_scan"
        )

        self.emit_event("compliance_scanned", {
            "scan_id": scan_id,
            "asset_code": asset_code,
            "passed": passed,
            "violations_count": len(violations),
        })

        return {
            "scan": scan,
            "passed": passed,
            "violations": violations,
            "pipeline": "compliance_scan->issue_track" if not passed else None,
        }

    def _generate_remediation(self, violations: list[str]) -> str:
        if not violations:
            return "无需修复"
        return f"发现{len(violations)}项违规: {'; '.join(violations)}。建议逐一确认并制定修复方案。"

    def _create_compliance_issue(self, asset_code: str, violations: list[str]) -> None:
        """合规扫描发现违规时创建治理问题。"""
        issue_id = store.next_id("issue_track")
        issue = {
            "id": issue_id,
            "问题编号": f"ISSU-COMP-{issue_id:04d}",
            "关联资产": asset_code,
            "问题类型": "合规违规",
            "严重级别": "需关注" if len(violations) <= 2 else "严重",
            "指派处理": "合规管理员",
            "当前状态": "待处理",
            "修复方案": "逐项处理合规违规问题: " + "; ".join(violations),
            "截止日期": _time.strftime("%Y-%m-%d", _time.localtime(_time.time() + 86400 * 14)),
            "status": "待确认",
            "pending": True,
            "abnormal": True,
            "created_at": _time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        store.rows("issue_track").append(issue)

    def get_scans_by_asset(self, asset_code: str) -> list[dict[str, Any]]:
        return store.find_by_field(self.MODULE, "目标资产", asset_code)

    def get_violations(self) -> list[dict[str, Any]]:
        return [r for r in store.rows(self.MODULE) if r.get("status") == "存在违规"]

    # ── 异常访问追溯联动：扫描待办与追溯命中保持一致 ─────────

    def scan_audit_trace(self, trace_id: int) -> dict[str, Any]:
        """按追溯会话的冻结命中明细生成扫描待办，重复扫描不产生重复待办。"""
        from app.services.audit_trace import AuditTraceService

        audit = AuditTraceService()
        result = audit.get_trace_hits(trace_id, page=1, size=1_000_000)
        session = audit._require_session(trace_id)
        existing_refs = {
            sc.get("trace_hit_ref")
            for sc in store.rows(self.MODULE)
            if sc.get("trace_id") == trace_id
        }

        todos: list[dict[str, Any]] = []
        for hit in result["items"]:
            ref = f"{trace_id}:{hit['日志id']}"
            if ref in existing_refs:
                continue
            scan_id = store.next_id(self.MODULE)
            basis = "；".join(item["依据"] for item in hit["分级依据"])
            scan = {
                "id": scan_id,
                "任务编号": f"COMP-AUDIT-{scan_id:04d}",
                "目标资产": hit["目标资产"],
                "合规条款": "异常访问追溯",
                "检查规则": "高敏字段下载访问时点分级核查",
                "扫描范围": f"{session['开始时间']}~{session['结束时间']}",
                "违规发现": (
                    f"操作人{hit['操作人']}于{hit['操作时间']}下载高敏字段"
                    f"{'、'.join(b['字段'] for b in hit['分级依据'])}"
                ),
                "修复意见": "逐笔核实访问授权与业务必要性，确认后闭环",
                "扫描时间": _time.strftime("%Y-%m-%d %H:%M:%S"),
                "status": "存在违规",
                "pending": True,
                "abnormal": True,
                "triggered_by": "audit_trace",
                "trace_id": trace_id,
                "访问序号": hit["访问序号"],
                "trace_hit_ref": ref,
                "分级依据": basis,
                "created_at": _time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            store.rows(self.MODULE).append(scan)
            todos.append(scan)

        session["扫描状态"] = "扫描完成"
        store.set_pipeline_state(f"{AuditTraceService.SESSION_STATE_PREFIX}{trace_id}", session)
        entry = store.find("audit_trace", trace_id)
        if entry is not None:
            entry["status"] = "扫描完成"
            entry["扫描状态"] = "扫描完成"

        trace_todos = [
            sc for sc in store.rows(self.MODULE)
            if sc.get("trace_id") == trace_id
        ]
        store.log_change(
            self.MODULE, trace_id, "追溯扫描",
            before=None,
            after=f"命中{result['total']}笔，待办{len(trace_todos)}条，补报{result['supplement_count']}笔",
            source="audit_trace", scope="compliance_scan",
        )
        return {
            "trace_id": trace_id,
            "hit_total": result["total"],
            "new_todos": len(todos),
            "todo_total": len(trace_todos),
            "supplement_count": result["supplement_count"],
            "todos": trace_todos,
        }