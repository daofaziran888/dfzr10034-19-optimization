"""数据分级领域服务：敏感数据自动识别、分级标注和人工复核。

接收数据画像的分析结果，对敏感字段进行分级标注。
"""
from __future__ import annotations

import time as _time
from typing import Any

from app.services.base import BaseModuleService
from app.store import store


class ClassificationService(BaseModuleService):
    MODULE = "classification"
    ENTITY = "分级标签"
    OPERATION_TERM = "校验"
    LIST_FIELDS = ["标签编号", "目标字段", "敏感等级", "识别规则", "识别置信度", "人工复核", "复核人", "生效日期"]
    REQUIRED_FIELDS = ["标签编号", "目标字段", "敏感等级"]
    STATUS_ORDER = ["待复核", "已确认", "误识别", "已降级"]
    ACTION_RULES = {"确认分级": "已确认", "标记误识别": "误识别", "申请降级": "已降级"}
    NEGATIVE_ACTIONS = ["标记误识别"]

    def classify_field(self, asset_code: str, field_name: str, level: str, rule: str, confidence: str = "0.90") -> dict[str, Any]:
        """为指定字段创建分级标签。"""
        label = {
            "id": store.next_id(self.MODULE),
            "标签编号": f"CLAS-{asset_code}-{field_name}",
            "目标字段": f"{asset_code}.{field_name}",
            "敏感等级": level,
            "识别规则": rule,
            "识别置信度": confidence,
            "人工复核": "否",
            "复核人": "",
            "生效日期": _time.strftime("%Y-%m-%d"),
            "status": "待复核",
            "pending": True,
            "abnormal": False,
            "created_at": _time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        store.rows(self.MODULE).append(label)
        return label

    def get_sensitive_fields(self, asset_code: str) -> list[dict[str, Any]]:
        """查询资产的所有敏感字段分级标签。"""
        prefix = f"{asset_code}."
        return [
            row for row in store.rows(self.MODULE)
            if str(row.get("目标字段", "")).startswith(prefix)
        ]

    def confirm_classification(self, label_id: int) -> dict[str, Any] | None:
        """人工确认分级标签。"""
        entry, msg = self.run_action(label_id, "确认分级")
        if entry:
            entry["人工复核"] = "是"
            entry["复核人"] = "合规管理员"
            store.log_change(
                self.MODULE, label_id, "确认分级",
                before="待复核", after="已确认",
                source="manual_review", scope="classification"
            )
        return entry

    def get_all_confirmed(self) -> list[dict[str, Any]]:
        """获取所有已确认的高敏感字段。"""
        return [
            row for row in store.rows(self.MODULE)
            if row.get("status") == "已确认"
        ]

    @staticmethod
    def _as_datetime(value: str) -> str:
        """把日期/日期时间统一成可比较的 `YYYY-MM-DD HH:MM:SS`。"""
        value = str(value or "").strip()
        if len(value) == 10:
            return f"{value} 00:00:00"
        if len(value) == 16:
            return f"{value}:00"
        return value

    def adjust_field_level(
        self,
        asset_code: str,
        field_name: str,
        new_level: str,
        *,
        changed_at: str | None = None,
        reviewer: str = "合规管理员",
        reason: str = "字段分级更正",
    ) -> dict[str, Any]:
        """按发生时间更正字段分级，保留完整分级履历，历史时点结论不被覆盖。

        审计追溯按访问发生时点取分级：午间把某列调成高敏后，上午的访问仍按
        当时的低敏口径判定，下午的访问才按高敏命中。
        """
        target = f"{asset_code}.{field_name}"
        changed_at = self._as_datetime(changed_at or _time.strftime("%Y-%m-%d %H:%M:%S"))
        label = next(
            (row for row in store.rows(self.MODULE) if row.get("目标字段") == target),
            None,
        )

        if label is None:
            label = self.classify_field(asset_code, field_name, new_level, "人工更正", "1.00")
            label["status"] = "已确认"
            label["pending"] = False
            label["人工复核"] = "是"
            label["复核人"] = reviewer
            label["生效日期"] = changed_at[:10]
            label["level_history"] = [{
                "敏感等级": new_level, "生效时间": changed_at,
                "复核人": reviewer, "变更原因": reason,
            }]
            store.log_change(
                self.MODULE, label["id"], "分级更正",
                before=None, after=f"{target}:{new_level}",
                source="audit_reclassify", scope="classification",
            )
            return label

        previous = str(label.get("敏感等级", ""))
        history = label.setdefault("level_history", [])
        if not history:
            base_time = self._as_datetime(str(label.get("生效日期") or "")) or "1970-01-01 00:00:00"
            history.append({
                "敏感等级": previous, "生效时间": base_time,
                "复核人": str(label.get("复核人", "")), "变更原因": "初始分级",
            })
        history.append({
            "敏感等级": new_level, "生效时间": changed_at,
            "复核人": reviewer, "变更原因": reason,
        })
        history.sort(key=lambda item: item["生效时间"])

        label["敏感等级"] = new_level
        label["status"] = "已确认"
        label["pending"] = False
        label["人工复核"] = "是"
        label["复核人"] = reviewer
        store.log_change(
            self.MODULE, label["id"], "分级更正",
            before=f"{target}:{previous}", after=f"{target}:{new_level}",
            source="audit_reclassify", scope="classification",
        )
        return label

    def field_level_at(self, asset_code: str, field_name: str, at_time: str) -> tuple[str, str]:
        """返回字段在指定时点的已确认敏感等级及其分级生效时间；未确认或无履历返回空。"""
        target = f"{asset_code}.{field_name}"
        at_time = self._as_datetime(at_time)
        label = next(
            (row for row in store.rows(self.MODULE) if row.get("目标字段") == target),
            None,
        )
        if label is None or label.get("status") != "已确认":
            return "", ""

        history = label.get("level_history")
        if history:
            effective: dict[str, Any] | None = None
            for item in sorted(history, key=lambda h: h["生效时间"]):
                if item["生效时间"] <= at_time:
                    effective = item
                else:
                    break
            if effective is None:
                return "", ""
            return str(effective["敏感等级"]), str(effective["生效时间"])

        base_time = self._as_datetime(str(label.get("生效日期") or "")) or "1970-01-01 00:00:00"
        if base_time <= at_time:
            return str(label.get("敏感等级", "")), base_time
        return "", ""