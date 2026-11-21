"""异常访问追溯测试：分级时点口径、去重、分页冻结与扫描待办一致性。

叙事场景：
- 审计对象（操作人 周审计）交替下载 salary_month 与 shop_total；
- 午间仅把薪资表 salary_month.salary_amt 一列由中敏更正为高敏；
- 对上午至傍晚发起一次追溯，逐笔核对薪资表访问的分级依据；
- 商店统计表的读取、其他人的同名/同表访问都不得混入命中。
"""
import app.store as store_mod
from app.services.audit_trace import AuditTraceService
from app.services.classification import ClassificationService
from app.services.compliance_scan import ComplianceScanService


DAY = "2026-11-20"


def _fresh():
    store_mod.store.reset()
    store_mod.store.rows("classification").clear()
    store_mod.store.rows("operation_log").clear()
    store_mod.store.rows("compliance_scan").clear()
    return AuditTraceService(), ClassificationService(), ComplianceScanService()


def _confirmed_label(target: str, level: str, effective: str) -> None:
    asset, field = target.split(".", 1)
    label = {
        "id": store_mod.store.next_id("classification"),
        "标签编号": f"CLAS-{asset}-{field}",
        "目标字段": target,
        "敏感等级": level,
        "识别规则": "人工标注",
        "识别置信度": "1.00",
        "人工复核": "是",
        "复核人": "合规管理员",
        "生效日期": effective,
        "status": "已确认",
        "pending": False,
        "abnormal": False,
        "level_history": [{
            "敏感等级": level,
            "生效时间": f"{effective} 00:00:00",
            "复核人": "合规管理员",
            "变更原因": "初始分级",
        }],
    }
    store_mod.store.rows("classification").append(label)


def _setup_classification(classification: ClassificationService) -> None:
    _confirmed_label("salary_month.emp_id", "低", "2026-11-01")
    _confirmed_label("salary_month.salary_amt", "中", "2026-11-01")
    _confirmed_label("shop_total.shop_id", "低", "2026-11-01")
    _confirmed_label("shop_total.sales_amt", "低", "2026-11-01")
    # 午间更正：仅薪资表的 salary_amt 一列转为高敏。
    classification.adjust_field_level(
        "salary_month", "salary_amt", "高",
        changed_at=f"{DAY} 12:30:00", reason="午间分级更正",
    )


class TestPointInTimeClassification:

    def test_level_lookup_uses_occurrence_time(self):
        _, classification, _ = _fresh()
        _setup_classification(classification)

        level_morning, eff_morning = classification.field_level_at(
            "salary_month", "salary_amt", f"{DAY} 09:00:00")
        level_noon, eff_noon = classification.field_level_at(
            "salary_month", "salary_amt", f"{DAY} 13:00:00")

        assert level_morning == "中"
        assert eff_morning == "2026-11-01 00:00:00"
        assert level_noon == "高"
        assert eff_noon == f"{DAY} 12:30:00"

    def test_history_keeps_previous_level_conclusion(self):
        _, classification, _ = _fresh()
        _setup_classification(classification)
        label = next(
            c for c in store_mod.store.rows("classification")
            if c["目标字段"] == "salary_month.salary_amt"
        )
        levels = [(h["生效时间"], h["敏感等级"]) for h in label["level_history"]]
        assert ("2026-11-01 00:00:00", "中") in levels
        assert (f"{DAY} 12:30:00", "高") in levels
        assert label["敏感等级"] == "高"


class TestDownloadDedup:

    def test_same_operator_multi_columns_same_time_is_one_download(self):
        audit, classification, _ = _fresh()
        _setup_classification(classification)

        first = audit.record_download(
            "周审计", "salary_month", f"{DAY} 09:05:00", columns=["emp_id"])
        second = audit.record_download(
            "周审计", "salary_month", f"{DAY} 09:05:00", columns=["salary_amt"])

        salary_logs = [
            r for r in store_mod.store.rows("operation_log")
            if r["目标资产"] == "salary_month" and r["操作人"] == "周审计"
        ]
        assert len(salary_logs) == 1
        assert second["id"] == first["id"]
        assert second["dedup_merged"] is True
        assert second["访问列"] == ["emp_id", "salary_amt"]

    def test_access_sequence_is_monotonic_and_stable(self):
        audit, classification, _ = _fresh()
        _setup_classification(classification)
        r1 = audit.record_download("周审计", "salary_month", f"{DAY} 09:05:00",
                                   columns=["salary_amt"])
        r2 = audit.record_download("周审计", "shop_total", f"{DAY} 10:20:00",
                                   columns=["sales_amt"])
        r3 = audit.record_download("周审计", "salary_month", f"{DAY} 11:40:00",
                                   columns=["salary_amt"])
        assert r1["访问序号"] < r2["访问序号"] < r3["访问序号"]
        # 历史分级结论按访问序号引用，重复读取不会重新编号。
        assert store_mod.store.find("operation_log", r1["id"])["访问序号"] == r1["访问序号"]


class TestTraceSession:

    def _seed_visits(self, audit: AuditTraceService) -> None:
        # 同一人交替访问普通表和高敏表（salary_amt 午间才转高敏）。
        audit.record_download("周审计", "salary_month", f"{DAY} 09:05:00",
                              columns=["emp_id", "salary_amt"])
        audit.record_download("周审计", "shop_total", f"{DAY} 10:20:00",
                              columns=["shop_id", "sales_amt"])
        audit.record_download("周审计", "salary_month", f"{DAY} 11:40:00",
                              columns=["salary_amt"])
        audit.record_download("周审计", "salary_month", f"{DAY} 14:10:00",
                              columns=["salary_amt", "emp_id"])
        audit.record_download("周审计", "shop_total", f"{DAY} 15:00:00",
                              columns=["sales_amt"])
        audit.record_download("周审计", "salary_month", f"{DAY} 16:30:00",
                              columns=["salary_amt"])
        # 干扰项1：其他人下载薪资表，不得凭同资产混入。
        audit.record_download("王审计", "salary_month", f"{DAY} 13:30:00",
                              columns=["salary_amt"])
        # 干扰项2：同人对商店统计表的读取，不得凭人员同名混入薪资追溯。
        audit.record_download("周审计", "shop_total", f"{DAY} 17:30:00",
                              columns=["shop_id"])

    def test_trace_hits_follow_point_in_time_basis(self):
        audit, classification, _ = _fresh()
        _setup_classification(classification)
        self._seed_visits(audit)

        opened = audit.open_trace(
            "周审计", "salary_month",
            f"{DAY} 08:00:00", f"{DAY} 18:00:00", page=1, size=20)
        trace_id = opened["entry"]["id"]
        result = audit.get_trace_hits(trace_id)

        # 候选只含 (周审计, salary_month) 的 4 笔；同名商店表读取与其他人的访问被排除。
        assert result["frozen_candidate_count"] == 4
        assert result["total"] == 2
        hit_times = [item["操作时间"] for item in result["items"]]
        assert hit_times == [f"{DAY} 14:10:00", f"{DAY} 16:30:00"]

        for hit in result["items"]:
            assert hit["命中"] is True
            basis = hit["分级依据"]
            assert basis and all(b["时点敏感等级"] == "高" for b in basis)
            assert all(b["分级生效时间"] == f"{DAY} 12:30:00" for b in basis)
            assert all(b["依据"].startswith("字段salary_month.salary_amt") for b in basis)

        # 上午两笔未命中：发生时 salary_amt 仍为中敏，逐笔留有时点分级说明。
        candidates = [
            audit._build_hit(r) for r in store_mod.store.rows("operation_log")
            if r["操作人"] == "周审计" and r["目标资产"] == "salary_month"
        ]
        morning = [c for c in candidates if c["操作时间"] < f"{DAY} 12:30:00"]
        assert all(not c["命中"] for c in morning)
        assert all(
            f["时点敏感等级"] == "中"
            for c in morning for f in c["字段时点分级"] if f["字段"] == "salary_amt"
        )

    def test_shop_table_trace_never_mixed_in(self):
        audit, classification, _ = _fresh()
        _setup_classification(classification)
        self._seed_visits(audit)

        opened = audit.open_trace(
            "周审计", "shop_total",
            f"{DAY} 08:00:00", f"{DAY} 18:00:00")
        result = audit.get_trace_hits(opened["entry"]["id"])
        assert result["frozen_candidate_count"] == 3
        assert result["total"] == 0
        assert result["items"] == []

    def test_supplement_keeps_original_pagination_boundary(self):
        audit, classification, _ = _fresh()
        _setup_classification(classification)
        self._seed_visits(audit)

        opened = audit.open_trace(
            "周审计", "salary_month",
            f"{DAY} 08:00:00", f"{DAY} 18:00:00", page=1, size=1)
        trace_id = opened["entry"]["id"]

        page1 = audit.get_trace_hits(trace_id, page=1, size=1)
        assert page1["total"] == 2
        assert len(page1["items"]) == 1
        first_hit_id = page1["items"][0]["日志id"]
        assert page1["supplement_count"] == 0

        # 查询期间补报一笔本应落在时间窗内、且按高敏口径会命中的访问。
        audit.record_download("周审计", "salary_month", f"{DAY} 17:00:00",
                              columns=["salary_amt"])

        page1_again = audit.get_trace_hits(trace_id, page=1, size=1)
        # 原分页边界不变：总数、首条命中、候选集快照都保持开启时口径。
        assert page1_again["total"] == 2
        assert page1_again["frozen_candidate_count"] == 4
        assert page1_again["items"][0]["日志id"] == first_hit_id
        assert len(page1_again["items"]) == 1
        # 补报访问单独挂出，不挤占原分页。
        assert page1_again["supplement_count"] == 1
        assert page1_again["supplement_hits"][0]["操作时间"] == f"{DAY} 17:00:00"

        page2 = audit.get_trace_hits(trace_id, page=2, size=1)
        assert len(page2["items"]) == 1
        assert page2["items"][0]["日志id"] != first_hit_id

    def test_scan_todos_match_hits_and_rescan_has_no_duplicates(self):
        audit, classification, compliance = _fresh()
        _setup_classification(classification)
        self._seed_visits(audit)

        opened = audit.open_trace(
            "周审计", "salary_month",
            f"{DAY} 08:00:00", f"{DAY} 18:00:00")
        trace_id = opened["entry"]["id"]
        hits = audit.get_trace_hits(trace_id)["items"]

        scan1 = compliance.scan_audit_trace(trace_id)
        assert scan1["hit_total"] == 2
        assert scan1["new_todos"] == 2
        assert scan1["todo_total"] == 2

        todos = [
            sc for sc in store_mod.store.rows("compliance_scan")
            if sc.get("trace_id") == trace_id
        ]
        # 待办与命中明细一一对应，按访问序号兼容历史分级结论。
        assert {sc["trace_hit_ref"] for sc in todos} == {
            f"{trace_id}:{h['日志id']}" for h in hits
        }
        assert {sc["访问序号"] for sc in todos} == {h["访问序号"] for h in hits}
        assert all(sc["目标资产"] == "salary_month" for sc in todos)
        assert all("高敏字段" in sc["违规发现"] for sc in todos)

        # 重复扫描不产生重复待办，扫描待办始终与命中明细一致。
        scan2 = compliance.scan_audit_trace(trace_id)
        assert scan2["new_todos"] == 0
        assert scan2["todo_total"] == 2
        assert len({sc["trace_hit_ref"] for sc in todos}) == 2

        entry = store_mod.store.find("audit_trace", trace_id)
        assert entry["status"] == "扫描完成"
        assert entry["扫描状态"] == "扫描完成"

    def test_supplement_does_not_enter_existing_scan_todos(self):
        audit, classification, compliance = _fresh()
        _setup_classification(classification)
        self._seed_visits(audit)

        opened = audit.open_trace(
            "周审计", "salary_month",
            f"{DAY} 08:00:00", f"{DAY} 18:00:00")
        trace_id = opened["entry"]["id"]
        compliance.scan_audit_trace(trace_id)

        audit.record_download("周审计", "salary_month", f"{DAY} 17:00:00",
                              columns=["salary_amt"])
        audit.get_trace_hits(trace_id)
        scan = compliance.scan_audit_trace(trace_id)

        # 补报访问不改变冻结命中口径，待办仍只对应原两笔命中。
        assert scan["hit_total"] == 2
        assert scan["todo_total"] == 2
        assert scan["supplement_count"] == 1
