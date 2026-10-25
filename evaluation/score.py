"""Score agent reports against evaluation/ground_truth.json.

Usage: python evaluation/score.py <reports-dir>
where <reports-dir> contains scenario_a.json ... scenario_e.json produced by agent.py.

Each reported violation is matched to at most one ground-truth entry (rule_id in the entry's accepted rules,
file in the accepted files if given, line within +/-2 if given). Unmatched reports count as false positives.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

GT = json.loads((Path(__file__).parent / "ground_truth.json").read_text())


def _matches(v: dict, gt: dict) -> bool:
    if v["rule_id"] not in gt["rules"]:
        return False
    if "files" in gt and v["file"] not in gt["files"]:
        return False
    if "line" in gt and v["line"] is not None and abs(v["line"] - gt["line"]) > 2:
        return False
    return True


def score(reports_dir: Path) -> int:
    total_tp = total_rep = total_req = total_hit = 0
    for scenario, truth in GT.items():
        if scenario.startswith("_"):
            continue
        path = reports_dir / f"{scenario}.json"
        if not path.exists():
            print(f"{scenario}: report missing ({path})")
            continue
        reported = json.loads(path.read_text())["violations"]
        unmatched_truth = list(truth)
        correct, false_pos = [], []
        for v in reported:
            hit = next((g for g in unmatched_truth if _matches(v, g)), None)
            if hit:
                unmatched_truth.remove(hit)
                correct.append((v, hit))
            else:
                false_pos.append(v)
        required = [g for g in truth if not g.get("optional")]
        found_required = [g for _, g in correct if not g.get("optional")]
        missed = [g for g in unmatched_truth if not g.get("optional")]
        precision = len(correct) / len(reported) if reported else 1.0
        recall = len(found_required) / len(required) if required else 1.0
        print(f"\n{scenario}: reported={len(reported)} correct={len(correct)} "
              f"required_found={len(found_required)}/{len(required)} precision={precision:.2f} recall={recall:.2f}")
        for g in missed:
            print(f"  MISSED {g['id']}: {g['desc']}")
        for v in false_pos:
            print(f"  UNMATCHED {v['rule_id']} {v['file']}:{v['line']} - {v['description']}")
        total_tp += len(correct)
        total_rep += len(reported)
        total_req += len(required)
        total_hit += len(found_required)
    if total_rep or total_req:
        print(f"\nOVERALL precision={total_tp / max(total_rep, 1):.2f} ({total_tp}/{total_rep}) "
              f"recall={total_hit / max(total_req, 1):.2f} ({total_hit}/{total_req})")
    return 0


if __name__ == "__main__":
    sys.exit(score(Path(sys.argv[1] if len(sys.argv) > 1 else "eval_reports")))
