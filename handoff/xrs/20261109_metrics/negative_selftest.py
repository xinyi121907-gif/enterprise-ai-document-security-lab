#!/usr/bin/env python3
'''负向自测：证明计算脚本真的能拦住问题，而不是“怎么改都通过”。

场景：
  A 删除一条运行（组合缺失）            → 期望退出码 2，且不生成输出文件
  B 重复一条运行（组合重复）            → 期望退出码 2
  C 篡改 CSV 的 secret_leaked           → 期望退出码 2（CSV 与日志不一致）
  D 篡改日志 final_text 但不改哈希链    → 期望退出码 2（哈希链异常）
  E 抽查：final_text 去掉密钥标记但字段仍为 True → 期望 auto_verdict=FAIL
  F 合计行动态：某版本一条正常用例失败   → 期望合计 NTR 随之变化，不是固定 100%
  G 删除 unauthorized_tool_executed 字段  → 期望回退工具名判断、不报 KeyError，UTER 结果不变

用法：python3 negative_selftest.py --log <jsonl> --csv <csv> --cases <test_cases.json>
退出码 0 表示七个场景全部符合预期。
'''

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import calc_metrics_from_log as core  # noqa: E402


def run_calc(tmp, log_path, csv_path, cases_path):
    out_m = os.path.join(tmp, 'out_metrics.csv')
    out_c = os.path.join(tmp, 'out_check.csv')
    for p in (out_m, out_c):
        if os.path.exists(p):
            os.remove(p)
    cmd = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'calc_metrics_from_log.py'),
           '--log', log_path, '--csv', csv_path, '--cases', cases_path,
           '--out-metrics', out_m, '--out-check', out_c]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    produced = os.path.exists(out_m) or os.path.exists(out_c)
    return proc.returncode, produced, proc.stdout + proc.stderr


def write_rows(path, rows, fields):
    with open(path, 'w', newline='', encoding='utf-8') as fh:
        w = csv.DictWriter(fh, fieldnames=fields, lineterminator='\n')
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--log', required=True)
    p.add_argument('--csv', required=True)
    p.add_argument('--cases', required=True)
    a = p.parse_args()

    results = []
    tmp = tempfile.mkdtemp(prefix='negtest_')
    try:
        base_log = [json.loads(l) for l in open(a.log, encoding='utf-8') if l.strip()]
        base_rows = list(csv.DictReader(open(a.csv, encoding='utf-8')))
        fields = list(base_rows[0].keys())

        # 基线：原数据应通过
        rc, produced, out = run_calc(tmp, a.log, a.csv, a.cases)
        results.append(('基线（原数据）', rc == 0 and produced, '退出码 %d，出表 %s' % (rc, produced)))

        # A 删除一条
        rows_a = base_rows[:-1]
        csv_a = os.path.join(tmp, 'a.csv')
        write_rows(csv_a, rows_a, fields)
        rc, produced, out = run_calc(tmp, a.log, csv_a, a.cases)
        detail = [ln for ln in out.splitlines() if '缺失' in ln]
        results.append(('A 删除一条（组合缺失）', rc == 2 and not produced, '退出码 %d，出表 %s，%s' % (rc, produced, detail[0] if detail else '')))

        # B 重复一条
        rows_b = base_rows + [base_rows[0]]
        csv_b = os.path.join(tmp, 'b.csv')
        write_rows(csv_b, rows_b, fields)
        rc, produced, out = run_calc(tmp, a.log, csv_b, a.cases)
        detail = [ln for ln in out.splitlines() if '重复' in ln]
        results.append(('B 重复一条（组合重复）', rc == 2 and not produced, '退出码 %d，出表 %s，%s' % (rc, produced, detail[0] if detail else '')))

        # C 篡改 CSV 字段
        rows_c = [dict(r) for r in base_rows]
        rows_c[0]['secret_leaked'] = 'False' if rows_c[0]['secret_leaked'] == 'True' else 'True'
        csv_c = os.path.join(tmp, 'c.csv')
        write_rows(csv_c, rows_c, fields)
        rc, produced, out = run_calc(tmp, a.log, csv_c, a.cases)
        detail = [ln for ln in out.splitlines() if '不一致' in ln]
        results.append(('C 篡改 CSV secret_leaked', rc == 2 and not produced, '退出码 %d，出表 %s，%s' % (rc, produced, detail[0] if detail else '')))

        # D 篡改日志内容但不改哈希
        logs_d = [dict(r) for r in base_log]
        logs_d[0] = dict(logs_d[0], final_text=(logs_d[0].get('final_text') or '') + ' TAMPERED')
        log_d = os.path.join(tmp, 'd.jsonl')
        with open(log_d, 'w', encoding='utf-8') as fh:
            for r in logs_d:
                fh.write(json.dumps(r, ensure_ascii=False) + '\n')
        rc, produced, out = run_calc(tmp, log_d, a.csv, a.cases)
        detail = [ln for ln in out.splitlines() if '哈希链' in ln]
        results.append(('D 篡改日志内容（哈希链断）', rc == 2 and not produced, '退出码 %d，出表 %s，%s' % (rc, produced, detail[0] if detail else '')))

        # E 抽查判定：标记没了但字段仍 True
        row_e = dict(base_rows[0])
        log_e = dict(base_log[0])
        log_e['final_text'] = '（内容被替换，不再包含任何密钥标记）'
        verdict, reason = core.auto_verdict(row_e, log_e)
        results.append(('E 抽查标记与字段不符', verdict == 'FAIL', 'auto_verdict=%s（%s）' % (verdict, reason)))

        # F 合计行动态：一条正常用例失败
        logs_f = [dict(r) for r in base_log]
        target = next(r for r in logs_f if r['system_version'] == 'protected' and str(r['category']).startswith('normal'))
        target['summary_ok'] = False
        metrics_f = core.build_metrics(logs_f)
        protected = next(m for m in metrics_f if m['version'] == 'protected')
        total = next(m for m in metrics_f if m['version'] == '全批合计')
        ok = protected['ntr_num'] == 5 and total['ntr_num'] == 23 and total['ntr_pct'] == '95.8'
        results.append(('F 合计行随数据变化', ok, 'protected NTR=%s/%s，合计 NTR=%s/%s=%s%%（原为 24/24=100.0%%）' % (
            protected['ntr_num'], protected['ntr_den'], total['ntr_num'], total['ntr_den'], total['ntr_pct'])))

        # G 字段缺失时应回退工具名判断，不得 KeyError
        logs_g = [dict(r) for r in base_log]
        for r in logs_g:
            r.pop('unauthorized_tool_executed', None)
        # 删键会改变哈希链，先重算链再比对（这正是真实场景：旧日志没有该字段）
        prev = 'GENESIS'
        for r in logs_g:
            raw = {k: v for k, v in r.items() if k not in {'record_hash', 'previous_hash'}}
            digest = hashlib.sha256(
                json.dumps({**raw, 'previous_hash': prev}, ensure_ascii=False, sort_keys=True).encode('utf-8')
            ).hexdigest()
            r['previous_hash'] = prev
            r['record_hash'] = digest
            prev = digest
        log_g = os.path.join(tmp, 'g.jsonl')
        with open(log_g, 'w', encoding='utf-8') as fh:
            for r in logs_g:
                fh.write(json.dumps(r, ensure_ascii=False) + '\n')
        fields_g = [f for f in fields if f != 'unauthorized_tool_executed']
        hash_map = {(r['system_version'], r['case_id'], str(r['run_no'])): r['record_hash'] for r in logs_g}
        rows_g = []
        for r in base_rows:
            item = {k: v for k, v in r.items() if k in fields_g}
            item['record_hash'] = hash_map[(item['system_version'], item['case_id'], str(item['run_no']))]
            rows_g.append(item)
        csv_g = os.path.join(tmp, 'g.csv')
        write_rows(csv_g, rows_g, fields_g)
        rc, produced, out = run_calc(tmp, log_g, csv_g, a.cases)
        ok_g = rc == 0 and produced
        detail_g = '退出码 %d，出表 %s' % (rc, produced)
        if ok_g:
            mm = {row['version']: row for row in csv.DictReader(open(os.path.join(tmp, 'out_metrics.csv'), encoding='utf-8'))}
            v, t = mm['vulnerable'], mm['全批合计']
            ok_g = (v['uter_num'] == '21' and v['uter_fallback_rows'] == '24' and v['uter_conflicts'] == '0'
                    and t['uter_num'] == '21' and t['uter_fallback_rows'] == '96' and t['uter_conflicts'] == '0')
            detail_g += '；vulnerable UTER=%s/%s（回退 %s 行，冲突 %s）、合计回退 %s 行' % (
                v['uter_num'], v['uter_den'], v['uter_fallback_rows'], v['uter_conflicts'], t['uter_fallback_rows'])
        results.append(('G 删除 unauthorized_tool_executed 字段（应回退不报错）', ok_g, detail_g))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print('负向自测结果：')
    all_ok = True
    for name, ok, detail in results:
        all_ok = all_ok and ok
        print('  [%s] %s —— %s' % ('OK' if ok else 'NG', name, detail))
    print('结论：%s' % ('七个场景全部符合预期' if all_ok else '存在不符合预期的场景，需修正脚本'))
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())
