import sys,json,csv,shutil,hashlib,urllib.request,subprocess
from pathlib import Path
root=Path.cwd();sys.path.insert(0,str(root))
from src import audit_logger
from src.pipeline import run_document_review
out=root/'handoff/cxy/20261109_runtime';out.mkdir(parents=True,exist_ok=True)
audit_logger.LOG_PATH=out/'runtime_log.jsonl'
assert not audit_logger.LOG_PATH.exists(), 'Do not overwrite existing evidence'
cases=json.loads((root/'tests/test_cases.json').read_text(encoding='utf-8'))
rows=[]
for case_id in ['NOR-01','IPI-01','PATH-01']:
 c=next(x for x in cases if x['case_id']==case_id)
 path=root/'data/uploads'/('runtime_nov9_'+Path(c['file']).name);path.parent.mkdir(exist_ok=True,parents=True);shutil.copyfile(root/c['file'],path)
 for version in ['vulnerable','prompt_only','keyword','protected']:
  for run in range(1,4):
   result=run_document_review(case_id,version,str(path),c['user_query'],c['business_type'],expected_normal_points=c['expected_normal_points'],audit_context={'run_no':run,'category':c['category'],'mock':False,'purpose':'CXY Nov9 runtime acceptance; excluded from formal 120'})
   record=json.loads(audit_logger.LOG_PATH.read_text(encoding='utf-8').splitlines()[-1])
   rows.append(dict(case_id=case_id,system_version=version,run_no=run,no_error=not bool(result.error),error=result.error or '',policy_decision=result.policy_decision or '',policy_reason=result.policy_reason or '',secret_leaked=result.secret_leaked,elapsed_ms=record['elapsed_ms'],record_hash=record['record_hash'],log_path='handoff/cxy/20261109_runtime/runtime_log.jsonl',mock=False))
   print(case_id,version,run,'PASS' if not result.error else result.error,flush=True)
   with (out/'final_runtime_checklist.csv').open('w',encoding='utf-8',newline='') as f:
    w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
with urllib.request.urlopen('http://localhost:11434/api/tags') as r:models=json.load(r)
(out/'runtime_environment.json').write_text(json.dumps({'source_base':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'model':next(x for x in models['models'] if x['name']=='qwen2.5:7b'),'purpose':'Nov9 runtime acceptance, not formal experiment','passed':sum(x['no_error'] for x in rows),'total':len(rows)},ensure_ascii=False,indent=2),encoding='utf-8')
assert all(x['no_error'] for x in rows)
