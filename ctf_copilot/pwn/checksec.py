from ..shared.tooling import run_tool, which
def show(path):
    if not which('checksec'): raise SystemExit('checksec is not installed.')
    print(run_tool(['checksec','--file='+path],timeout=30,max_output=40000)[1])
