from ..shared.tooling import run_tool, which
def show(path):
    if not which('ROPgadget'): raise SystemExit('ROPgadget is not installed.')
    print(run_tool(['ROPgadget','--binary',path,'--only','pop|ret|leave'],timeout=45,max_output=80000)[1])
