from ..shared.tooling import run_tool, which
def show(path,function=None):
    if not which('objdump'): raise SystemExit('objdump is not installed.')
    argv=['objdump','-d',path]
    if function: argv=['objdump','-d','--disassemble='+function,path]
    print(run_tool(argv,timeout=45,max_output=160000)[1])
