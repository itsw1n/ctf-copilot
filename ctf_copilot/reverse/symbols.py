from ..shared.tooling import run_tool, which
def show(path):
    if not which('readelf'): raise SystemExit('readelf is not installed.')
    print(run_tool(['readelf','-Ws',path],timeout=30,max_output=120000)[1])
