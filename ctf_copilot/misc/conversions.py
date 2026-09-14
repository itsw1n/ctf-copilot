def convert(value,from_base,to_base): return format(int(value,from_base),{2:'b',8:'o',10:'d',16:'x'}[to_base])
