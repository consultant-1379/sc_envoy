import re
from string import Template
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--logfile", required=True, help="Path to the logfile")
parser.add_argument("--svg", required=True, help="Path to the svg file")
parser.add_argument("output", help="Path of the output file")
args = parser.parse_args()

ul_ids = []

with open(args.logfile, "r") as logfile:
    pattern = re.compile(r'ul_id: ([A-Z0-9-]+)')
    for line in logfile.readlines():
        for matched_id in pattern.finditer(line):
            ul_ids.append(matched_id.group(1))

header = '''<html><head>
<style>
'''

css = []

for id in ul_ids:
    css.append(Template('''#$id rect {
  stroke:red !important;
  fill: #ffeeee80 !important;
}
#$id path {
  stroke:red !important;
}
#$id text {
  fill:black !important;
}''').substitute(id=id))
    if 'prev_id' in locals():
        css.append(Template('''#$prev_id---$id rect {
  stroke:red !important;
  fill: #ffeeee80 !important;
}
#$prev_id---$id path {
  stroke:red !important;
}
#$prev_id---$id text {
  fill:black !important;
}''').substitute(prev_id=prev_id, id=id))
    prev_id = id

header_close = '''</style></head>
<body>'''

footer = '''</body>
</html>'''

with open(args.svg, "r") as svg:
    svg_content = svg.read()

with open(args.output, "w") as output:
    output.write(header)
    output.write("\n".join(css))
    output.write("\n")
    output.write(header_close)
    output.write(svg_content)
    output.write(footer)

print ("Done.")