with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

target = "from redteam_benchmark import RedTeamBenchmark"
replacement = "from redteam_benchmark import RedTeamBenchmark, BenchmarkRunSummary"

if target not in content and target.replace('\n', '\r\n') in content:
    target = target.replace('\n', '\r\n')
    replacement = replacement.replace('\n', '\r\n')

assert target in content, "target not found"
content = content.replace(target, replacement, 1)

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Added BenchmarkRunSummary import to app.py")
