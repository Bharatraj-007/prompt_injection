with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

target = "import logging\nfrom guard import PromptGuardPipeline"
replacement = "import logging\nfrom typing import Optional, Dict, Any, List\nfrom guard import PromptGuardPipeline"

if target not in content and target.replace('\n', '\r\n') in content:
    target = target.replace('\n', '\r\n')
    replacement = replacement.replace('\n', '\r\n')

assert target in content, "target import not found"
content = content.replace(target, replacement, 1)

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Added typing imports to app.py")
