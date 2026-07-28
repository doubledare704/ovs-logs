import json, re

with open(r'C:\Users\milla\.local\share\kilo\tool-output\tool_fa8919f3d001fjUy2KxSYqGHdN') as f:
    comments = json.load(f)

for c in comments:
    body = c['body']
    body = re.sub(r'<[^>]+>', '', body)
    body = re.sub(r'```suggestion.*?```', '', body, flags=re.DOTALL)
    body = re.sub(r'```.*?```', '', body, flags=re.DOTALL)
    body = re.sub(r'<details>.*?</details>', '', body, flags=re.DOTALL)
    body = re.sub(r'\s+', ' ', body).strip()
    print(f'ID: {c["id"]} Author: {c["user"]["login"]}')
    print(f'File: {c["path"]} Lines: {c["start_line"]}-{c["line"]}')
    print(f'Body: {body[:600]}')
    print('---')
