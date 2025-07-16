import os
import re
import requests
from flask import Flask, request
from langchain.llms import Ollama
from unidiff import PatchSet
from io import StringIO

# Initialize Flask app and Ollama model
GITHUB_TOKEN = ""  # Replace with env var in production
app = Flask(__name__)
llm = Ollama(model="tinyllama")  # Use "llama3" or "mistral" if available for better accuracy

# Regex-based heuristic scan for common secrets
def contains_sensitive_keywords(text):
    patterns = [
        r'(?i)(password|secret|token|access_token|api_key)[\'"\s:=]+[a-zA-Z0-9_\-.$#]+'
    ]
    for pattern in patterns:
        if re.search(pattern, text):
            return True
    return False

@app.route('/github-webhook', methods=['POST'])
def github_webhook():
    data = request.json

    # Get repository and commits info
    repo = data['repository']['full_name']
    commits = data.get('commits', [])

    for commit in commits:
        diff_url = commit['url']
        author = commit['author']['name']
        sha = commit['id']

        # Fetch the raw diff
        diff_response = requests.get(f"{diff_url}.diff", headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}"
        })
        diff_text = diff_response.text

        # Parse and print diff file/line info
        patch = PatchSet(StringIO(diff_text))
        filewise_diff = ""

        print(f"\n--- Files and Changes in Commit {sha[:7]} by {author} ---")
        for patched_file in patch:
            filename = patched_file.path
            print(f"Changed file: {filename}")
            filewise_diff += f"\n### File: {filename}\n"
            for hunk in patched_file:
                for line in hunk:
                    if line.is_added or line.is_removed:
                        symbol = '+' if line.is_added else '-'
                        filewise_diff += f"{symbol} {line.value}"
                        print(f"{symbol} {line.value.strip()}")
        print("----------------------------------------------------------\n")

        # Heuristic scan before LLM
        if contains_sensitive_keywords(diff_text):
            print("⚠️ Heuristic scan detected possible secrets in the diff.")

        # Build prompt for LLM
        prompt = f"""
You are a security agent reviewing a Git commit.

Below is the file-wise diff of the commit. Look for secrets like passwords, API keys, tokens, or private keys.


If anything looks risky, classify the risk as High / Medium / Low / None.
- Mention the filename(s)
- Explain why
- Suggest a remediation
"""

        # Get LLM analysis
        result = llm(prompt)
        print(f"---\nAnalysis for commit {sha} by {author}:\n{result}\n---")

        # Create GitHub issue if risky
        if "high" in result.lower() or "medium" in result.lower():
            create_github_issue(repo, sha, author, result)

    return {"status": "processed"}

# GitHub issue creation function
def create_github_issue(repo, sha, author, analysis):
    url = f"https://api.github.com/repos/{repo}/issues"
    title = f"⚠️ Sensitive Data Detected in Commit {sha[:7]}"
    body = f"**Author**: {author}\n\n**Analysis**:\n```\n{analysis}\n```\nPlease review immediately."

    response = requests.post(url, headers={
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }, json={
        "title": title,
        "body": body,
    })

    if response.status_code == 201:
        print(f"Issue created: {response.json().get('html_url')}")
    else:
        print(f"Issue creation failed: {response.text}")

if __name__ == '__main__':
    app.run(port=5000)
