"""CLI runner for GuardX Groq Demo Agent.

Usage:
    python -m examples.groq_agent.cli "Inspect this workspace and summarize findings."
"""

import sys
from examples.groq_agent.agent import GroqAgent, load_project_groq_api_key


def main():
    prompt = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "Inspect the workspace. Determine how the application is configured. Read files as necessary and summarize your findings."
    )

    api_key = load_project_groq_api_key()
    if not api_key:
        print("[GuardX Groq Agent] ERROR: GROQ_API_KEY is not set.")
        print("Please add GROQ_API_KEY=your_key to /Users/neerajkahal/Documents/Tool/.env")
        sys.exit(1)

    print("=" * 70)
    print(" GuardX Groq Demo Agent — Controlled Runtime Investigation")
    print("=" * 70)
    print(f"[*] Prompt: {prompt}")
    print("[*] Session: groq_agent_live_session (Viewable in GuardX Console)")
    print("[*] Executing agent loop...")

    try:
        agent = GroqAgent()
        result = agent.run(prompt)
        print("-" * 70)
        print(f"[+] Task Completed in {result['rounds']} rounds!")
        print(f"[+] Total Events Recorded: {result['event_count']}")
        print(f"[+] Final Agent Response:\n\n{result['final_answer']}\n")
        print("=" * 70)
        print("Open http://127.0.0.1:8080 to inspect the complete Provenance DAG!")
        print("=" * 70)
    except Exception as e:
        print(f"[-] Execution error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
