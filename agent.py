import asyncio
import os
import requests
import json
from typing import Any, Dict, List, Optional
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "phi")
OLLAMA_TIMEOUT = float(os.environ.get("OLLAMA_TIMEOUT", "90"))
OLLAMA_TOOL_TIMEOUT = float(os.environ.get("OLLAMA_TOOL_TIMEOUT", "180"))
MAX_HISTORY = int(os.environ.get("AGENT_MAX_HISTORY", "18"))
MCP_MASTER_KEY = os.environ.get("KITTYSPLOIT_MASTER_KEY", "")
MCP_SERVER_PATH = os.environ.get(
    "KITTYMCP_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "kittymcp.py"),
)
http = requests.Session()


def build_system_prompt(tool_lines: str) -> str:
    return f"""Tu es un assistant intelligent.

Outils MCP KittySploit — noms EXACTS (sensible à la casse) :
{tool_lines}

Règles importantes :
- La clé JSON doit s'appeler **tool** (singulier), pas "tools".
- Pour la **liste des modules d'exploitation / scanners** du framework (pas la liste des outils MCP ci-dessus), tu DOIS appeler l'outil **ks_list_modules**. Exemple : {{"tool": "ks_list_modules", "arguments": {{}}}}
- Ne renvoie jamais un JSON qui ne fait que recopier les noms d'outils MCP : ce n'est pas une réponse utile.
- Quand l'utilisateur demande un scan/exploit, enchaîne efficacement: ks_list_modules (si besoin) -> ks_get_module_options -> ks_run_module -> ks_get_module_logs.
- Si possible, propose des commandes prêtes à copier avec des options réalistes (RHOST, RPORT, TARGETURL, THREADS).
- Sois concis, orienté action, et priorise les réponses en français.

Si tu dois appeler un outil, réponds UNIQUEMENT avec un JSON valide, sans markdown ni texte autour :
{{"tool": "nom_exact", "arguments": {{ ... }} }}

Autres exemples : {{"tool": "ks_health", "arguments": {{}}}} — {{"tool": "ks_list_modules", "arguments": {{"query": "http", "limit": 50}}}}

Sinon, réponds en texte normal."""


def trim_messages(messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
    if len(messages) <= MAX_HISTORY + 1:
        return messages
    return [messages[0]] + messages[-MAX_HISTORY:]


def call_llm(messages: List[Dict[str, str]], timeout: Optional[float] = None) -> Dict[str, Any]:
    try:
        response = http.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "messages": messages,
                "stream": False,
            },
            timeout=timeout or OLLAMA_TIMEOUT,
        )
        response.raise_for_status()
    except requests.exceptions.Timeout:
        print(
            f"⚠️ Ollama timeout après {OLLAMA_TIMEOUT}s ({OLLAMA_URL}). "
            "Vérifie qu'Ollama tourne (`ollama serve`) et augmente OLLAMA_TIMEOUT si besoin."
        )
        return {"message": {"content": "[erreur: timeout LLM]"}}
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Erreur HTTP Ollama: {e}")
        return {"message": {"content": "[erreur: LLM indisponible]"}}

    # Ollama renvoie parfois du NDJSON — on prend la dernière ligne valide
    data = None
    for line in reversed(response.text.strip().splitlines()):
        try:
            data = json.loads(line)
            if "message" in data:
                break
        except json.JSONDecodeError:
            continue

    if not data or "message" not in data:
        print("⚠️ Réponse Ollama inattendue:", response.text[:300])
        return {"message": {"content": "[erreur LLM]"}}

    return data


def extract_json_object(content: str):
    """Parse JSON éventuellement dans un bloc ```json ... ```."""
    s = content.strip()
    if s.startswith("```"):
        lines = s.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        s = "\n".join(lines).strip()
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return None


def user_wants_kittysploit_module_list(user_text: str) -> bool:
    t = user_text.lower()
    if "module" not in t and "modules" not in t:
        return False
    return any(
        k in t
        for k in (
            "liste",
            "lister",
            "donner",
            "affiche",
            "montre",
            "tous",
            "quels",
            "enumerate",
        )
    )


def normalize_tool_call(
    data: dict,
    user_text: str,
    tool_names: set,
) -> dict | None:
    """
    Si le modèle renvoie {{"tools": [...]}} au lieu d'un appel, tenter ks_list_modules
    quand la question utilisateur le demande clairement.
    """
    if not isinstance(data, dict):
        return None
    if "tool" in data and isinstance(data.get("tool"), str):
        return data
    if "tools" in data and "tool" not in data:
        if user_wants_kittysploit_module_list(user_text) and "ks_list_modules" in tool_names:
            return {"tool": "ks_list_modules", "arguments": {}}
    return None


def parse_tool_call(content: str, user_input: str, tool_names: set) -> Optional[Dict[str, Any]]:
    data = extract_json_object(content)
    if data is None:
        return None
    fixed = normalize_tool_call(data, user_input, tool_names)
    data = fixed or data
    if not isinstance(data, dict):
        return None
    if not isinstance(data.get("tool"), str):
        return None
    if data["tool"] not in tool_names:
        return None
    args = data.get("arguments", {})
    if not isinstance(args, dict):
        return None
    return {"tool": data["tool"], "arguments": args}


def is_local_command(text: str) -> bool:
    return text.strip().lower() in {"/help", "/tools", "/reset", "/exit", "/quit"}


def show_help() -> None:
    print("Commandes locales: /help, /tools, /reset, /exit")
    print("Astuce scan: demande directe ex: 'lance un scan wordpress sur 10.10.10.10'")


async def main():
    if not MCP_MASTER_KEY:
        print("⚠️ KITTYSPLOIT_MASTER_KEY absent. Définis-le dans l'environnement.")
    if not os.path.exists(MCP_SERVER_PATH):
        print(f"⚠️ Serveur MCP introuvable: {MCP_SERVER_PATH}")
        return

    server_args = [MCP_SERVER_PATH]
    if MCP_MASTER_KEY:
        server_args += ["--master-key", MCP_MASTER_KEY]
    server_params = StdioServerParameters(
        command="python3",
        args=server_args,
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools_result = await session.list_tools()
            tools = tools_result.tools
            tool_names = {t.name for t in tools}
            tool_lines = "\n".join(
                f"- {t.name}: {t.description or ''}".strip() for t in tools
            )
            print("🔧 Tools available:", sorted(tool_names))

            messages = [{"role": "system", "content": build_system_prompt(tool_lines)}]

            while True:
                try:
                    user_input = await asyncio.to_thread(input, "🧑 > ")
                except (EOFError, KeyboardInterrupt):
                    print("\n👋 Arrêt de l'agent.")
                    break
                if not user_input.strip():
                    continue
                if is_local_command(user_input):
                    cmd = user_input.strip().lower()
                    if cmd in {"/exit", "/quit"}:
                        print("👋 Arrêt de l'agent.")
                        break
                    if cmd == "/reset":
                        messages = [{"role": "system", "content": build_system_prompt(tool_lines)}]
                        print("♻️ Contexte réinitialisé.")
                    elif cmd == "/tools":
                        print("🔧", sorted(tool_names))
                    else:
                        show_help()
                    continue

                messages.append({"role": "user", "content": user_input})
                messages = trim_messages(messages)

                response = call_llm(messages, timeout=OLLAMA_TIMEOUT)
                content = response.get("message", {}).get("content", "").strip()
                if not content:
                    print("⚠️ Réponse vide du LLM, nouvelle tentative...")
                    response = call_llm(messages, timeout=OLLAMA_TIMEOUT)
                    content = response.get("message", {}).get("content", "").strip()
                if not content:
                    print("🤖 > Désolé, je n'ai pas reçu de réponse exploitable.")
                    continue

                data = parse_tool_call(content, user_input, tool_names)
                if data:
                    name = data["tool"]
                    print("⚙️ Appel tool:", name)
                    try:
                        result = await session.call_tool(name, data["arguments"])
                    except Exception as e:
                        print("⚠️ Échec appel MCP:", e)
                        messages.append({"role": "assistant", "content": content})
                        messages.append({"role": "user", "content": f"[erreur outil {name}] {e}"})
                        messages = trim_messages(messages)
                        continue
                    tool_payload = [r.model_dump() for r in result.content]
                    tool_output = json.dumps(tool_payload, ensure_ascii=False)
                    if len(tool_output) > 12000:
                        tool_output = tool_output[:12000] + "... [truncated]"
                    messages.append({"role": "assistant", "content": content})
                    messages.append({"role": "tool", "content": tool_output})
                    messages = trim_messages(messages)

                    response2 = call_llm(messages, timeout=OLLAMA_TOOL_TIMEOUT)
                    final = response2.get("message", {}).get("content", "").strip()
                    if not final:
                        final = "Le module a été exécuté, mais je n'ai pas pu formuler de synthèse."
                    print("🤖 >", final)
                    messages.append({"role": "assistant", "content": final})
                    messages = trim_messages(messages)
                    continue

                print("🤖 >", content)
                messages.append({"role": "assistant", "content": content})
                messages = trim_messages(messages)

if __name__ == "__main__":
    asyncio.run(main())
