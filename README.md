# mcp-agents

Gateway MCP enxuto e plug-and-play para orquestrar CLIs (`grok`, `codex`, `claude`, `opencode`, `agy`, `gemini`) com handoffs `@PKT` (sem depender de kanban) e retomada de sessão (`session_id`).

## Tools (4)

- `agent_run(cli, prompt, workspace=".", pkt_ref="", session_id="", mode="read", model="", role="", fallback=True)`
  - Use `cli="status"` para listar CLIs disponíveis e cooldowns.
  - `role` carrega perfil de `.mcp-agents/roles.json`, `.claude/agents/<role>.md` ou [roles.json](file:///d:/mcp%20agents/roles.json) e mantém sessão separada por `(cli, role)`.
  - Se `pkt_ref` for passado (`@PKT|...` ou `<id>#<sha8>`), o gateway injeta o handoff e `[DELTA]` de edições recentes.
- `pkt_save(id, touched_files, interface_contracts, handoff_why, handoff_next, workspace=".", op="HND", status="doing", cli="-")`
  - Valida e gera `@PKT|...`, salvando o payload completo em `<workspace>/.mcp-agents/pkt_refs.json`.
- `pkt_get(ref="", workspace=".", limit=15)`
  - Expande um `ref=<id>#<sha8>` ou lista os últimos `@PKT`s quando `ref` está vazio.
- `rtk_run(cmd, workspace=".", timeout=60)`
  - Reescreve comandos (`dotnet test/build`, `git diff`, `grep`, `ls`, `head -n`, cadeias `&& || ;`) para `rtk` e executa no workspace.

## Como plugar

### `.mcp.json` / `mcp_config.json` (Claude Code, Antigravity, Grok, etc.)
```json
{
  "mcpServers": {
    "mcp-agents": {
      "command": "D:\\Pythonn\\python.exe",
      "args": ["d:\\mcp agents\\server.py"]
    }
  }
}
```

### `opencode.json`
```json
{
  "mcp": {
    "mcp-agents": {
      "type": "local",
      "command": ["D:\\Pythonn\\python.exe", "d:\\mcp agents\\server.py"],
      "enabled": true
    }
  }
}
```

## Variáveis de ambiente opcionais
- `MCP_PKT_REFS`: sobrescreve o caminho do `pkt_refs.json`.
- `MCP_CLI_<NOME>`: caminho customizado de uma CLI (ex.: `MCP_CLI_GEMINI`).

## Testes
```powershell
D:\Pythonn\python.exe -m unittest discover -s "d:\mcp agents\tests" -v
```
