# mcp-token-killer

Gateway MCP enxuto para orquestrar múltiplas CLIs de agentes (`grok`, `codex`, `claude`, `opencode`, `gemini`, `agy`) com handoffs estruturados **`@PKT`** (Zero Context Loss), `RepoMap` just-in-time e execução compactada via `rtk`.

> A história completa de design, auditorias Red Team e benchmarks do protocolo está em [`docs/HISTORIA_PKT.md`](docs/HISTORIA_PKT.md).

---

## O problema que o `@PKT` resolve

Em fluxos multi-agente, handoffs em prosa (*"editei a classe X, tive um erro na linha 40, fiz um fallback..."*) causam três falhas:
1. **Acúmulo de ruído:** históricos narrativos saturam o contexto a cada troca de agente.
2. **Ambiguidade de contrato:** prosa omite tipos e assinaturas reais; o próximo agente adivinha ou reescreve.
3. **Alucinação de escopo:** pedir ao LLM para listar o que alterou mistura intenção com fato.

### Invariante central
**O pacote carrega fatos extraídos do Git, não a opinião do modelo — e toda perda ou aproximação é visível.**

```text
@PKT|TASK-12|doing|codex|[CODE,API,PUB]|op=HND|f=pkt_core.py,server.py|api=pkt_core.py: `def build_pkt_from_git(task_id: str)`|why=Extrair f= e api= do git|nxt=Rodar suite de testes
```

- **`f=` (`touched_files`):** extraído de `git diff --name-only <base_commit>` + arquivos novos/modificados no worktree (nunca preenchido pelo LLM).
- **`api=` (`interface_contracts`):** assinaturas públicas extraídas das linhas `+` de `git diff -U0` via `CONTRACT_SIG_RE` (GDScript, Python, C#, TypeScript/JS, Rust), ignorando identificadores privados com `_`.
- **`base_commit` no claim (herdado em failover):** gravado em `.mcp-agents/tasks.json` no início do trabalho em `mode="work"` (ou `pkt_save(..., claim=True)`) e preservado se outro agente assumir depois.
- **`PARTIAL_DIFF` e `(?)`:** se não houver `base_commit` validado (ex.: rebase/squash ou execução sem claim prévio), o pacote acende `[PARTIAL_DIFF]` e anexa `,(?)` em `api=` para sinalizar que o diff é heurístico.
- **Truncamento recuperável (`ref=<id>#<sha8>`):** `f=` mostra até 4 arquivos (`+(N)`), `api=` até 3 contratos (`+(N)`), `why=` até 90 chars e `nxt=` até 140 chars (`...(+Nc)...`). **Somente quando há truncamento**, o payload integral é salvo atomicamente em `.mcp-agents/pkt_refs.json` e o pacote recebe `|ref=<id>#<sha8>` (expansível sob demanda via `pkt_get`).
- **JIT `[REPOMAP]` & `[DELTA]`:** no despacho de `agent_run`, o gateway injeta o esqueleto `L<n>:` dos arquivos tocados existentes (ignorando *ghost files* deletados) e os hunks `@@ ... @@` editados recentemente por outros agentes.

---

## Tools expostas (4)

- `agent_run(cli, prompt, workspace=".", pkt_ref="", session_id="", mode="read", model="", role="", task_id="", fallback=True)`
  - Orquestra `grok`, `codex`, `claude`, `gemini`, `opencode` ou `agy` (ou `cli="status"` para listar disponibilidade/cooldowns).
  - Em `mode="work"`, fixa `base_commit` no primeiro claim, detecta arquivos alterados por hash de conteúdo (incluindo arquivos já sujos editados novamente) e devolve `"pkt"` gerado direto do Git.
- `pkt_save(id, handoff_why="", handoff_next="", workspace=".", op="HND", status="doing", cli="-", qa_status="", claim=False)`
  - Gera um `@PKT` combinando `f=` e `api=` extraídos do Git com o `why` e `nxt` informados. Passe `claim=True` antes de iniciar edições manuais para fixar o `base_commit`.
- `pkt_get(ref="", workspace=".", limit=15)`
  - Expande o payload integral de um `ref=<id>#<sha8>` ou lista refs recentes quando `ref` está vazio.
- `rtk_run(cmd, workspace=".", timeout=60)`
  - Reescreve comandos (`dotnet build/test`, `git diff`, `grep`, `ls`, `head -n`, cadeias `&& || ;`) para `rtk` e retorna saída compactada.

---

## Modelo de segurança

- **Sem escalonamento de permissão por role:** um `role` nunca promove `mode="read"` para `"work"` (flags como `--always-approve`, `--dangerously-skip-permissions`, `--yolo` só entram quando `mode="work"` é pedido explicitamente na chamada).
- **Fallback restrito a rate limit:** o failover entre CLIs só dispara em erros reais de cota/rate-limit (`429`, `quota`, `overloaded`), nunca em falhas normais de execução ou timeout, e marca `[DELEG]` no `@PKT`.
- **Workspace hooks e roles desativados por padrão:** arquivos de repositórios de terceiros (`.mcp-agents/prompt_hook.py`, `.mcp-agents/roles.json`, `.claude/agents/*.md`) **não** são carregados nem executados a menos que você habilite explicitamente via variável de ambiente.
- **Anti-loop em 3 camadas:** limite rígido de profundidade (`MCP_AGENTS_MAX_DEPTH`, padrão `2`), bloqueio de ciclo no grafo (`MCP_AGENTS_CHAIN`, ex.: `grok:architect > grok:coder` permitido, retorno a `grok:architect` bloqueado) e circuit breaker para chamadas repetidas.

---

## Instalação

Requisitos: Python 3.10+ e `mcp` 2.x.

```bash
pip install -r requirements.txt
python install.py
```

O `install.py` registra o servidor globalmente nas CLIs instaladas (`grok`, `codex`, `claude`, `opencode`) usando o `python` do ambiente atual.

### Configuração manual (`.mcp.json` / `mcp_config.json`)

```json
{
  "mcpServers": {
    "mcp-token-killer": {
      "command": "python",
      "args": ["/caminho/para/mcp-token-killer/server.py"]
    }
  }
}
```

### Variáveis de ambiente opcionais

| Variável | Efeito |
|---|---|
| `MCP_PKT_REFS` | Caminho customizado para `pkt_refs.json` |
| `MCP_CLI_<NOME>` | Binário customizado para uma CLI (ex.: `MCP_CLI_GEMINI`) |
| `MCP_AGENTS_MAX_DEPTH` | Profundidade máxima de delegação entre agentes (padrão: `2`) |
| `MCP_ALLOW_WORKSPACE_ROLES=1` | Permite carregar `.mcp-agents/roles.json` e `.claude/agents/*.md` do workspace |
| `MCP_ALLOW_WORKSPACE_HOOKS=1` | Permite executar `.mcp-agents/prompt_hook.py` do workspace |

---

## Testes

```bash
python -m unittest discover -s tests -v
```

## Licença

[MIT](LICENSE)
