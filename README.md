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
- **`api=` (`interface_contracts`):** declarações públicas cuja assinatura toca uma linha adicionada no diff, extraídas com parser real (tree-sitter, ver [Linguagens suportadas](#linguagens-suportadas)). Assinaturas em várias linhas, métodos de classe e receivers do Go são capturados; mudança só no corpo de uma função não vira contrato.
- **`base_commit` externo (PR de outro agente, ex.: Devin):** `pkt_save(id, base_commit="origin/main")` usa o `merge-base` entre a branch e o alvo, então commits que chegaram ao `main` depois da bifurcação não entram no pacote.
- **`base_commit` no claim (herdado em failover):** gravado em `.mcp-agents/tasks.json` no início do trabalho em `mode="work"` (ou `pkt_save(..., claim=True)`) e preservado se outro agente assumir depois.
- **Escopo cumulativo da tarefa (`task_id`):** o `@PKT` descreve o estado acumulado da **tarefa desde o `claim`** (`base_commit`), e não apenas o delta do último agente. O campo `cli=` identifica quem emitiu o último pacote; para saber o que cada agente alterou isoladamente na última rodada, o gateway injeta linhas `[DELTA] <cli> edited <arquivo>: @@ ... @@`.
- **`PARTIAL_DIFF` e `(?)`:** se não houver `base_commit` validado (ex.: rebase/squash ou execução sem claim prévio), se houver arquivo não commitado fora da janela do `agent_run` ou conflito de lock ativo, o pacote acende `[PARTIAL_DIFF]` e anexa `,(?)` em `api=` para sinalizar que o diff é aproximado.
- **Truncamento recuperável (`ref=<id>#<sha8>`):** `f=` mostra até 4 arquivos (`+(N)`), `api=` até 3 contratos (`+(N)`), `why=` até 90 chars e `nxt=` até 140 chars (`...(+Nc)...`). **Somente quando há truncamento**, o payload integral é salvo atomicamente em `.mcp-agents/pkt_refs.json` e o pacote recebe `|ref=<id>#<sha8>` (expansível sob demanda via `pkt_get`).
- **JIT `[REPOMAP]` & `[DELTA]`:** no despacho de `agent_run`, o gateway injeta o esqueleto `L<n>:` dos arquivos tocados existentes (ignorando *ghost files* deletados) e os hunks `@@ ... @@` editados recentemente por outros agentes.

---

## Tools expostas (4)

- `agent_run(cli, prompt, workspace=".", pkt_ref="", session_id="", mode="read", model="", role="", task_id="", fallback=True)`
  - Orquestra `grok`, `codex`, `claude`, `gemini`, `opencode` ou `agy`, **somente as permitidas e instaladas**. Pedir uma CLI fora da lista ou ausente do `PATH` retorna erro sem executar nada.
  - `cli="status"` lista as CLIs permitidas, se estão instaladas e o cooldown. Com `check_login=True`, manda a cada CLI instalada um prompt mínimo (numa pasta temporária vazia, modo leitura, sem permitir chamadas aninhadas) e reporta `login: ok | auth_error | rate_limited | timeout | error`. Custa uma requisição pequena por CLI.
  - Fallback só acontece por **limite de uso ou login expirado** (a CLI ficou inutilizável, não a tarefa), e só para CLIs permitidas, instaladas e sem falha de login conhecida nos últimos 15 minutos.
  - Em `mode="work"`, fixa `base_commit` no primeiro claim, detecta arquivos alterados por hash de conteúdo (incluindo arquivos já sujos editados novamente) e devolve `"pkt"` gerado direto do Git.
- `pkt_save(id, handoff_why="", handoff_next="", workspace=".", op="HND", status="doing", cli="-", qa_status="", base_commit="", claim=False)`
  - Gera um `@PKT` combinando `f=` e `api=` extraídos do Git com o `why` e `nxt` informados. Passe `claim=True` antes de iniciar edições manuais para fixar o `base_commit`, ou `base_commit="origin/main"` para extrair o pacote de uma branch/PR externo (ex.: Devin, CI).
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

## Linguagens suportadas

A extração de contratos e o `[REPOMAP]` usam tree-sitter. Cada linguagem tem sua regra de visibilidade pública:

| Linguagem | Extensões | Público quando |
|---|---|---|
| Python, GDScript, Ruby | `.py` `.gd` `.rb` | nome não começa com `_` (GDScript: `var` só com `@export`) |
| TypeScript / JavaScript | `.ts` `.tsx` `.js` `.jsx` `.mjs` `.cjs` | declaração exportada; métodos de classe exportada sem `private`/`protected`/`#` |
| Go | `.go` | nome começa com maiúscula (inclui métodos com receiver) |
| Java, C# | `.java` `.cs` | modificador `public`, ou membro de `interface` |
| Kotlin, Swift | `.kt` `.kts` `.swift` | sem `private`/`internal`/`protected` (Swift: sem `private`/`fileprivate`) |
| Rust | `.rs` | `pub` (membros de `trait` herdam) |
| PHP | `.php` | sem `private`/`protected` |
| C / C++ | `.c` `.h` `.cpp` `.cc` `.hpp` | não `static`, nome sem `_` |

Membros (funções, métodos, propriedades) vêm antes das declarações de tipo no `api=`, já que o tipo aparece como qualificador: `svc.ts(Svc): \`cancel(id: string): boolean\``.

**Fallback sinalizado:** se a gramática de um arquivo não estiver disponível, a extração cai para a regex antiga só naquele arquivo e o `api=` recebe `(?)`. A lista de arquivos (`f=`) continua exata, então `PARTIAL_DIFF` não acende por isso.

**Gramáticas e rede:** o `tree-sitter-language-pack` baixa cada gramática no primeiro uso e guarda em cache local. Em máquina sem acesso à internet (ou com proxy corporativo), rode antes, numa máquina com rede, `python install.py --grammars` para pré-baixar as gramáticas das linguagens acima. Sem a gramática, o comportamento é o fallback sinalizado, nunca omissão silenciosa.

## Instalação

Requisitos: Python 3.10+, `mcp` 2.x e `tree-sitter-language-pack` (para extração multilinguagem).

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
| `MCP_AGENTS_ALLOWED` | CLIs que o gateway pode usar, na ordem de fallback (ex.: `claude,codex`). Vale para chamada direta e fallback. Sem ela, todas as suportadas |
| `MCP_CLI_<NOME>` | Binário customizado para uma CLI (ex.: `MCP_CLI_GEMINI`) |
| `MCP_AGENTS_MAX_DEPTH` | Profundidade máxima de delegação entre agentes (padrão: `2`) |
| `MCP_ALLOW_WORKSPACE_ROLES=1` | Permite carregar `.mcp-agents/roles.json` e `.claude/agents/*.md` do workspace |
| `MCP_ALLOW_WORKSPACE_HOOKS=1` | Permite executar `.mcp-agents/prompt_hook.py` do workspace |

---

## Benchmark empírico (3 braços × n=5)

Experimento controlado em `claude --model sonnet` sobre um repositório Git limpo com **60 módulos `.gd`** distribuídos em 6 pastas, onde o Agente 1 já commitou `class_name CritEngine` (`static func compute_crit_damage(...)`) em `scripts/combat/effects/sys_7.gd`, e o Agente 2 recebe o bastão para criar `hit_apply.gd`. As 15 execuções foram intercaladas (`#1..#5` entre os 3 braços) em repositórios descartáveis independentes; os dados brutos e `session_id`s estão em [`docs/benchmark_ab3.json`](docs/benchmark_ab3.json).

- **Braço A (`A_vague_prose`):** resumo narrativo típico de agente (~780 chars) descrevendo o que foi feito, sem caminho nem assinatura exatos.
- **Braço A' (`A_prime_fact_prose`):** parágrafo em prosa natural (~710 chars) contendo **exatamente os mesmos fatos** do `@PKT` (`scripts/combat/effects/sys_7.gd`, `class_name CritEngine` e assinatura completa).
- **Braço B (`B_pkt`):** `@PKT` + `[REPOMAP]` extraídos automaticamente do Git (~720 chars com envelope).

| Braço (n=5 cada, 100% acerto) | Custo faturado USD — Mediana `[min..max]` | Input tokens totais — Mediana `[min..max]` | Turnos — Mediana `[min..max]` | Tools — Mediana `[min..max]` | Tempo (s) — Mediana `[min..max]` |
|---|---|---|---|---|---|
| **A: Prosa narrativa vaga** | **`$0,1252`** `[$0,1217..$0,1384]` | `165.980` `[160.759..199.813]` | `5` `[5..6]` | `4` `[4..5]` | `29,0s` `[28,2..38,9s]` |
| **A': Prosa com os mesmos fatos** | **`$0,0987`** `[$0,0980..$0,1227]` | `98.185` `[98.086..164.625]` | `3` `[3..5]` | `2` `[2..4]` | `17,3s` `[10,4..27,0s]` |
| **B: `@PKT` + `RepoMap` (Git)** | **`$0,0988`** `[$0,0987..$0,0988]` | `98.283` `[98.277..98.286]` | `3` `[3..3]` | `2` `[2..2]` | `10,2s` `[10,0..14,9s]` |

### O que os dados mostram (e o que não mostram)

1. **Redução de custo faturado (`B` vs `A`): `-21,1%` na mediana (`$0,1252` → `$0,0988`)**, enquanto os tokens de entrada caem **`-40,8%`** (`165.980` → `98.283`). O custo em dólares cai menos que os tokens brutos porque a criação inicial de cache do system prompt da CLI (~21k tokens) é um custo fixo de 1º turno e as releituras entre turnos usam tarifa reduzida de cache.
2. **De onde vem o ganho (`A'` ≈ `B` na mediana):** quando a prosa em linguagem natural (`A'`) carrega manualmente todos os fatos exatos, a mediana de custo empata com `B` (`$0,0987` vs `$0,0988`). Ou seja, **o ganho principal vem de extrair os fatos determinísticos do Git** (em vez de depender de o modelo anterior lembrar de escrever caminhos e tipos sem omitir nada, o que na prática degrada para `A`).
3. **Onde o formato estruturado `B` supera `A'` (variância de cauda e latência):** mesmo com todos os fatos na prosa `A'`, em **3 de 5** rodadas o modelo ainda abriu `Bash` para conferir o repositório (elevando o pior caso de `A'` a `$0,1227` / `164.625` tokens / `27,0s`). No `B` (`@PKT` + `[POLICY]`), **5 de 5** rodadas executaram exatamente `['Read', 'Write']`, cravando o teto em `$0,0988` e baixando a mediana de tempo de `17,3s` para **`10,2s` (`-40,8%` vs `A'`, `-64,7%` vs `A`)**.
4. **Quando NÃO há ganho (contra-exemplo):** em repositórios pequenos onde o único arquivo alterado ainda está sujo no `git status`, o cabeçalho automático de status da CLI já entrega o caminho ao modelo; nesse cenário `A` e `B` empatam (`~98k` tokens, `2` tools).

### Exemplo ilustrativo em projeto real (`KB-0357`)

Na execução real de uma tarefa de manutenção em repositório grande (`grok:architect` → `codex:coder` → failover `429` do `claude` → `grok:reviewer`), a telemetria oficial da CLI (`grok usage`) registrou `2.052.848` input tokens / `15` chamadas (`$2,70`) no agente que explorou do zero (`architect`) e `843.909` input tokens / `8` chamadas (`$1,36`) no agente que recebeu o `@PKT` com os 6 arquivos tocados (`reviewer`). *(Nota: trata-se de observação ilustrativa de fluxo real, não de A/B causal, pois `architect` e `reviewer` executam papéis distintos.)*

Para auditar métricas reais do seu próprio workspace a qualquer momento:
```bash
python pkt_report.py /caminho/do/workspace
```

---

## Testes

```bash
python -m unittest discover -s tests -v
```

## Licença

[MIT](LICENSE)
