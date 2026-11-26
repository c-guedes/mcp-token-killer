# @PKT: do rascunho inflado ao gateway público

Registro da evolução do protocolo de handoff compacto entre agentes (`@PKT` + bitmask de estado), desde o primeiro documento até o port standalone em [`mcp-token-killer`](https://github.com/c-guedes/mcp-token-killer). Cobre as seis versões do documento, a auditoria do código no Brumavale, as correções aplicadas e a revisão do repositório público.

O fio condutor é um só: **o pacote deve carregar fatos extraídos do sistema, não a opinião do modelo**, e qualquer perda de informação deve ser visível para quem recebe.

---

## Sumário

1. [Contexto](#1-contexto)
2. [A ideia central](#2-a-ideia-central)
3. [As seis versões do documento](#3-as-seis-versões-do-documento)
4. [Uma armadilha no caminho: a resenha elogiosa](#4-uma-armadilha-no-caminho-a-resenha-elogiosa)
5. [A auditoria do código](#5-a-auditoria-do-código)
6. [As correções e os testes de regressão](#6-as-correções-e-os-testes-de-regressão)
7. [O port para o `mcp-token-killer`](#7-o-port-para-o-mcp-token-killer)
8. [Lições](#8-lições)
9. [Pendências](#9-pendências)
10. [Referências](#10-referências)

---

## 1. Contexto

O Brumavale (RPG em Godot, com servidor C#) é desenvolvido com várias CLIs de agentes trabalhando em paralelo sobre um Kanban próprio (`tools/kanban.py`): Codex, Opencode, Claude Code e Agy, cada um assumindo cards, às vezes caindo no meio e sendo substituído por outro.

O problema prático era o **handoff narrativo**: cada agente deixava para o próximo um parágrafo em prosa ("terminei a classe X, tive um problema na linha 40, resolvi com fallback, agora você precisa..."). Isso gerava três falhas recorrentes:

| Falha | Efeito |
|---|---|
| Acúmulo de ruído | Diários de bordo com saídas de terminal e tentativas descartadas saturam o contexto do 5º agente |
| Ambiguidade de contrato | Prosa omite tipos e nomes exatos; o próximo agente adivinha e reescreve o que já existia |
| Exploração cega | O agente acorda sem saber o que mudou e gasta os primeiros turnos com `find`/`grep` |

## 2. A ideia central

Duas camadas com públicos diferentes:

- **Bitmask de 16 bits**, para o motor Python. Gates em O(1) sem chamar LLM (`if bits & BIT_NEEDS_IMG and not bits & BIT_HAS_IMG: bloqueia`).
- **Micro-packet `@PKT`**, uma linha de texto para o LLM seguinte:

```
@PKT|KB0186|done|codex|0x1023[CODE,API,BAL_OK,PUB]|op=HND|f=server/Combat.cs,scripts/hud/CombatLog.gd|api=Combat.cs: `public void ApplyStun(int duration)`|nxt=Conectar chamada no HUD
```

O hexadecimal é opaco para o modelo; quem carrega significado são as tags textuais entre colchetes. O ganho real não vem da codificação binária, e sim de o pacote conter **só fatos verificáveis**: arquivos de `git diff --name-only`, assinaturas de `git diff -U0` via regex, e um ponteiro curto de próximo passo.

## 3. As seis versões do documento

### v1: boa engenharia, fundamentação inflada

A arquitetura já estava certa. O problema era a seção acadêmica, que atribuía aos papers conclusões que eles não sustentam:

| O que o doc dizia | O que a fonte mostra |
|---|---|
| AgentDiet: "até 70% do histórico é ruído" | Redução de **39,9% a 59,7%** nos tokens de entrada (custo final −21,1% a −35,9%), mantendo desempenho. Paper de 2025, publicado na FSE 2026 |
| SWE-Pruner (2024): RepoMap com linha exata | Paper de **2026**; faz poda de observações de arquivo dentro do contexto do agente, não RepoMap |
| AgentPrune: "+38% de acurácia", "degeneração por fofoca" | Poda **arestas** do grafo de comunicação entre agentes; os números e o termo não vêm dele |
| Lost in the Middle "prova a necessidade de chave-valor" | Mostra o efeito de posição no contexto; o formato chave-valor é inferência de design |

Além disso, a revisão apontou problemas de engenharia:

- `f=` e `api=` cortavam em 4 e 3 itens **em silêncio**.
- `git diff -U0 HEAD~1` só enxerga o último commit.
- A regex tinha `[AZa-z0-9_]` (faltava o hífen em `A-Z`).
- `nxt=` dizia "o que fazer" mas perdia o **porquê**, o que leva o próximo agente a desfazer um fallback intencional.

### v2: honestidade nas citações, correções no protocolo

A seção 2 passou a dizer "o que o estudo realmente demonstra" e "inspiração no Kanban" separadamente. Entraram quatro correções: marcador `(+N)`, campo `why=`, diff contra commit base, regex corrigida.

Ficaram três pontos:

- O fallback `HEAD~1` evita diff vazio, mas continua perdendo commits; o certo é gravar `base_commit` no claim.
- O exemplo da seção 3.1 (`f=tools/kanban.py,(+2)`) contradizia a regra de 4 itens.
- Linhas `L<n>` do RepoMap envelhecem se forem geradas no handoff e não no despacho.

Também: um filtro de log por **whitelist** de palavras-chave descarta falhas reais que não usaram o vocabulário esperado.

### v3: base_commit na origem, RepoMap just-in-time, blacklist

Tudo entrou. Sobrou um caso de borda criado pelo próprio protocolo: **failover**. Se o `base_commit` é gravado ao entrar em `doing`, o segundo claim (após o Codex cair) sobrescreveria a base e o diff do Claude perderia os commits do Codex. Regra: gravar só se vazio. E se a base sumiu (rebase/squash), `git diff` retorna erro, não diff vazio; tratar `returncode != 0`.

### v4: herança no failover e proteção contra rebase

Correto. Mas uma inconsistência filosófica: quando o fallback `HEAD~1` dispara, o diff é parcial e chega ao receptor **com cara de completo**. Isso é o "truncamento invisível" que o próprio doc proibia. Sugestão: um bit `DIFF_PARTIAL` e um marcador `(?)`.

### v5: o pêndulo para o outro lado

O doc virou "100% lossless", com duas heurísticas novas de recuperação. Ambas podem errar:

- `git log --until=<claimed_at>` usa data de commit, que rebase reescreve, e depende do relógio da máquina.
- `git merge-base HEAD <trunk>` devolve tudo desde a bifurcação; se outro card commitou na mesma branch, **os contratos dele entram neste card**. Isso é pior que perder: é atribuir errado.

Correção de enquadramento: exato quando há `base_commit` validado; *best-effort sinalizado* nos demais casos. E ligar `PARTIAL_DIFF` sempre que o diff não veio de uma base gravada e validada, não só quando tudo falha.

### v6: versão final

A seção 4.3 passou a descrever o que o código faz, inclusive onde pode errar. `PARTIAL_DIFF (0x4000)` dispara pela regra certa. O guia de portabilidade fechou em sete pontos:

1. Substituir diários narrativos por tuplas estruturadas extraídas do git.
2. Fazer os gates críticos no código hospedeiro, não no LLM.
3. Manter truncamentos visíveis (`(+N)`).
4. Preservar intenção com um `why=` curto.
5. Gravar `base_commit` no primeiro claim e herdar no failover.
6. Sinalizar qualquer diff heurístico (`PARTIAL_DIFF` / `(?)`).
7. Gerar RepoMaps no despacho do worker.

A partir daqui, a recomendação foi **parar de iterar o documento e ir para o código**.

## 4. Uma armadilha no caminho: a resenha elogiosa

Outro agente, convidado a dar sua visão sobre o `.md`, respondeu com "brilhante", "perfeição", "zero reparos", "100%". Não era mentira: ele avaliou o documento, a conta `0x1482 | 0x4000 = 0x5482` está certa e os exemplos batem. Mas era uma resenha da coerência interna do texto, não uma verificação do código, e o tom trazia de volta exatamente o vocabulário inflado que tinha sido retirado do doc.

A lição prática: **uma avaliação sem evidência (função, linha, trecho, saída de comando) não prova nada**, por mais confiante que soe. A pergunta "o código faz o que o doc diz?" continuava aberta.

## 5. A auditoria do código

Foi montado um checklist de 18 itens com resposta obrigatória `OK / FALHA / NÃO_ENCONTRADO`, função, linha e trecho colado, mais quatro testes de execução, e a instrução de **reportar sem corrigir**.

### Resultado

| Item | Veredito | Observação |
|---|---|---|
| 1–2 Truncamento `f=` / `api=` | OK | 4 arquivos + `,(+N)`; 3 contratos + `;(+N)` |
| 3–4 `why=` / `nxt=` | OK | 90 e 140 chars, `\n` removido |
| **5 `base_commit` no claim** | **FALHA** | Gravado em `new_card` (e duplicado); ausente em `move_card` |
| 6–9 Validação, diff, heurísticas, returncode | OK | `cat-file -e`, `PARTIAL_DIFF` e `(?)` ligados nos caminhos heurísticos |
| **10 Regex** | **FALHA** | Sem `def`, sem `@export`, sem propriedades C# `{ get; set; }` |
| 11–12 Bitmask | OK | Tabela bate com o doc |
| 13 Log blacklist | OK | Mas com padrão perigoso (abaixo) |
| 14 RepoMap no despacho | OK | Chamado em `_work_prompt()` |
| T15–T18 | OK | Mas T18 passou pelo motivo errado |

### O bug que a auditoria subestimou

O auditor descreveu o item 5 como "o card cai nas heurísticas". Na verdade era pior. Como `new_card` gravava a base **na criação**, um card criado no backlog na segunda e assumido na quinta chegava a `doing` com base de segunda. Essa base passa no `cat-file`, então o diff vinha **marcado como exato** incluindo os commits de todos os outros cards da semana. Era sobreinclusão silenciosa, o pior caso possível para o protocolo.

O teste T18 (failover não altera a base) passou só porque `move_card` nunca escrevia no campo, não porque a herança estivesse implementada.

### O padrão perigoso na blacklist

`"nao encontrei"` descartava qualquer nota curta com essa frase, inclusive "nao encontrei Combat.cs, criei do zero", que é exatamente o diagnóstico de que o próximo agente precisa.

## 6. As correções e os testes de regressão

Aplicadas em `tools/kanban.py`, sem refatoração ao redor:

```diff
 def new_card(...):
-        if not card.get("base_commit"):     # (bloco removido, estava duplicado)
-            ...
 def move_card(...):
     if status == "doing":
         card["claimed_by"] = by
         card["claimed_at"] = card["updated"]
+        if not card.get("base_commit"):
+            rev = _git_head_rev()
+            if rev:
+                card["base_commit"] = rev
 def cmd_claim(...):                          # caminho --take que não passa por move_card
+        if not card.get("base_commit"): ...
 _LOG_NOISE_PATTERNS = (
-    "nao encontrei",
 )
-    code_f = [... endswith((".gd", ".cs"))]
+    code_f = [... endswith((".gd", ".cs", ".py"))]
     sig_re = re.compile(
-        r"...func\s+[A-Za-z0-9_]+..."
+        r"...func\s+(?!_)[A-Za-z0-9_]+..."
+        r"def\s+(?!_)[A-Za-z0-9_]+\s*\(|"
+        r"@export(?:_[a-z_]+)?\s+var\s+[A-Za-z0-9_]+|"
+        r"public\s+(?:static\s+)?[A-Za-z0-9_<>]+\s+[A-Za-z0-9_]+\s*\{\s*get|"
```

Dois ajustes feitos pelo agente sem pedir, e corretos: incluir `.py` em `code_f` (sem isso a alternância `def` nunca rodaria) e repetir o guard em `cmd_claim`.

O `(?!_)` foi uma afinação posterior: sem ele, `_ready()`, `_process()` e `__init__` enchiam o `api=` e empurravam o contrato público para dentro do `(+N)`.

### Testes

| Teste | O que prova | Resultado |
|---|---|---|
| T18 | Criado em backlog → base vazia; claim pelo Codex → base = HEAD; failover para Claude → base inalterada | Passou |
| **T19** | Card criado, dois commits de outro card, depois claim → base é o HEAD do **claim**, não da criação | Passou; é o teste que prova que o bug morreu |
| T20 | `@export var speed: int` e `public int Hp { get; set; }` aparecem em `api=` | Passou |
| Filtro privado | `func _ready`, `def __init__` ignorados; `static func get_instance` mantido | 8/8 |

Arremates: apagar os scripts descartáveis de patch, mover os testes para `tools/tests/`, e uma linha no doc (4.4) sobre identificadores com `_` serem tratados como privados.

## 7. O port para o `mcp-token-killer`

O protocolo foi extraído para um servidor MCP standalone: `pkt_core.py`, `cli_gateway.py`, `rtk_exec.py`, `server.py`, com quatro tools (`agent_run`, `pkt_save`, `pkt_get`, `rtk_run`). Os 13 testes de `pkt_core` passam; o servidor importa com `mcp` 2.3.0.

### O que melhorou em relação ao doc

- **Truncamento recuperável.** O `(+N)` agora vem acompanhado de `ref=<id>#<sha8>`, que aponta para o payload completo em `.mcp-agents/pkt_refs.json`. Não é só visível: dá para expandir com `pkt_get`.
- `smart_truncate` corta cabeça + cauda com `...(+Nc)...`, preservando início e fim do `why`/`nxt`.
- Validação de tipos (`coerce_handoff`) antes de serializar.
- Proteções de recursão (profundidade, ciclo entre atores, circuit breaker de chamada repetida) e cooldown por rate limit.
- Escrita atômica com lock e *spill* em JSONL quando o lock não é obtido.

### O que se perdeu no caminho

**A ideia central.** `pkt_save` recebe `touched_files` e `interface_contracts` como argumentos preenchidos pelo LLM. É justamente o que o documento mandava nunca fazer. O extrator com `sig_re` e `base_commit` não foi portado. Consequência: nada seta `diff_partial`, `delegated` ou `qa_status`, então `PARTIAL_DIFF`, `(?)`, `DELEG` e `QA_*` são código morto, e o `api=` carrega o que o agente *acha* que mudou com a mesma cara de fato.

O caminho de volta já está meio pronto: `run_cli` calcula arquivos alterados via `git status`. Basta gerar o `@PKT` no fim de um `agent_run` em modo work, com arquivos do git e contratos da regex, deixando para o LLM apenas `why` e `nxt`.

### Riscos de segurança

Relevantes porque o repositório é público:

- `_run_prompt_hook` executa `.mcp-agents/prompt_hook.py` (e `tools/claude_jev_prompt_hook.py`, resto do Brumavale) de qualquer `workspace` informado. Um repo clonado com esse arquivo roda código arbitrário.
- `roles.json` do workspace pode declarar `"mode": "work"`, e um `role` promove `read` para `work` silenciosamente. Assim um repo de terceiros consegue disparar `--dangerously-skip-permissions` / `--yolo`.
- O fallback continua em **qualquer** falha, não só em rate limit. Uma tarefa de escrita que falhou de verdade é refeita pelas outras CLIs, todas sem permissões, nos mesmos arquivos.

Mitigação proposta: hook e roles do workspace atrás de opt-in explícito por variável de ambiente; fallback só quando `_is_limit_error`; modo nunca promovido por role.

### Bugs menores

- `changed = _git_changed_files(ws) - files_before`: arquivo já sujo antes da execução e editado de novo some de `changed_files` e do `[DELTA]`.
- `BIT_CODE_TOUCHED` testa se o arquivo **existe**, não se mudou.
- `lock_owner` usa o pid do servidor MCP, então duas chamadas simultâneas do mesmo ator nunca conflitam.

### Repositório

- Nome "token-killer", README intitulado "mcp-agents" e sem explicação do `@PKT`. O documento desta história não está lá.
- Caminhos fixos `D:\Pythonn\...`, sem `requirements.txt` (depende de `mcp` 2.x pelo `MCPServer`), sem licença.
- Testes só para `pkt_core`; o gateway, onde estão os riscos, não tem cobertura.

## 8. Lições

1. **Inflação vem dos dois lados.** Na v1 eram números de papers; na v5 era "100% lossless". Nas duas a correção foi a mesma: dizer o que o código faz, inclusive onde erra.
2. **Perda visível é aceitável; perda silenciosa não.** `(+N)`, `(?)`, `PARTIAL_DIFF` e `ref=` existem pela mesma razão.
3. **Errar para mais é pior que errar para menos.** Atribuir a um card contratos que vieram de outro engana o receptor com confiança.
4. **Teste que passa pelo motivo errado não prova nada.** T18 só ficou significativo depois que T19 existiu.
5. **Avaliação sem evidência é opinião.** Auditoria pede função, linha, trecho e saída de comando, e pede para reportar antes de corrigir.
6. **Portar é onde as garantias se perdem.** O mecanismo que dava sentido ao protocolo (extração do git) foi o que ficou para trás.

## 9. Pendências

**No `mcp-token-killer`, em ordem:**

- [x] Opt-in para `prompt_hook.py` (`MCP_ALLOW_WORKSPACE_HOOKS=1`) e `roles.json` do workspace (`MCP_ALLOW_WORKSPACE_ROLES=1`); removida referência a `claude_jev_prompt_hook.py`
- [x] Fallback apenas em rate limit (`_is_limit_error`); role nunca promove `read` → `work`
- [x] Portado `CONTRACT_SIG_RE` + `base_commit` (`ensure_base_commit`) e geração de `@PKT` a partir do git no fim de `agent_run` em modo `work` (e em `pkt_save`, sem `touched_files`/`interface_contracts` vindos do LLM)
- [x] `diff_partial` (`PARTIAL_DIFF` / `(?)`) ligado sempre que não houver `base_commit` gravado e validado
- [x] Detecção de arquivos já sujos reeditados via snapshot de hash (`snapshot_worktree` / `diff_worktree_snapshots`), `BIT_CODE_TOUCHED` validando mudança real e `lock_owner` único por invocação
- [x] Suíte de testes cobrindo `cli_gateway` (`tests/test_cli_gateway.py`) além de `pkt_core` (`tests/test_pkt_core.py`) — 18/18 passando
- [x] `README.md` documentando o protocolo `@PKT` e modelo de segurança, `docs/HISTORIA_PKT.md`, `requirements.txt`, `LICENSE` (MIT) e caminhos genéricos

**No Brumavale:**

- [ ] Apagar scripts descartáveis de patch e consolidar testes em `tools/tests/`
- [ ] Commit isolado das correções do `kanban.py`
- [ ] Nota na seção 4.4 sobre identificadores privados com `_`
- [ ] Observar a frequência de `(?)` em uso real; se for alta, o problema é card entrando em `doing` sem passar pelo claim

## 10. Referências

- Xiao, Gao, Peng, Xiong. *Reducing Cost of LLM Agents with Trajectory Reduction* (AgentDiet). FSE 2026. [arXiv:2509.23586](https://arxiv.org/abs/2509.23586)
- *SWE-Pruner: Self-Adaptive Context Pruning for Coding Agents*. 2026. [arXiv:2601.16746](https://arxiv.org/abs/2601.16746)
- *SWE-Pruner Pro: The Coder LLM Already Knows What to Prune*. 2026. [arXiv:2607.18213](https://arxiv.org/abs/2607.18213)
- *Cut the Crap* (AgentPrune). 2024. Poda de arestas em grafos de comunicação multiagente.
- Liu et al. *Lost in the Middle: How Language Models Use Long Contexts*. 2023.
- Repositório: [c-guedes/mcp-token-killer](https://github.com/c-guedes/mcp-token-killer)
