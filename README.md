# 🚀 CYBERPUNK AI PENTEST AGENT 2077

**Agente automatizado de pentest com UI “cyberpunk”, gerenciamento de fila sensível a recursos e integração com IA.**

---

## 🔎 Descrição curta
Ferramenta de automação de testes de penetração com GUI, gerenciamento de fila baseado em recursos e análise assistida por IA. Ideal para laboratórios e testes autorizados.

---

## ⚠️ Aviso de segurança / legal
**Somente use em sistemas que você possui ou tem permissão explícita para testar.** Varreduras sem autorização são ilegais. O script pode executar ferramentas intrusivas e enviar dados para uma API externa (configurável). Revise o código e as chaves de API antes de rodar.

---

## 🧰 Principais recursos
- Gerenciamento de fila sensível a recursos (CPU / RAM) com limites configuráveis.  
- Perfis de recursos por ferramenta (estimativa de CPU/RAM/tempo).  
- GUI em **tkinter** com tema "cyberpunk" (monitor de recursos, fila, console).  
- Integração com um serviço de IA para analisar relatórios e sugerir comandos/ações.  
- Geração de relatórios por rodada e extração automática de CVEs.

---

## 📦 Requisitos
- Python 3.7+ (recomendado 3.9+)  
- `psutil`, `requests` e `tkinter` (ver `install_dependencies.py`).  
- Ferramentas externas opcionais (para funcionalidades completas): `nmap`, `sqlmap`, `nikto`, `nuclei`, `masscan`, `hydra`, `metasploit`, etc. (instale via apt / pacman / brew conforme sua distro).

---

## 🚀 Instalação rápida

1. Clone o repositório:
```bash
git clone <SEU_REPO_URL>
cd <SEU_REPO_DIR>
```

2. Instale dependências Python (script incluído):
```bash
python3 install_dependencies.py
```
(este script verifica e instala `psutil` e `requests`; `tkinter` pode precisar ser instalado via pacote do sistema).

3. (Opcional) Instale ferramentas de pentest do sistema:
```bash
# Exemplo Debian/Ubuntu
sudo apt update
sudo apt install -y nmap sqlmap nikto masscan
```

---

## ▶️ Quick start (execução)
Siga o guia rápido no arquivo `QUICK_START.md` ou rode:
```bash
python3 AIlinuxV2.py
```
Depois, insira o alvo (use apenas alvos autorizados), ajuste `Max Concurrent Tools`, thresholds de CPU/RAM e clique em **INITIATE SCAN** na GUI.

---

## ⚙️ Configurações importantes
- Configure as chaves de API (se for usar a integração IA) no topo do `AIlinuxV2.py`: `API_KEYS` e `API_URL`. A integração envia relatórios para um endpoint externo — revise a política de privacidade antes de enviar dados sensíveis.  
- Ajuste `Max Concurrent Tools`, `CPU Threshold` e `RAM Threshold` na interface para proteger seu sistema de sobrecarga.

---

## 🗂️ Estrutura de saída (exemplo)
Cada sessão gera uma pasta `AI_Pentest_YYYYMMDD_HHMMSS_<id>/` com subpastas por rodada:
```
AI_Pentest_YYYYMMDD_HHMMSS_ID/
├─ round_1/
│  ├─ nmap.txt
│  ├─ nikto.txt
│  ├─ report.json
│  └─ decision.json
├─ round_2/
├─ errors.log
└─ final_report.json
```
Os relatórios e decisões são usados pela IA para determinar próximos passos.

---

## 🛠️ Como funciona (resumo técnico)
1. Usuário inicia scan e adiciona ferramentas à fila.  
2. `ResourceMonitor` verifica CPU/RAM e permite execução apenas quando seguro.  
3. `ToolQueueManager` gerencia execução concorrente (1–3 ferramentas).  
4. Saídas são agregadas em `report.json`.  
5. Resultado é enviado ao motor IA (se configurado); a IA retorna comandos no formato `<COMMANDS>` e um JSON `<DECISION>` com próximas ferramentas.

---

## 📚 Leituras / documentação adicional
- `QUICK_START.md` — passo a passo visual e exemplos.  
- `OPTIMIZATION_SUMMARY.md` — resumo das otimizações de uso de recursos (filas, perfis, monitor).

---

## 🤝 Contribuição
Contribuições são bem-vindas. Sugestões:
- Adicionar novos perfis de ferramenta
- Melhorar validação de comandos retornados pela IA
- Suporte a contêiner/Docker para execução isolada

---

## 🧾 Licença
Uso educacional / testes autorizados. Inclua aqui a sua licença (MIT, Apache-2.0, etc.) conforme desejar.

---

**OBS:** revise o código antes de execução em ambiente de produção. Para uso seguro, rode dentro de VM isolada e contra laboratórios/CTFs autorizados.
