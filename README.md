<<<<<<< HEAD
# SentinelAI: Plataforma de Pentest Inteligente com LLMs

**README.md**

## 1. Visão Geral (Overview)

SentinelAI é uma plataforma de pentest inteligente que utiliza modelos de linguagem grandes (LLMs) para auxiliar em diversas tarefas de segurança.  Seu propósito principal é acelerar e otimizar o processo de teste de penetração, fornecendo insights valiosos e automatizando tarefas repetitivas.  SentinelAI integra diversas ferramentas e técnicas para análise de vulnerabilidades, geração de provas de conceito e orquestração de ferramentas de reconhecimento.

**Recursos Chave:**

* Análise detalhada de vulnerabilidades OWASP Top 10.
* Análise de requisições HTTP para identificar falhas de segurança.
* Análise visual de imagens (screenshots, diagramas) para detectar vulnerabilidades OWASP.
* Geração de Provas de Conceito (PoCs) em HTML.
* Análise estática básica de código.
* Análise de especificações OpenAPI/Swagger para identificar falhas em APIs.
* Busca e análise de exploits no repositório local do Exploit-DB.
* Orquestração de ferramentas de reconhecimento CLI (Subfinder, Httpx, Nuclei, GoBuster, ffuf, Katana, Gau, Naabu, CTFR, Sublist3r, TLSX, Netlas).
* Geração de comandos táticos otimizados para ferramentas de pentest.


## 2. Pré-requisitos

* **Python 3.x:**  Recomendado Python 3.9 ou superior.
* **pip:** Gerenciador de pacotes Python.
* **Chave de API do Google Gemini (GOOGLE_API_KEY):**  Obtida através do [Google Cloud Console](https://console.cloud.google.com/).  É necessário criar um projeto e habilitar a API do Gemini.
* **Chave de API da NVD (NVD_API_KEY):** Opcional, para buscas mais amplas no banco de dados de vulnerabilidades da NVD.  (Observação: A funcionalidade de busca no NVD foi renomeada para "Search Exploit (NVD)" em versões anteriores).  Instruções de obtenção podem variar dependendo do provedor.
* **Chave de API da Netlas (NETLAS_API_KEY):** Opcional, para acesso a recursos avançados de reconhecimento da Netlas. Obtenha sua chave em [Netlas](https://netlas.io/).
* **Ferramentas CLI de Reconhecimento:**  As seguintes ferramentas devem ser baixadas e colocadas na pasta `ReconTools/`: `subfinder`, `httpx`, `nuclei`, `gobuster`, `ffuf`, `katana`, `gau`, `naabu`, `ctfr`, `sublist3r`, `tlsx`, `netlas`.  Certifique-se de que estejam configuradas corretamente e adicionadas ao PATH do seu sistema (ou use caminhos absolutos na configuração).
* **Repositório do Exploit-DB:** Clone o repositório do Exploit-DB e coloque as pastas `exploits/` e `shellcodes/` na pasta `ExploitDB/`.  Você pode clonar usando `git clone https://github.com/offensive-security/exploit-db.git ExploitDB/exploit-db`.  Após clonar, renomeie a pasta `exploit-db` para `ExploitDB`.


## 3. Estrutura de Pastas Esperada

```
SentinelAI/
├── SentinelAI.py
├── .env
├── ReconTools/
│   ├── subfinder
│   ├── httpx
│   └── ...
├── Wordlist/
│   ├── Discovery/
│   │   └── Web-Content/
│   │       └── big.txt
│   └── Fuzzing/
│       └── fuzz.txt
└── ExploitDB/
    ├── exploits/
    └── shellcodes/
```

## 4. Instalação

1. **Clone o repositório:** `git clone <URL_DO_REPOSITORIO>`
2. **Ambiente Virtual (Recomendado):** Crie e ative um ambiente virtual usando `python3 -m venv venv` e `source venv/bin/activate` (Linux/macOS) ou `venv\Scripts\activate` (Windows).
3. **Instale as dependências:** `pip install -r requirements.txt`
4. **Configure o arquivo `.env`:** Crie um arquivo `.env` na raiz do projeto e adicione suas chaves de API:

```
GOOGLE_API_KEY=YOUR_GOOGLE_API_KEY
NVD_API_KEY=YOUR_NVD_API_KEY (opcional)
NETLAS_API_KEY=YOUR_NETLAS_API_KEY (opcional)
```

5. **Configure as Ferramentas CLI:** Baixe e coloque os executáveis das ferramentas de reconhecimento na pasta `ReconTools/`.
6. **Configure o Exploit-DB:** Baixe e coloque as pastas `exploits/` e `shellcodes/` do Exploit-DB na pasta `ExploitDB/`.


## 5. Como Usar

1. **Inicie o aplicativo:** `streamlit run SentinelAI.py`
2. **Navegue pelas seções:** Utilize a barra lateral para navegar entre as diferentes funcionalidades.

**Funcionalidades Principais:**

* **OWASP Details:** Analisa e fornece informações detalhadas sobre as vulnerabilidades OWASP Top 10.
* **HTTP Analyzer:** Analisa requisições HTTP para identificar potenciais falhas de segurança.
* **Image Analyzer:** Analisa imagens (screenshots, diagramas) para detectar vulnerabilidades OWASP.
* **PoC Generator:** Gera Provas de Conceito (PoCs) em HTML.
* **OpenAPI Analyzer:** Analisa especificações OpenAPI/Swagger para identificar falhas em APIs.
* **Static Code Analyzer:** Realiza análise estática básica de código.
* **Search Exploit (NVD):** Busca por exploits no banco de dados da NVD (requer NVD_API_KEY).
* **Advanced Reconnaissance:** Orquestra ferramentas de reconhecimento para coleta de informações.
* **Tactical Command Orchestrator:** Gera comandos otimizados para ferramentas de pentest.


**Nota Importante:** Utilize o SentinelAI apenas em ambientes de teste autorizados e com permissão explícita.  O uso não ético e ilegal desta ferramenta é estritamente proibido.


## 6. Contribuição

Contribuições são bem-vindas!  Por favor, abra um *issue* para relatar bugs ou sugestões de melhorias.  Para contribuições de código, crie um *pull request* após criar um *fork* do repositório.  Certifique-se de seguir as diretrizes de estilo de código e realizar testes adequados antes de enviar seu *pull request*.
=======
# SentinelAI: Plataforma de Pentest Inteligente com LLMs

**README.md**

## 1. Visão Geral (Overview)

SentinelAI é uma plataforma de pentest inteligente que utiliza modelos de linguagem grandes (LLMs) para auxiliar em diversas tarefas de segurança.  Seu propósito principal é acelerar e otimizar o processo de teste de penetração, fornecendo insights valiosos e automatizando tarefas repetitivas.  SentinelAI integra diversas ferramentas e técnicas para análise de vulnerabilidades, geração de provas de conceito e orquestração de ferramentas de reconhecimento.

**Recursos Chave:**

* Análise detalhada de vulnerabilidades OWASP Top 10.
* Análise de requisições HTTP para identificar falhas de segurança.
* Análise visual de imagens (screenshots, diagramas) para detectar vulnerabilidades OWASP.
* Geração de Provas de Conceito (PoCs) em HTML.
* Análise estática básica de código.
* Análise de especificações OpenAPI/Swagger para identificar falhas em APIs.
* Busca e análise de exploits no repositório local do Exploit-DB.
* Orquestração de ferramentas de reconhecimento CLI (Subfinder, Httpx, Nuclei, GoBuster, ffuf, Katana, Gau, Naabu, CTFR, Sublist3r, TLSX, Netlas).
* Geração de comandos táticos otimizados para ferramentas de pentest.


## 2. Pré-requisitos

* **Python 3.x:**  Recomendado Python 3.9 ou superior.
* **pip:** Gerenciador de pacotes Python.
* **Chave de API do Google Gemini (GOOGLE_API_KEY):**  Obtida através do [Google Cloud Console](https://console.cloud.google.com/).  É necessário criar um projeto e habilitar a API do Gemini.
* **Chave de API da NVD (NVD_API_KEY):** Opcional, para buscas mais amplas no banco de dados de vulnerabilidades da NVD.  (Observação: A funcionalidade de busca no NVD foi renomeada para "Search Exploit (NVD)" em versões anteriores).  Instruções de obtenção podem variar dependendo do provedor.
* **Chave de API da Netlas (NETLAS_API_KEY):** Opcional, para acesso a recursos avançados de reconhecimento da Netlas. Obtenha sua chave em [Netlas](https://netlas.io/).
* **Ferramentas CLI de Reconhecimento:**  As seguintes ferramentas devem ser baixadas e colocadas na pasta `ReconTools/`: `subfinder`, `httpx`, `nuclei`, `gobuster`, `ffuf`, `katana`, `gau`, `naabu`, `ctfr`, `sublist3r`, `tlsx`, `netlas`.  Certifique-se de que estejam configuradas corretamente e adicionadas ao PATH do seu sistema (ou use caminhos absolutos na configuração).
* **Repositório do Exploit-DB:** Clone o repositório do Exploit-DB e coloque as pastas `exploits/` e `shellcodes/` na pasta `ExploitDB/`.  Você pode clonar usando `git clone https://github.com/offensive-security/exploit-db.git ExploitDB/exploit-db`.  Após clonar, renomeie a pasta `exploit-db` para `ExploitDB`.


## 3. Estrutura de Pastas Esperada

```
SentinelAI/
├── SentinelAI.py
├── .env
├── ReconTools/
│   ├── subfinder
│   ├── httpx
│   └── ...
├── Wordlist/
│   ├── Discovery/
│   │   └── Web-Content/
│   │       └── big.txt
│   └── Fuzzing/
│       └── fuzz.txt
└── ExploitDB/
    ├── exploits/
    └── shellcodes/
```

## 4. Instalação

1. **Clone o repositório:** `git clone <URL_DO_REPOSITORIO>`
2. **Ambiente Virtual (Recomendado):** Crie e ative um ambiente virtual usando `python3 -m venv venv` e `source venv/bin/activate` (Linux/macOS) ou `venv\Scripts\activate` (Windows).
3. **Instale as dependências:** `pip install -r requirements.txt`
4. **Configure o arquivo `.env`:** Crie um arquivo `.env` na raiz do projeto e adicione suas chaves de API:

```
GOOGLE_API_KEY=YOUR_GOOGLE_API_KEY
NETLAS_API_KEY=YOUR_NETLAS_API_KEY (opcional)
```

5. **Configure as Ferramentas CLI:** Baixe e coloque os executáveis das ferramentas de reconhecimento na pasta `ReconTools/`.
6. **Configure o Exploit-DB:** Baixe e coloque as pastas `exploits/` e `shellcodes/` do Exploit-DB na pasta `ExploitDB/`.


## 5. Como Usar

1. **Inicie o aplicativo:** `streamlit run SentinelAI.py`
2. **Navegue pelas seções:** Utilize a barra lateral para navegar entre as diferentes funcionalidades.

**Funcionalidades Principais:**

* **OWASP Details:** Analisa e fornece informações detalhadas sobre as vulnerabilidades OWASP Top 10.
* **HTTP Analyzer:** Analisa requisições HTTP para identificar potenciais falhas de segurança.
* **Image Analyzer:** Analisa imagens (screenshots, diagramas) para detectar vulnerabilidades OWASP.
* **PoC Generator:** Gera Provas de Conceito (PoCs) em HTML.
* **OpenAPI Analyzer:** Analisa especificações OpenAPI/Swagger para identificar falhas em APIs.
* **Static Code Analyzer:** Realiza análise estática básica de código.
* **Search Exploit (NVD):** Busca por exploits no banco de dados da NVD (requer NVD_API_KEY).
* **Advanced Reconnaissance:** Orquestra ferramentas de reconhecimento para coleta de informações.
* **Tactical Command Orchestrator:** Gera comandos otimizados para ferramentas de pentest.


**Nota Importante:** Utilize o SentinelAI apenas em ambientes de teste autorizados e com permissão explícita.  O uso não ético e ilegal desta ferramenta é estritamente proibido.


## 6. Contribuição

Contribuições são bem-vindas!  Por favor, abra um *issue* para relatar bugs ou sugestões de melhorias.  Para contribuições de código, crie um *pull request* após criar um *fork* do repositório.  Certifique-se de seguir as diretrizes de estilo de código e realizar testes adequados antes de enviar seu *pull request*.
>>>>>>> d952da5b7f7b2e0742adccf77664452963260a10
