import streamlit as st
import os
import sys
from dotenv import load_dotenv
import google.generativeai as genai
from PIL import Image
from io import BytesIO
import requests
import time
import json
from urllib.parse import urlparse
import streamlit.components.v1 as components
import yaml
import subprocess
import uuid
import re


# --- Configurações do LLM (Temperatura Reduzida para Consistência) ---
LLM_TEMPERATURE = 0.1

# --- Configuração do LLM (API Key) ---
load_dotenv()
API_KEY = os.getenv("GOOGLE_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")
NETLAS_API_KEY = os.getenv("NETLAS_API_KEY")
RAPID7_INSIGHTVM_API_KEY = os.getenv("RAPID7_INSIGHTVM_API_KEY") # Nova chave para Rapid7 InsightVM
RAPID7_INSIGHTVM_REGION = os.getenv("RAPID7_INSIGHTVM_REGION", "us") # Região padrão: us

# Base URL para a API do Rapid7 InsightVM
RAPID7_API_BASE_URLS = {
    "us": "https://us.api.insight.rapid7.com",
    "eu": "https://eu.api.insight.rapid7.com",
    "ca": "https://ca.api.insight.rapid7.com",
    "au": "https://au.api.insight.rapid7.com",
    "ap": "https://ap.api.insight.rapid7.com",
    "jp": "https://jp.api.insight.rapid7.com"
}
RAPID7_INSIGHTVM_URL = RAPID7_API_BASE_URLS.get(RAPID7_INSIGHTVM_REGION.lower(), RAPID7_API_BASE_URLS["us"])


if not API_KEY:
    st.error("ERRO: A variável de ambiente 'GOOGLE_API_KEY' não está configurada.")
    st.info("Por favor, crie um arquivo .env na raiz do seu projeto e adicione 'GOOGLE_API_KEY=SUA_CHAVE_AQUI'.")
    st.info("Você pode obter sua chave em [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)")
    st.stop()

# --- Dicionários de Referência da OWASP ---
OWASP_TOP_10_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)"
}

OWASP_API_TOP_10_2023 = {
    "API1": "Broken Object Level Authorization (BOLA)",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization (BFLA)",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery (SSRF)",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs"
}

OWASP_SUBCATEGORIES = {
    "A01": [
        "Insecure Direct Object References (IDOR)", "Missing Function Level Access Control",
        "Privilege Escalation (Vertical/Horizontal)", "Path Traversal",
        "URL Tampering", "Parameter Tampering"
    ],
    "A02": [
        "Weak Hashing Algorithms", "Use of Outdated/Weak Encryption Protocols (e.g., TLS 1.0/1.1)",
        "Hardcoded Cryptographic Keys", "Improper Key Management",
        "Exposure of Sensitive Data in Transit/At Rest"
    ],
    "A03": [
        "SQL Injection (SQLi)", "Cross-Site Scripting (XSS)",
        "Command Injection", "LDAP Injection", "XPath Injection",
        "NoSQL Injection", "Server-Side Template Injection (SSTI)",
        "Code Injection (e.g., PHP, Python, Java)", "Header Injection (e.g., Host Header Injection)"
    ],
    "A04": [
        "Business Logic Flaws", "Lack of Security Design Principles",
        "Trust Boundary Violations", "Feature Overload",
        "Insecure Direct Object References (IDOR) - (also A01, design aspect)"
    ],
    "A05": [
        "Default Passwords/Configurations", "Unnecessary Features/Services Enabled",
        "Improper File/Directory Permissions", "Missing Security Headers",
        "Error Messages Revealing Sensitive Information", "Open Cloud Storage Buckets"
    ],
    "A06": [
        "Using Libraries/Frameworks with Known Vulnerabilities", "Outdated Server Software (e.g., Apache, Nginx, IIS)",
        "Client-Side Libraries with Vulnerabilities", "Lack of Patch Management"
    ],
    "A07": [
        "Weak Password Policies", "Missing Multi-Factor Authentication (MFA)",
        "Session Management Flaws (e.g., fixed session IDs)", "Improper Credential Recovery Mechanisms",
        "Brute-Force Attacks (lack of rate limiting)"
    ],
    "A08": [
        "Insecure Deserialization", "Lack of Integrity Checks on Updates/Packages",
        "Weak Digital Signatures", "Client-Side Trust (e.g., relying on client-side validation)"
    ],
    "A09": [
        "Insufficient Logging of Security Events", "Lack of Alerting on Suspicious Activities",
        "Inadequate Retention of Logs", "Logs Not Protected from Tampering"
    ],
    "A10": "Server-Side Request Forgery (SSRF)"
}


# --- Funções Auxiliares Comuns ---

def get_gemini_models_cached():
    if 'llm_models' not in st.session_state:
        st.session_state.llm_models = {'vision_model': None, 'text_model': None, 'initialized': False}

    if not st.session_state.llm_models['initialized']:
        genai.configure(api_key=API_KEY)

        llm_model_vision_temp = None
        llm_model_text_temp = None

        vision_model_priority = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-pro-vision"]
        text_model_priority = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-pro"]

        try:
            available_models = list(genai.list_models())

            for preferred_name in vision_model_priority:
                for m in available_models:
                    if preferred_name in m.name and 'generateContent' in m.supported_generation_methods:
                        llm_model_vision_temp = genai.GenerativeModel(m.name)
                        break
                if llm_model_vision_temp:
                    break

            for preferred_name in text_model_priority:
                for m in available_models:
                    if preferred_name in m.name and 'generateContent' in m.supported_generation_methods:
                        llm_model_text_temp = genai.GenerativeModel(m.name, generation_config={"temperature": LLM_TEMPERATURE})
                        break
                if llm_model_text_temp:
                    break

            if not llm_model_vision_temp:
                st.error("ERRO: Nenhum modelo LLM de visão adequado (gemini-1.5-flash/pro ou gemini-pro-vision) encontrado.")
                st.info("Por favor, configure sua GOOGLE_API_KEY e verifique a disponibilidade de modelos no Google AI Studio.")
            if not llm_model_text_temp:
                st.error("ERRO: Nenhum modelo LLM de texto adequado (gemini-1.5-flash/pro ou gemini-pro) encontrado.")
                st.info("Por favor, configure sua GOOGLE_API_KEY e verifique a disponibilidade de modelos no Google AI Studio.")

        except Exception as e:
            st.error(f"ERRO ao listar ou selecionar modelos do Gemini: {e}")
            st.info("Verifique sua conexão com a internet e sua GOOGLE_API_KEY.")

        st.session_state.llm_models['vision_model'] = llm_model_vision_temp
        st.session_state.llm_models['text_model'] = llm_model_text_temp
        st.session_state.llm_models['initialized'] = True
    
    return st.session_state.llm_models['vision_model'], st.session_state.llm_models['text_model']


def obter_resposta_llm(model_instance, prompt_parts):
    if model_instance is None:
        st.error("Erro: O modelo LLM não foi inicializado corretamente. Não é possível gerar conteúdo.")
        return None
    try:
        response = model_instance.generate_content(prompt_parts)
        return response.text
    except Exception as e:
        st.error(f"Erro ao comunicar com o LLM: {e}")
        st.info("Verifique se a sua conexão com a internet está ativa e se o modelo LLM está funcionando.")
        return None

def formatar_resposta_llm(resposta_bruta):
    return resposta_bruta

@st.cache_data(show_spinner=False)
def mapear_falha_para_owasp(_llm_text_model, falha_input):
    owasp_list = "\n".join([f"{code}: {name}" for code, name in OWASP_TOP_10_2021.items()])

    prompt = (
        f"Qual categoria da OWASP Top 10 (2021) melhor representa a vulnerabilidade ou técnica de ataque '{falha_input}'?"
        f"\n\nConsidere a seguinte lista de categorias OWASP Top 10 (2021):"
        f"\n{owasp_list}"
        f"\n\nResponda apenas com o CÓDIGO da categoria OWASP (ex: A03) e nada mais. Se não tiver certeza ou se não se encaixar em nenhuma categoria, responda 'INDEFINIDO'."
        f"Exemplos: 'SQL Injection' -> 'A03', 'Cross-Site Scripting' -> 'A03', 'IDOR' -> 'A01', 'Clickjacking' -> 'A04'"
    )

    with st.spinner(f"Tentando mapear '{falha_input}' para uma categoria OWASP..."):
        resposta = obter_resposta_llm(_llm_text_model, [prompt])

    if resposta:
        codigo_owasp = resposta.strip().upper().split(':')[0].split(' ')[0]
        if codigo_owasp in OWASP_TOP_10_2021:
            return codigo_owasp
        elif codigo_owasp == "INDEFINIDO":
            st.warning("O LLM não conseguiu mapear a falha para uma categoria OWASP específica.")
            return None
        else:
            st.warning(f"O LLM retornou um código inesperado: '{codigo_owasp}'.")
            return None
    return None

def parse_vulnerability_summary(text_response):
    summary = {
        "Total": 0, "Críticas": 0, "Altas": 0, "Médias": 0, "Baixas": 0
    }

    lines = text_response.split('\n')
    summary_line_found = False
    parsed_content = []

    for i, line in enumerate(lines):
        if ("Total de Vulnerabilidades:" in line or "Total de Ameaças:" in line or "Total de Vulnerabilidades API:" in line or "Total de Insights:" in line or "Total de Eventos:" in line or "Total de Achados:" in line) and not summary_line_found:
            summary_line = line
            summary_line_found = True
        else:
            parsed_content.append(line)

    if summary_line_found:
        parts = summary_line.split('|')
        for part in parts:
            part = part.strip()
            if "Total de Vulnerabilidades:" in part or "Total de Ameaças:" in part or "Total de Vulnerabilidades API:" in part or "Total de Insights:" in part or "Total de Eventos:" in part or "Total de Achados:" in part:
                try:
                    summary["Total"] = int(part.split(':')[1].strip())
                except ValueError: pass
            elif "Críticas:" in part:
                try:
                    summary["Críticas"] = int(part.split(':')[1].strip())
                except ValueError: pass
            elif "Altas:" in part:
                try:
                    summary["Altas"] = int(part.split(':')[1].strip())
                except ValueError: pass
            elif "Médias:" in part:
                try:
                    summary["Médias"] = int(part.split(':')[1].strip())
                except ValueError: pass
            elif "Baixas:" in part:
                try:
                    summary["Baixas"] = int(part.split(':')[1].strip())
                except ValueError: pass

    return summary, "\n".join(parsed_content).strip()

def parse_raw_http_request(raw_request):
    method = ""
    path = ""
    full_url = ""
    headers = {}
    body = ""

    lines = raw_request.splitlines()

    if lines:
        first_line_parts = lines[0].split(' ')
        if len(first_line_parts) >= 2:
            method = first_line_parts[0].strip()
            path = first_line_parts[1].strip()

    body_started = False
    for line in lines[1:]:
        if not line.strip() and not body_started:
            body_started = True
            continue

        if not body_started:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        else:
            body += line + '\n'

    if 'Host' in headers and path:
        host = headers['Host']
        scheme = "https" if "443" in host or "https" in raw_request.lower().splitlines()[0] else "http"
        if path.startswith('/') and urlparse(f"{scheme}://{host}").path != '/':
            full_url = f"{scheme}://{host}{path}"
        else:
             full_url = f"{scheme}://{host}{path}"

    return {
        "method": method,
        "path": path,
        "full_url": full_url,
        "headers": headers,
        "body": body.strip()
    }


# --- Funções das "Páginas" ---

def home_page():
    llm_model_vision, llm_model_text = get_gemini_models_cached()

    st.header("Bem-vindo ao SentinelAI - Plataforma de Segurança 🛡️")
    st.markdown("""
        Sua suíte de reconhecimento e pentest inteligente, com o poder do LLM!
        Selecione uma opção na barra lateral para começar:
        - **Início**: Esta página.
        - **OWASP Vulnerability Details**: Digite uma falha ou categoria OWASP e obtenha detalhes completos.
        - **Análise de Requisições HTTP**: Cole uma requisição HTTP e identifique possíveis falhas de segurança.
        - **OWASP Image Analyzer**: Identifique vulnerabilidades OWASP em prints de tela ou imagens.
        - **PoC Generator (HTML)**: Gere PoCs HTML para vulnerabilidades específicas.
        - **OpenAPI Analyzer**: Analise especificações de API em busca de falhas de segurança e melhorias de design.
        - **Static Code Analyzer**: Cole trechos de código para análise básica de segurança e busca por informações sensíveis.
        - **Search Exploit**: Pesquise por exploits e shellcodes no seu repositório local do Exploit-DB.
        - **Advanced Reconnaissance**: Orquestre ferramentas de recon e obtenha insights do LLM.
        - **Tactical Command Orchestrator**: Obtenha comandos de ferramentas otimizados com o LLM para seu cenário.
        - **Pentest Playbook Generator**: Gere playbooks passo a passo para cenários de pentest.
        - **Intelligent Log Analyzer**: Analise logs em busca de anomalias e eventos de segurança.
        - **Rapid7 Vulnerability Validation**: Valide vulnerabilidades do Rapid7 e encontre exploits.
    """)
    st.info("Para começar, selecione uma das opções de análise na barra lateral.")


def modelagem_de_ameacas_page():
    # Esta função está definida no seu código original, mas não está nas opções da barra lateral
    # Mantendo-a aqui caso decida adicioná-la futuramente.
    llm_model_vision, llm_model_text = get_gemini_models_cached()

    st.header("Modelagem de Ameaças (STRIDE) 📊")
    st.markdown("""
        Envie um diagrama de arquitetura (ou um print de tela) e uma descrição da sua aplicação.
        O SentinelAI irá analisar a imagem e o texto para identificar ameaças de segurança usando a metodologia STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
    """)

    def reset_stride_analysis():
        st.session_state.stride_image_uploaded = None
        st.session_state.stride_description_text = ""
        st.session_state.stride_analysis_result = ""
        st.session_state.stride_summary = None
        st.rerun()

    if st.button("Limpar e Fazer Nova Consulta", key="reset_stride_analysis_button"):
        reset_stride_analysis()

    uploaded_diagram_file = st.file_uploader(
        "Selecione o diagrama de arquitetura (JPG, JPEG, PNG)",
        type=["jpg", "jpeg", "png"],
        key="stride_file_uploader"
    )

    diagram_preview_placeholder = st.empty()

    if uploaded_diagram_file is not None:
        try:
            diagram_bytes = uploaded_diagram_file.getvalue()
            diagram_img = Image.open(BytesIO(diagram_bytes))
            diagram_preview_placeholder.image(diagram_img, caption="Pré-visualização do Diagrama", use_container_width=True)
            st.session_state.stride_image_uploaded = diagram_img
        except Exception as e:
            st.error(f"Erro ao carregar o diagrama: {e}")
            st.session_state.stride_image_uploaded = None
    elif st.session_state.stride_image_uploaded:
        diagram_preview_placeholder.image(st.session_state.stride_image_uploaded, caption="Pré-visualização do Diagrama", use_container_width=True)
    else:
        st.session_state.stride_image_uploaded = None

    app_description = st.text_area(
        "Descreva a aplicação e sua arquitetura (componentes, fluxos de dados, etc.):",
        value=st.session_state.stride_description_text,
        placeholder="Ex: 'É um e-commerce com frontend React, backend Node.js, banco de dados MongoDB, e usa AWS S3 para armazenamento de imagens.'",
        height=150,
        key="stride_description_input"
    )
    st.session_state.stride_description_text = app_description.strip()

    if st.button("Analisar Arquitetura (STRIDE)", key="analyze_stride_button"):
        if st.session_state.stride_image_uploaded is None:
            st.error("Por favor, selecione um diagrama de arquitetura para análise.")
        elif not st.session_state.stride_description_text:
            st.error("Por favor, forneça uma descrição da aplicação e sua arquitetura.")
        else:
            with st.spinner("Realizando modelagem de ameaças STRIDE..."):
                stride_prompt = (
                    f"Você é um especialista em modelagem de ameaças e segurança de software, com profundo conhecimento na metodologia STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).\n"
                    f"Sua tarefa é analisar o diagrama de arquitetura fornecido (na imagem) e a descrição da aplicação, e identificar ameaças de segurança usando o framework STRIDE.\n"
                    f"\n**RESUMO:** Forneça um resumo quantitativo na PRIMEIRA LINHA da sua resposta, no formato exato: `Total de Ameaças: X | Críticas: Y | Altas: Z | Médias: W | Baixas: V` (substitua X,Y,Z,W,V pelos números correspondentes). Se não houver ameaças, use 0.\n\n"
                    f"Para cada ameaça STRIDE identificada, forneça os seguintes detalhes de forma concisa e prática, utilizando formato Markdown para títulos e blocos de código:\n\n"
                    f"## Ameaça Identificada: [Nome da Ameaça]\n"
                    f"**Tipo STRIDE:** [S/T/R/I/D/E - Ex: Information Disclosure]\n"
                    f"**Severidade:** [Crítica/Alta/Média/Baixa]\n"
                    f"**Descrição:** Explique brevemente a ameaça e como ela se manifesta neste diagrama/descrição.\n"
                    f"**Árvore de Ataques (Simplificada):** Descreva os passos típicos que um atacante seguiria para explorar esta ameaça, como uma lista ou pequenos parágrafos, ilustrando o fluxo de ataque.\n"
                    f"**Impacto Potencial:** Qual o risco se esta ameaça for explorada?\n"
                    f"**Sugestão de Mitigação:** Ações concretas e específicas para mitigar esta ameaça, relevantes para a arquitetura apresentada. Seja direto e acionável.\n\n"
                    f"Se não encontrar ameaças óbvias, ou a informação for insuficiente, indique isso e sugira melhorias para a arquitetura ou para o diagrama/descrição.\n\n"
                    f"**Descrição da Aplicação/Arquitetura:**\n{st.session_state.stride_description_text}\n\n"
                    f"**Diagrama:** (Imagem anexada)"
                )

                stride_analysis_result_raw = obter_resposta_llm(llm_model_vision, [stride_prompt, st.session_state.stride_image_uploaded])

                if stride_analysis_result_raw:
                    st.session_state.stride_summary, st.session_state.stride_analysis_result = parse_vulnerability_summary(stride_analysis_result_raw)
                else:
                    st.session_state.stride_analysis_result = "Não foi possível realizar a modelagem de ameaças. Tente refinar sua descrição ou diagrama."
                    st.session_state.stride_summary = None

    if st.session_state.stride_analysis_result:
        st.subheader("Resultados da Modelagem de Ameaças (STRIDE)")

        if st.session_state.stride_summary:
            st.markdown("#### Resumo das Ameaças Identificadas:")
            cols = st.columns(5)
            cols[0].metric("Total", st.session_state.stride_summary["Total"])
            cols[1].metric("Críticas", st.session_state.stride_summary["Críticas"])
            cols[2].metric("Altas", st.session_state.stride_summary["Altas"])
            cols[3].metric("Médias", st.session_state.stride_summary["Médias"])
            cols[4].metric("Baixas", st.session_state.stride_summary["Baixas"])
            st.markdown("---")

        st.markdown(st.session_state.stride_analysis_result)
        # Feedback Buttons for Modelagem de Ameaças
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="stride_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="stride_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")

def owasp_scout_visual_page(llm_model_vision, llm_model_text):
    st.header("OWASP Image Analyzer: Análise de Vulnerabilidades em Imagens 👁️")
    st.markdown("""
        Envie um print, um trecho de código em imagem, ou qualquer diagrama e pergunte ao SentinelAI se ele detecta vulnerabilidades OWASP Top 10.
        Quanto mais detalhes na sua pergunta, melhor a análise!
    """)

    def reset_owasp_scout_visual():
        st.session_state.owasp_image_uploaded = None
        st.session_state.owasp_question_text = ""
        st.session_state.owasp_analysis_result = ""
        st.session_state.owasp_consider_waf_state = False
        st.rerun()

    if st.button("Limpar e Fazer Nova Consulta", key="reset_visual_analysis_button"):
        reset_owasp_scout_visual()

    uploaded_file = st.file_uploader(
        "Selecione uma imagem para análise (JPG, JPEG, PNG)",
        type=["jpg", "jpeg", "png"],
        key="owasp_file_uploader"
    )

    image_preview_placeholder = st.empty()

    if uploaded_file is not None:
        try:
            img_bytes = uploaded_file.getvalue()
            img = Image.open(BytesIO(img_bytes))
            image_preview_placeholder.image(img, caption="Pré-visualização da Imagem", use_container_width=True)
            st.session_state.owasp_image_uploaded = img
        except Exception as e:
            st.error(f"Erro ao carregar a imagem: {e}")
            st.session_state.owasp_image_uploaded = None
    elif st.session_state.owasp_image_uploaded:
        image_preview_placeholder.image(st.session_state.owasp_image_uploaded, caption="Pré-visualização da Imagem", use_container_width=True)
    else:
        st.session_state.owasp_image_uploaded = None


    question = st.text_area(
        "Sua pergunta sobre a vulnerabilidade ou contexto:",
        value=st.session_state.owasp_question_text,
        placeholder="Ex: 'Esta tela de login é vulnerável?', 'Há XSS neste código?', 'Qual vulnerabilidade está presente neste diagrama?'",
        key="owasp_question_input"
    )
    st.session_state.owasp_question_text = question

    consider_waf = st.checkbox(
        "Considerar bypass de WAF?",
        value=st.session_state.owasp_consider_waf_state,
        key="owasp_waf_checkbox"
    )

    if st.button("Analisar Vulnerabilidade", key="owasp_analyze_button_main"):
        if st.session_state.owasp_image_uploaded is None:
            st.error("Por favor, selecione uma imagem para análise.")
        elif not st.session_state.owasp_question_text:
            st.error("Por favor, digite sua pergunta sobre a vulnerabilidade na imagem.")
        else:
            with st.spinner("Analisando sua imagem em busca de vulnerabilidades OWASP..."):
                prompt_parts = [
                    f"Você é um especialista em segurança da informação e pentest."
                    f"Analise a imagem fornecida e a seguinte pergunta/contexto: '{st.session_state.owasp_question_text}'."
                    f"\n\nIdentifique possíveis vulnerabilidades de segurança da informação relevantes para a OWASP Top 10 (2021) que possam ser inferidas da imagem ou do contexto fornecido."
                    f"\n\nPara cada vulnerabilidade identificada, forneça os seguintes detalhes de forma concisa e prática, utilizando formato Markdown para títulos e blocos de código:"
                    f"\n\n## 1. Detalhamento da Falha"
                    f"\nUma breve explicação do que é a vulnerabilidade, como ela ocorre e os cenários comuns de impacto, **especificamente como se relaciona à imagem ou ao contexto.**"
                    f"\n\n## 2. Categoria OWASP (2021)"
                    f"\nIndique o CÓDIGO e o NOME da categoria da OWASP Top 10 (2021) à qual esta vulnerabilidade pertence (ex: A03: Injection). Use a lista: {', '.join([f'{c}: {n}' for c, n in OWASP_TOP_10_2021.items()])}. Se for uma subcategoria, mencione-la também."
                    f"\n\n## 3. Técnicas de Exploração Detalhadas"
                    f"\nDescreva passo a passo os métodos comuns e abordagens para testar e explorar esta vulnerabilidade, focando em como a imagem pode estar relacionada. Seja didático e prático.\n"
                    f"\n\n## 4. Ferramentas Sugeridas"
                    f"\nListe as ferramentas de segurança e pentest (ex: Burp Suite, Nmap, SQLmap, XSSer, Nessus, Nikto, Metasploit, etc.) que seriam úteis para descobrir e explorar esta vulnerabilidade, explicando brevemente como cada uma se aplicaria.\n"
                    f"\n\n## 5. Severidade"
                    f"\nClassifique a severidade desta vulnerabilidade: [Crítica/Alta/Média/Baixa].\n"
                    f"\n\n## 6. Dicas de Exploração / Próximos Passos Práticos"
                    f"\nCom base na falha identificada e no contexto da imagem, forneça dicas práticas e os próximos passos que um pentester faria para explorar ou confirmar a falha. Inclua instruções sobre como usar as ferramentas sugeridas e payloads de teste, se aplicável. Seja acionável.\n"
                ]

                if st.session_state.owasp_consider_waf_state:
                    prompt_parts.append(f"\n\n## 7. Dicas de Bypass de WAF")
                    prompt_parts.append(f"\nForneça estratégias, técnicas e exemplos práticos (se aplicável à vulnerabilidade) para contornar ou evadir a detecção de um Web Application Firewall (WAF) ao tentar explorar esta falha. Inclua exemplos de payloads ou modificações de requisições que podem ajudar a testar o presença ou bypass do WAF.")
                    poc_section_num = 8
                else:
                    poc_section_num = 7

                prompt_parts.append(f"\n\n## {poc_section_num}. Prova de Conceito (PoC)")
                prompt_parts.append(f"\nForneça **exemplos práticos de comandos de terminal, requisições HTTP (com `curl` ou similar), ou payloads de código (Python, JS, etc.)** que demonstrem a exploração. Esses exemplos devem ser claros, prontos para uso (com pequenas adaptações) e encapsulados em blocos de código Markdown (` ``` `). Relacione o PoC à imagem ou contexto, se possível.")

                prompt_parts.append(f"\n\nSeu objetivo é ser direto, útil e focado em ações e informações completas para um pentester. Se a imagem não contiver vulnerabilidades óbvias, ou a pergunta for muito genérica, indique isso de forma clara.")

                full_prompt_list = [st.session_state.owasp_image_uploaded, "".join(prompt_parts)]

                analysis_result = obter_resposta_llm(llm_model_vision, full_prompt_list)

                if analysis_result:
                    st.session_state.owasp_analysis_result = analysis_result
                else:
                    st.session_state.owasp_analysis_result = "Não foi possível obter uma resposta do Gemini. Tente novamente."

    if st.session_state.owasp_analysis_result:
        st.subheader("Resultados da Análise Visual")
        st.markdown(st.session_state.owasp_analysis_result)
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="owasp_visual_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="owasp_visual_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")

def owasp_text_analysis_page(llm_model_vision, llm_model_text):
    st.header("OWASP Vulnerability Details 📝")
    st.markdown("""
        Digite o CÓDIGO de uma categoria OWASP Top 10 (ex: `A03`) ou o NOME de uma falha específica (ex: `IDOR`, `XSS`, `SQL Injection`).
        O SentinelAI fornecerá detalhes completos sobre a vulnerabilidade.
    """)

    def reset_owasp_text_analysis():
        st.session_state.owasp_text_input_falha = ""
        st.session_state.owasp_text_analysis_result = ""
        st.session_state.owasp_text_context_input = ""
        st.session_state.owasp_text_consider_waf_state = False
        st.rerun()

    if st.button("Limpar e Fazer Nova Consulta", key="reset_text_analysis_button"):
        reset_owasp_text_analysis()

    user_input_falha = st.text_input(
        "Digite a falha ou categoria OWASP:",
        value=st.session_state.owasp_text_input_falha,
        placeholder="Ex: A01, Injection, IDOR, Cross-Site Scripting",
        key="text_input_falha"
    )
    st.session_state.owasp_text_input_falha = user_input_falha.strip()


    contexto_texto = st.text_area(
        "Forneça um contexto adicional (opcional):",
        value=st.session_state.owasp_text_context_input,
        placeholder="Ex: 'aplicação web em PHP', 'API REST com JWT', 'exploração via SQLi no parâmetro id'",
        key="text_context_input"
    )
    st.session_state.owasp_text_context_input = contexto_texto.strip()

    consider_waf_texto = st.checkbox(
        "Considerar bypass de WAF?",
        value=st.session_state.owasp_text_consider_waf_state,
        key="text_consider_waf_checkbox"
    )

    if st.button("Analisar Falha por Texto", key="analyze_text_button"):
        if not st.session_state.owasp_text_input_falha:
            st.error("Por favor, digite a falha ou categoria OWASP para análise.")
        else:
            categoria_owasp_codigo = None
            subcategoria_info = ""

            if st.session_state.owasp_text_input_falha.upper() in OWASP_TOP_10_2021:
                categoria_owasp_codigo = st.session_state.owasp_text_input_falha.upper()
                st.info(f"Categoria OWASP selecionada: {OWASP_TOP_10_2021[categoria_owasp_codigo]}")
            else:
                categoria_owasp_codigo = mapear_falha_para_owasp(llm_model_text, st.session_state.owasp_text_input_falha)
                if categoria_owasp_codigo:
                    st.info(f"O LLM mapeou '{st.session_state.owasp_text_input_falha}' para a categoria OWASP: {OWASP_TOP_10_2021[categoria_owasp_codigo]}")
                    if categoria_owasp_codigo in OWASP_SUBCATEGORIES:
                        for sub in OWASP_SUBCATEGORIES[categoria_owasp_codigo]:
                            if st.session_state.owasp_text_input_falha.lower() in sub.lower():
                                subcategoria_info = f" Foco na subcategoria: **'{sub}'**."
                                break
                else:
                    st.error("Não foi possível identificar a categoria OWASP para a falha fornecida.")
                    st.session_state.owasp_text_analysis_result = ""
                    return

            if categoria_owasp_codigo:
                with st.spinner(f"Obtendo informações para {OWASP_TOP_10_2021[categoria_owasp_codigo]}..."):
                    prompt_base = (
                        f"Você é um especialista em segurança da informação e pentest."
                        f"Sua tarefa é fornecer informações detalhadas para a exploração da vulnerabilidade da OWASP Top 10 (2021) "
                        f"categorizada como **'{OWASP_TOP_10_2021[categoria_owasp_codigo]}' ({categoria_owasp_codigo})**."
                        f"\n\nPor favor, inclua os seguintes tópicos de forma concisa e prática, utilizando formato Markdown para títulos e blocos de código:"
                        f"\n\n## 1. Detalhamento da Falha"
                        f"\nExplique a natureza da vulnerabilidade de forma clara e concisa: o que ela é, como surge e por que é um problema de segurança. Foque nos conceitos essenciais e no seu mecanismo.\n"
                        f"\n\n## 2. Cenário de Exemplo de Exploração"
                        f"\nIlustre um cenário de ataque potencial que explora essa vulnerabilidade. Descreva as etapas passo a passo que um atacante poderia seguir para explorá-la, incluindo o ambiente típico e as condições necessárias para o sucesso do ataque.\n"
                        f"\n\n## 3. Técnicas de Exploração"
                        f"\nMétodos comuns e abordagens para testar e explorar esta vulnerabilidade em diferentes contextos."
                        f"\n\n## 4. Severidade e Impacto Técnico"
                        f"\nClassifique a severidade desta vulnerabilidade: [Crítica/Alta/Média/Baixa].\n"
                        f"**Impacto Técnico:** Descreva o impacto técnico detalhado da exploração desta falha, com exemplos e consequências técnicas específicas.\n"
                        f"**CVSSv3.1 Score:** Forneça uma estimativa do score CVSS v3.1 para esta vulnerabilidade e o vetor CVSS. Ex: `7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)`\n"
                    )

                    if st.session_state.owasp_text_consider_waf_state:
                        prompt_base += f"\n\n## 5. Dicas de Bypass de WAF"
                        prompt_base += f"\nForneça estratégias, técnicas e exemplos práticos (se aplicável à vulnerabilidade) para contornar ou evadir a detecção de um Web Application Firewall (WAF) ao tentar explorar esta falha. Inclua exemplos de payloads ou modificações de requisições que podem ajudar a testar o presença ou bypass do WAF."
                        poc_section_num = 6
                        solution_section_num = 7
                        benefits_risks_section_num = 8
                    else:
                        poc_section_num = 5
                        solution_section_num = 6
                        benefits_risks_section_num = 7

                    prompt_base += (
                        f"\n\n## {poc_section_num}. Prova de Conceito (PoC)"
                        f"\nForneça **exemplos práticos de comandos de terminal, requisições HTTP (com `curl` ou similar), ou payloads de código (Python, JS, etc.)** que demonstrem a exploração. Esses exemplos devem ser claros, prontos para uso (com pequenas adaptações) e encapsulados em blocos de código Markdown (` ``` `)."
                        f"\n\n## {solution_section_num}. Detalhamento da Solução"
                        f"\nDescreva as ações recomendadas para corrigir o vulnerabilidade de forma eficaz."
                        f"\n\n## {benefits_risks_section_num}. Benefícios e Riscos da Correção"
                        f"\nQuais são os benefícios de implementar a solução e os possíveis riscos ou impactos colaterais da sua aplicação?"
                        f"\n\nSeu objetivo é ser direto, útil e focado em ações e informações completas para um pentester, como um resumo para um relatório de pentest."
                    )

                    analysis_result = obter_resposta_llm(llm_model_text, [prompt_base])

                    if analysis_result:
                        st.session_state.owasp_text_analysis_result = analysis_result
                    else:
                        st.session_state.owasp_text_analysis_result = "Não foi possível obter uma resposta do Gemini. Tente novamente."
            else:
                st.error("Não foi possível identificar a categoria OWASP para a falha fornecida.")
                st.session_state.owasp_text_analysis_result = ""

    if st.session_state.owasp_text_analysis_result:
        st.subheader("Resultados da Análise por Texto")
        st.markdown(st.session_state.owasp_text_analysis_result)
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="owasp_text_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="owasp_text_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")

def http_request_analysis_page(llm_model_vision, llm_model_text):
    st.header("Análise de Requisições HTTP 📡")
    st.markdown("""
        Cole a URL alvo e a requisição HTTP completa (RAW) do Burp Suite ou similar.
        O SentinelAI irá analisar a requisição em busca de **múltiplas falhas de segurança OWASP Top 10**, incluindo:
        - Injeções (SQLi, XSS, Command, etc.)
        - Falhas de autenticação/sessão
        - Configurações incorretas (headers, métodos HTTP, etc.)
        - Exposição de dados sensíveis
        - Falhas de controle de acesso
        - SSRF e outros tipos de falhas em componentes externos
        E sugerir **Provas de Conceito (PoCs) acionáveis** para testar essas falhas.
    """)

    def reset_http_request_analysis():
        st.session_state.http_request_input_url = ""
        st.session_state.http_request_input_raw = ""
        st.session_state.http_request_analysis_result = ""
        st.session_state.http_request_consider_waf_state = False
        st.session_state.http_request_summary = None
        st.rerun()

    if st.button("Limpar e Fazer Nova Consulta", key="reset_http_request_button"):
        reset_http_request_analysis()

    target_url = st.text_input(
        "URL Alvo (Target):",
        value=st.session_state.http_request_input_url,
        placeholder="Ex: [https://testphp.vulnweb.com/search.php](https://testphp.vulnweb.com/search.php)",
        key="http_request_target_url_input"
    )
    st.session_state.http_request_input_url = target_url.strip()

    http_request_raw = st.text_area(
        "Cole a requisição HTTP RAW aqui:",
        value=st.session_state.http_request_input_raw,
        placeholder="Ex: POST /search.php?... HTTP/1.1\nHost: ...\nContent-Length: ...",
        height=300,
        key="http_request_input_area"
    )
    st.session_state.http_request_input_raw = http_request_raw.strip()

    consider_waf_http = st.checkbox(
        "Considerar bypass de WAF?",
        value=st.session_state.http_request_consider_waf_state,
        key="http_request_waf_checkbox"
    )

    if st.button("Analisar Requisição", key="analyze_http_request_button"):
        if not st.session_state.http_request_input_url:
            st.error("Por favor, forneça a URL Alvo para análise.")
        elif not st.session_state.http_request_input_raw:
            st.error("Por favor, cole a requisição HTTP RAW para análise.")
        else:
            with st.spinner("Analisando a requisição HTTP com LLM..."):
                parsed_request = parse_raw_http_request(st.session_state.http_request_input_raw)

                request_method_path_version = f"{parsed_request['method']} {parsed_request['path']} HTTP/1.1" if parsed_request['method'] and parsed_request['path'] else "Não detectado"
                headers_formatted = "\n".join([f"{k}: {v}" for k, v in parsed_request['headers'].items()])
                body_content = parsed_request['body']

                prompt_base = (
                    f"Você é um especialista em segurança da informação e pentest. Analise a requisição HTTP RAW fornecida e a URL alvo. Identifique **TODAS as possíveis falhas de segurança OWASP Top 10 (2021) e outras vulnerabilidades relevantes aplicáveis**, sendo extremamente detalhado e preciso na análise de cada parte da requisição. Inclua:\n"
                    f"\n**RESUMO:** Forneça um resumo quantitativo na PRIMEIRA LINHA da sua resposta, no formato exato: `Total de Vulnerabilidades: X | Críticas: Y | Altas: Z | Médias: W | Baixas: V` (substitua X,Y,Z,W,V pelos números correspondentes). Se não houver vulnerabilidades, use 0.\n\n"
                    f"Para cada **falha potencial** identificado, apresente de forma concisa e prática:\n\n"
                    f"1.  **Tipo da Falha e Categoria OWASP (2021):** Ex: `Injeção SQL (A03: Injection)` ou `Exposição de Cookie Sensível`.\n"
                    f"2.  **Detalhes e Impacto:** Breve descrição da falha e como ela pode ser explorada nesta requisição específica, mencionando qual parte da requisição (linha, cabeçalho, corpo) está envolvida.\n"
                    f"3.  **Severidade:** [Crítica/Alta/Média/Baixa]\n"
                    f"4.  **Prova de Conceito (PoC) - REQUISIÇÃO HTTP RAW COMPLETA MODIFICADA:** Forneça **A REQUISIÇÃO HTTP RAW COMPLETA MODIFICADA** que demonstre a exploração da falha. Esta requisição RAW deve ser pronta para ser copiada e colada em um proxy (como Burp Suite Repeater) ou enviada via `netcat`. Encapsule a requisição RAW completa em um bloco de código Markdown com a linguagem `http` (` ```http `). Certifique-se de que a PoC é funcional e reflete a exploração da vulnerabilidade.\n"
                    f"5.  **Ferramentas Sugeridas:** Liste ferramentas de segurança e pentest (ex: Burp Suite, Nmap, SQLmap, XSSer, Nessus, Nikto, Metasploit, dirbuster, ffuf, ZAP, etc.) que seriam úteis para descobrir e explorar esta vulnerabilidade, explicando brevemente como cada uma se aplicaria.\n"
                )

                if st.session_state.http_request_consider_waf_state:
                    prompt_base += f"\n\n6.  **Dicas de Bypass de WAF:** Forneça estratégias, técnicas e exemplos práticos (se aplicável à vulnerabilidade) para contornar ou evadir a detecção de um Web Application Firewall (WAF) ao tentar explorar esta falha. Inclua exemplos de payloads ou modificações de requisições que podem ajudar a testar o presença ou bypass do WAF."
                    poc_section_num = 8
                else:
                    poc_section_num = 7

                prompt_base += (
                        f"\n\n## {poc_section_num}. Prova de Conceito (PoC)"
                        f"\nForneça **exemplos práticos de comandos de terminal, requisições HTTP (com `curl` ou similar), ou payloads de código (Python, JS, etc.)** que demonstrem a exploração. Esses exemplos devem ser claros, prontos para uso (com pequenas adaptações) e encapsulados em blocos de código Markdown (` ``` `)."
                        f"\n\n## {poc_section_num + 1}. Detalhamento da Solução"
                        f"\nDescreva as ações recomendadas para corrigir o vulnerabilidade de forma eficaz."
                        f"\n\n## {poc_section_num + 2}. Benefícios e Riscos da Correção"
                        f"\nQuais são os benefícios de implementar a solução e os possíveis riscos ou impactos colaterais da sua aplicação?"
                        f"\n\nSeu objetivo é ser direto, útil e focado em ações e informações completas para um pentester, como um resumo para um relatório de pentest."
                    )

                analysis_result_raw = obter_resposta_llm(llm_model_text, [prompt_base])

                if analysis_result_raw:
                    st.session_state.http_request_summary, st.session_state.http_request_analysis_result = parse_vulnerability_summary(analysis_result_raw)
                else:
                    st.session_state.http_request_analysis_result = "Não foi possível obter uma resposta do Gemini. Tente novamente."
                    st.session_state.http_request_summary = None

    if st.session_state.http_request_analysis_result:
        st.subheader("Resultados da Análise de Requisições HTTP")

        if st.session_state.http_request_summary:
            st.markdown("#### Resumo das Vulnerabilidades Identificadas:")
            cols = st.columns(5)
            cols[0].metric("Total", st.session_state.http_request_summary["Total"])
            cols[1].metric("Críticas", st.session_state.http_request_summary["Críticas"])
            cols[2].metric("Altas", st.session_state.http_request_summary["Altas"])
            cols[3].metric("Médias", st.session_state.http_request_summary["Médias"])
            cols[4].metric("Baixas", st.session_state.http_request_summary["Baixas"])
            st.markdown("---")

        st.markdown(st.session_state.http_request_analysis_result)
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="http_request_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="http_request_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")

def pentest_lab_page(llm_model_vision, llm_model_text):
    st.header("Pentest Lab: Seu Laboratório de Vulnerabilidades 🧪")
    st.markdown("""
        Selecione uma vulnerabilidade e o SentinelAI irá gerar um mini-laboratório HTML básico (PoC em HTML) para que você possa testar a falha diretamente no seu navegador.
        También fornecerá dicas de como explorar e o payload/comando para o teste.
        **AVISO: Este laboratório é para fins educacionais e de teste. Não execute payloads em sites reais.**
    """)

    def reset_pentest_lab():
        st.session_state.lab_vulnerability_selected = None
        st.session_state.lab_html_poc = ""
        st.session_state.lab_explanation = ""
        st.session_state.lab_payload_example = ""
        st.rerun()

    if st.button("Limpar Laboratório", key="reset_lab_button"):
        reset_pentest_lab()

    vulnerability_options = ["Escolha uma vulnerabilidade"] + sorted(OWASP_SUBCATEGORIES["A03"])

    selected_vuln = st.selectbox(
        "Selecione a vulnerabilidade para o laboratório:",
        options=vulnerability_options,
        index=0,
        key="lab_vuln_select"
    )
    st.session_state.lab_vulnerability_selected = selected_vuln if selected_vuln != "Escolha uma vulnerabilidade" else None

    if st.button("Gerar Laboratório", key="generate_lab_button"):
        if not st.session_state.lab_vulnerability_selected:
            st.error("Por favor, selecione uma vulnerabilidade para gerar o laboratório.")
        else:
            with st.spinner(f"Gerando laboratório para {st.session_state.lab_vulnerability_selected}..."):
                lab_prompt = (
                    f"Você é um especialista em pentest e educador. Sua tarefa é criar um mini-laboratório HTML simples e um payload para demonstrar a vulnerabilidade '{st.session_state.lab_vulnerability_selected}'.\n"
                    f"Forneça as informações nos seguintes tópicos:\n\n"
                    f"## 1. Descrição da Vulnerabilidade e Dicas de Exploração\n"
                    f"Uma breve explicação do que é a vulnerabilidade, como ela funciona e dicas práticas de como tentar explorá-la.\n\n"
                    f"## 2. Mini-Laboratório HTML (PoC HTML)\n"
                    f"Forneça um **código HTML COMPLETO e MÍNIMO** (com tags `<html>`, `<head>`, `<body>`) que simule um cenário vulnerável a **{st.session_state.lab_vulnerability_selected}**.\n"
                    f"Este HTML deve ser funcional e auto-contido. O foco é na vulnerabilidade, não no design.\n"
                    f"Encapsule o HTML completo em um bloco de código Markdown com a linguagem `html` (` ```html `).\n\n"
                    f"## 3. Exemplo de Payload/Comando para Teste\n"
                    f"Forneça o payload ou comando específico que o usuário injetaria ou usaria neste HTML para provar a vulnerabilidade. Encapsule em um bloco de código Markdown com la linguagem apropriada (ex: ` ```js `, ` ```sql `, ` ```bash `).\n"
                    f"Este payload deve ser adaptado para o HTML gerado no PoC HTML.\n"
                    f"\nSeja didático e direto. O objetivo é que o usuário possa copiar e colar o HTML e o payload para testar."
                )

                lab_generation_raw = obter_resposta_llm(llm_model_text, [lab_prompt])

                if lab_generation_raw:
                    st.session_state.lab_explanation = lab_generation_raw

                    html_start = lab_generation_raw.find("```html")
                    html_end = lab_generation_raw.find("```", html_start + len("```html"))

                    payload_start_marker = "```"

                    if html_start != -1 and html_end != -1:
                        payload_start = lab_generation_raw.find(payload_start_marker, html_end + 1)
                    else:
                        payload_start = lab_generation_raw.find(payload_start_marker)

                    payload_end = -1
                    if payload_start != -1:
                        payload_end = lab_generation_raw.find(payload_start_marker, payload_start + len(payload_start_marker))
                        if payload_end == payload_start:
                            payload_end = -1

                    if html_start != -1 and html_end != -1:
                        st.session_state.lab_html_poc = lab_generation_raw[html_start + len("```html") : html_end].strip()
                    else:
                        st.session_state.lab_html_poc = "Não foi possível extrair o HTML do laboratório. Verifique a resposta do LLM."

                    if payload_start != -1 and payload_end != -1:
                        payload_content = lab_generation_raw[payload_start + len(payload_start_marker) : payload_end].strip()
                        if '\n' in payload_content and payload_content.splitlines()[0].strip().isalpha():
                            st.session_state.lab_payload_example = '\n'.join(payload_content.splitlines()[1:])
                        else:
                            st.session_state.lab_payload_example = payload_content
                    else:
                        st.session_state.lab_payload_example = "Não foi possível extrair o exemplo de payload. Verifique a resposta do LLM."
                else:
                    st.session_state.lab_explanation = "Não foi possível gerar o laboratório para a vulnerabilidade selecionada."
                    st.session_state.lab_html_poc = ""
                    st.session_state.lab_payload_example = ""

    if st.session_state.lab_html_poc or st.session_state.lab_explanation:
        st.subheader("Resultados do Laboratório")

        st.markdown(st.session_state.lab_explanation)

        if st.session_state.lab_html_poc:
            st.markdown("#### Mini-Laboratório HTML (Copie e Cole em um arquivo .html e abra no navegador)")
            st.code(st.session_state.lab_html_poc, language="html")

            st.markdown("---")
            st.markdown("#### Teste o Laboratório Aqui (Visualização Direta)")
            st.warning("AVISO: Esta visualização direta é para conveniência. Para um teste real e isolado, **salve o HTML em um arquivo .html e abra-o diretamente no seu navegador**.")
            components.html(st.session_state.lab_html_poc, height=300, scrolling=True)
            st.markdown("---")

        if st.session_state.lab_payload_example:
            st.markdown("#### Exemplo de Payload/Comando para Teste")
            payload_lang = "plaintext"
            first_line = st.session_state.lab_payload_example.splitlines()[0].strip() if st.session_state.lab_payload_example else ""

            if "alert(" in st.session_state.lab_payload_example.lower() or "document.write" in st.session_state.lab_payload_example.lower():
                payload_lang = "js"
            elif "SELECT " in st.session_state.lab_payload_example.upper() and "FROM " in st.session_state.lab_payload_example.upper():
                payload_lang = "sql"
            elif "http" in first_line.lower() and ("post" in first_line.lower() or "get" in first_line.lower()):
                payload_lang = "http"
            elif "curl " in first_line.lower() or "bash" in first_line.lower():
                payload_lang = "bash"
            elif "python" in first_line.lower() or "import" in st.session_state.lab_payload_example.lower():
                payload_lang = "python"

            st.code(st.session_state.lab_payload_example, language=payload_lang)
        
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="pentest_lab_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="pentest_lab_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")


def poc_generator_html_page(llm_model_vision, llm_model_text):
    st.header("PoC Generator (HTML): Crie Provas de Conceito em HTML 📄")
    st.markdown("""
        Gere códigos HTML de Prova de Conceito para testar vulnerabilidades específicas no navegador.
        Perfect para demonstrar falhas como CSRF, Clickjacking, CORS, e XSS baseados em HTML.
    """)

    def reset_poc_generator():
        st.session_state.poc_gen_vulnerability_input = ""
        st.session_state.poc_gen_context_input = ""
        st.session_state.poc_gen_html_output = ""
        st.session_state.poc_gen_instructions = ""
        st.session_state.poc_gen_payload_example = ""
        st.rerun()

    if st.button("Limpar Gerador", key="reset_poc_gen_button"):
        reset_poc_generator()

    vulnerability_input = st.text_input(
        "Digite a vulnerabilidade para gerar a PoC HTML (Ex: CSRF, Clickjacking, CORS, XSS):",
        value=st.session_state.poc_gen_vulnerability_input,
        placeholder="Ex: CSRF, Clickjacking, CORS, XSS refletido",
        key="poc_gen_vuln_input"
    )
    st.session_state.poc_gen_vulnerability_input = vulnerability_input.strip()

    context_input = st.text_area(
        "Contexto Adicional (URL alvo, parâmetros, método, etc.):",
        value=st.session_state.poc_gen_context_input,
        placeholder="Ex: 'URL: [https://exemplo.com/transferencia](https://exemplo.com/transferencia), Parâmetros: conta=123&valor=100, Método: POST'",
        key="poc_gen_context_input_area"
    )
    st.session_state.poc_gen_context_input = context_input.strip()

    if st.button("Gerar PoC HTML", key="generate_poc_html_button"):
        if not st.session_state.poc_gen_vulnerability_input:
            st.error("Por favor, digite a vulnerabilidade para gerar a PoC.")
        else:
            with st.spinner(f"Gerando PoC HTML para {st.session_state.poc_gen_vulnerability_input}..."):
                poc_prompt = (
                    f"Você é um especialista em pentest e possui autorização para realizar testes de segurança. "
                    f"Sua tarefa é gerar uma Prova de Conceito (PoC) em HTML funcional e um payload/instruções para demonstrar a vulnerabilidade '{st.session_state.poc_gen_vulnerability_input}'.\n"
                    f"**Contexto:** {st.session_state.poc_gen_context_input if st.session_state.poc_gen_context_input else 'Nenhum contexto adicional fornecido.'}\n\n"
                    f"Forneça as informações nos seguintes tópicos:\n\n"
                    f"## 1. Detalhes da Vulnerabilidade e Como Funciona\n"
                    f"Uma breve explicação do que é a vulnerabilidade, como ela funciona e como a PoC a demonstra.\n\n"
                    f"## 2. Código HTML da PoC (Completo e Mínimo)\n"
                    f"Forneça um **código HTML COMPLETO e MÍNIMO** (com tags `<html>`, `<head>`, `<body>`) que simule um cenário vulnerável a **{st.session_state.poc_gen_vulnerability_input}**.\n"
                    f"Este HTML deve ser funcional e auto-contido. O foco é na vulnerabilidade, não no design.\n"
                    f"Encapsule o HTML completo em um bloco de código Markdown com a linguagem `html` (` ```html `).\n\n"
                    f"## 3. Instruções de Uso e Payload (se aplicável)\n"
                    f"Descreva como o usuário deve usar este HTML para testar a PoC. Se for necessário um payload ou comando específico (ex: um script XSS, uma URL modificada para Clickjacking), forneça-o explicitamente e encapsule-o em um bloco de código Markdown com la linguagem apropriada (ex: ` ```js `, ` ```sql `, ` ```bash `).\n"
                    f"\nSeja direto, prático e didático. O objetivo é que o usuário (um pentester autorizado) possa copiar e colar o HTML e as instruções para testar a falha em um ambiente de teste autorizado."
                )

                poc_generation_raw = obter_resposta_llm(llm_model_text, [poc_prompt])

                if poc_generation_raw:
                    st.session_state.poc_gen_instructions = poc_generation_raw

                    html_start = poc_generation_raw.find("```html")
                    html_end = poc_generation_raw.find("```", html_start + len("```html"))

                    payload_start_marker = "```"

                    if html_start != -1 and html_end != -1:
                        payload_start = poc_generation_raw.find(payload_start_marker, html_end + 1)
                    else:
                        payload_start = poc_generation_raw.find(payload_start_marker)

                    payload_end = -1
                    if payload_start != -1:
                        payload_end = poc_generation_raw.find(payload_start_marker, payload_start + len(payload_start_marker))
                        if payload_end == payload_start:
                            payload_end = -1

                    if html_start != -1 and html_end != -1:
                        st.session_state.poc_gen_html_output = poc_generation_raw[html_start + len("```html") : html_end].strip()
                    else:
                        st.session_state.poc_gen_html_output = "Não foi possível extrair o HTML do PoC. Verifique a resposta do LLM."

                    if payload_start != -1 and payload_end != -1:
                        payload_content = poc_generation_raw[payload_start + len(payload_start_marker) : payload_end].strip()
                        if '\n' in payload_content and payload_content.splitlines()[0].strip().isalpha():
                            st.session_state.poc_gen_payload_example = '\n'.join(payload_content.splitlines()[1:])
                        else:
                            st.session_state.poc_gen_payload_example = payload_content
                    else:
                        st.session_state.poc_gen_payload_example = "Não foi possível extrair o exemplo de payload. Verifique a resposta do LLM."
                else:
                    st.session_state.poc_gen_instructions = "Não foi possível gerar a PoC HTML para a vulnerabilidade selecionada."
                    st.session_state.poc_gen_html_output = ""
                    st.session_state.poc_gen_payload_example = ""

    if st.session_state.poc_gen_html_output or st.session_state.poc_gen_instructions:
        st.subheader("Results da PoC HTML")

        st.markdown(st.session_state.poc_gen_instructions)

        if st.session_state.poc_gen_html_output:
            st.markdown("#### Mini-Laboratório HTML (Copie e Cole em um arquivo .html e abra no navegador)")
            st.code(st.session_state.poc_gen_html_output, language="html")

            st.markdown("---")
            st.markdown("#### Teste o Laboratório Aqui (Visualização Direta)")
            st.warning("AVISO: Esta visualização direta é para conveniência. Para um teste real e isolado, **salve o HTML em um arquivo .html e abra-o diretamente no seu navegador**.")
            components.html(st.session_state.poc_gen_html_output, height=300, scrolling=True)
            st.markdown("---")

        if st.session_state.poc_gen_payload_example:
            st.markdown("#### Exemplo de Payload/Comando para Teste")
            payload_lang = "plaintext"
            first_line = st.session_state.poc_gen_payload_example.splitlines()[0].strip() if st.session_state.poc_payload_example else ""

            if "alert(" in st.session_state.poc_gen_payload_example.lower() or "document.write" in st.session_state.poc_gen_payload_example.lower():
                payload_lang = "js"
            elif "SELECT " in st.session_state.poc_gen_payload_example.upper() and "FROM " in st.session_state.poc_gen_payload_example.upper():
                payload_lang = "sql"
            elif "http" in first_line.lower() and ("post" in first_line.lower() or "get" in first_line.lower()):
                payload_lang = "http"
            elif "curl " in first_line.lower() or "bash" in first_line.lower():
                payload_lang = "bash"
            elif "python" in first_line.lower() or "import" in st.session_state.poc_gen_payload_example.lower():
                payload_lang = "python"

            st.code(st.session_state.poc_gen_payload_example, language=payload_lang)
        
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="poc_gen_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="poc_gen_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")


def static_code_analyzer_page(llm_model_vision, llm_model_text):
    st.header("Static Code Analyzer (Basic) 👨‍💻")
    st.markdown("""
        Cole um trecho de código para análise básica de segurança. O SentinelAI irá identificar
        vulnerabilidades comuns (OWASP Top 10), padrões de exposição de informações sensíveis
        (chaves, IPs, comentários) e sugerir correções e PoCs.
        **AVISO:** Esta é uma análise de *primeira linha* e não substitui um SAST completo.
    """)

    if 'code_input_content' not in st.session_state:
        st.session_state.code_input_content = ""
    if 'code_analysis_result' not in st.session_state:
        st.session_state.code_analysis_result = ""
    if 'code_language_selected' not in st.session_state:
        st.session_state.code_language_selected = "Python"

    def reset_code_analyzer():
        st.session_state.code_input_content = ""
        st.session_state.code_analysis_result = ""
        st.session_state.code_language_selected = "Python"
        st.rerun()

    if st.button("Limpar Análise de Código", key="reset_code_analysis_button"):
        reset_code_analyzer()

    code_content = st.text_area(
        "Cole o trecho de código aqui:",
        value=st.session_state.code_input_content,
        placeholder="Ex: import os\napi_key = 'YOUR_SECRET_KEY'\ndef query_db(user_input):\n  conn = sqlite3.connect('app.db')\n  cursor = conn.cursor()\n  cursor.execute(f\"SELECT * FROM users WHERE username = '{user_input}'\")",
        height=300,
        key="code_input_area"
    )
    st.session_state.code_input_content = code_content.strip()

    language_options = ["Python", "JavaScript", "Java", "PHP", "Go", "Ruby", "C#", "SQL", "Outra"]
    selected_language = st.selectbox(
        "Linguagem do Código:",
        options=language_options,
        index=language_options.index(st.session_state.code_language_selected),
        key="code_language_select"
    )
    st.session_state.code_language_selected = selected_language

    if st.button("Analisar Código", key="analyze_code_button"):
        if not st.session_state.code_input_content:
            st.error("Por favor, cole o código para análise.")
        else:
            with st.spinner(f"Analisando código {st.session_state.code_language_selected} com LLM..."):
                code_prompt = (
                    f"Você é um especialista em segurança de código e pentest. Analise o trecho de código fornecido na linguagem {st.session_state.code_language_selected}. "
                    f"Seu objetivo é identificar **TODAS as potenciais vulnerabilidades de segurança** (baseadas na OWASP Top 10 e outras falhas comuns) e **exposição de informações sensíveis**, tais como:\n"
                    f"- Chaves de API, chaves secretas ou tokens (ex: `API_KEY`, `secret_key`, `token`, `password`)\n"
                    f"- Endereços IP de servidores ou URLs internas/de desenvolvimento (ex: `192.168.1.1`, `dev.api.internal`, `test.database.com`)\n"
                    f"- Comentários de desenvolvedores que possam conter informações sensíveis (ex: `TODO: remover esta senha`, `FIXME: credenciais hardcoded aqui`, `username: admin / password: 123`)\n"
                    f"- Nomes de diretórios ou caminhos de arquivos internos/sensíveis (ex: `/var/www/backup`, `/admin/dev_tools`, `C:\\secrets\\config.ini`)\n\n"
                    f"**Código para análise:**\n```\n{st.session_state.code_input_content}\n```\n\n"
                    f"Para cada **achado (vulnerabilidade ou informação sensível)** identificado, apresente de forma concisa e prática, utilizando Markdown:\n\n"
                    f"## [Tipo de Achado (Ex: Injeção SQL, Chave de API Exposta, Credenciais em Comentário)]\n"
                    f"**Categoria OWASP (se aplicável):** [Ex: A03: Injection, A05: Security Misconfiguration]. Se for uma informação sensível não OWASP, indique 'Exposição de Informação'.\n"
                    f"**Severidade/Risco:** [Crítica/Alta/Média/Baixa - explique o impacto deste achado específico, tanto para vulnerabilidades quanto para informações expostas]\n"
                    f"**Detalhes no Código:** Explique onde no código a falha/informação foi observada. Inclua o **número da linha aproximado** se possível. Ex: `Linha 5: O parâmetro 'username' é usado diretamente em uma query SQL.`\n"
                    f"**Trecho de Código Afetado:** Forneça o trecho de código exato que contém a falha ou informação sensível. Encapsule-o em um bloco de código Markdown com a linguagem correspondente (ex: ```python, ```javascript, ```java). Este trecho deve ser facilmente identificável no código original.\n\n"
                    f"**Exemplo de PoC/Cenário de Exploração (se aplicável):** Descreva os passos para explorar a vulnerabilidade ou o risco de exposição da informação. Forneça exemplos de payloads, comandos ou trechos de código que demonstrem o problema. Para informações sensíveis, explique como essa exposição pode ser explorada (ex: acesso a sistemas, reconhecimento, pivotagem).\n"
                    f"Encapsule os exemplos de código em blocos de código Markdown (` ```{st.session_state.code_language_selected} ` ou ` ```bash `).\n\n"
                    f"**Ferramentas Sugeridas (se aplicável):** Liste ferramentas que podem ser usadas para explorar ou validar este achado. (Ex: `grep` para buscas de strings, `curl` para testar URLs, `nuclei` para templates, Burp Suite, etc.).\n\n"
                    f"**Recomendação/Mitigação:** Ações concretas para corrigir o problema ou mitigar o risco (ex: usar prepared statements, sanitizar input, remover hardcoded secrets, usar variáveis de ambiente, configurar permissões adequadas).\n\n"
                    f"Se não encontrar vulnerabilidades óbvias ou informações sensíveis, indique isso claramente. Lembre-se, sua análise é uma *primeira linha* e não substitui um SAST completo ou uma revisão de código manual profunda.\n\n"
                )

                code_analysis_raw = obter_resposta_llm(llm_model_text, [code_prompt])

                if code_analysis_raw:
                    st.session_state.code_analysis_result = code_analysis_raw
                else:
                    st.session_state.code_analysis_result = "Não foi possível obter a análise de código. Tente novamente."

    if st.session_state.code_analysis_result:
        st.subheader("Results da Análise de Código")
        st.markdown(st.session_state.code_analysis_result)
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="static_code_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="static_code_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")


def swagger_openapi_analyzer_page(llm_model_vision, llm_model_text):
    st.header("OpenAPI Analyzer: Análise de APIs (Swagger/OpenAPI) 📄")
    st.markdown("""
        Cole o conteúdo de um arquivo OpenAPI (JSON ou YAML) para analisar a especificação da API em busca de:
        - **Vulnerabilidades OWASP API Security Top 10 (2023)**
        - Falhas de design e implementação
        - Exposição de informações sensíveis
        - Boas práticas de segurança e sugestões de melhoria.
    """)

    if 'swagger_input_content' not in st.session_state:
        st.session_state.swagger_input_content = ""
    if 'swagger_analysis_result' not in st.session_state:
        st.session_state.swagger_analysis_result = []
    if 'swagger_analysis_result_display' not in st.session_state:
        st.session_state.swagger_analysis_result_display = ""
    if 'swagger_context_input' not in st.session_state:
        st.session_state.swagger_context_input = ""
    if 'swagger_summary' not in st.session_state:
        st.session_state.swagger_summary = None

    def reset_swagger_analyzer():
        st.session_state.swagger_input_content = ""
        st.session_state.swagger_analysis_result = []
        st.session_state.swagger_analysis_result_display = ""
        st.session_state.swagger_context_input = ""
        st.session_state.swagger_summary = None
        st.rerun()

    if st.button("Limpar Análise OpenAPI", key="reset_swagger_analysis_button"):
        reset_swagger_analyzer()

    swagger_content = st.text_area(
        "Cole o conteúdo do arquivo OpenAPI (JSON ou YAML) aqui:",
        value=st.session_state.swagger_input_content,
        placeholder="Ex: { 'openapi': '3.0.0', 'info': { ... }, 'paths': { ... } }",
        height=400,
        key="swagger_input_area"
    )
    st.session_state.swagger_input_content = swagger_content.strip()

    context_input = st.text_area(
        "Forneça um contexto adicional sobre a API (opcional):",
        value=st.session_state.swagger_context_input,
        placeholder="Ex: 'Esta API é para gerenciamento de usuários', 'É uma API interna para microserviços'",
        key="swagger_context_input_area"
    )
    st.session_state.swagger_context_input = context_input.strip()

    if st.button("Analisar OpenAPI", key="analyze_swagger_button"):
        if not st.session_state.swagger_input_content:
            st.error("Por favor, cole o conteúdo OpenAPI/Swagger para análise.")
        else:
            with st.spinner("Analisando especificação OpenAPI/Swagger..."):
                try:
                    json.loads(st.session_state.swagger_input_content)
                    content_format = "JSON"
                    code_lang = "json"
                except json.JSONDecodeError:
                    try:
                        yaml.safe_load(st.session_state.swagger_input_content)
                        content_format = "YAML"
                        code_lang = "yaml"
                    except yaml.YAMLError:
                        content_format = "TEXTO SIMPLES (formato inválido, análise pode ser limitada)"
                        code_lang = "plaintext"
                        st.warning("O conteúdo colado não parece ser um JSON ou YAML válido. A análise pode ser limitada.")

                swagger_prompt = (
                    f"Você é um especialista em segurança de APIs e pentest, com profundo conhecimento na OWASP API Security Top 10 (2023).\n"
                    f"Sua tarefa é analisar a especificação OpenAPI (Swagger) fornecida ({content_format}) e o contexto adicional, identificando **TODAS as possíveis vulnerabilidades de segurança e falhas de design**.\n"
                    f"\n**RESUMO:** Forneça um resumo quantitativo na PRIMEIRA LINHA da sua resposta, no formato exato: `Total de Vulnerabilidades API: X | Críticas: Y | Altas: Z | Médios: W | Baixas: V` (substitua X,Y,Z,W,V pelos números correspondentes). Se não houver vulnerabilidades, use 0.\n\n"
                    f"Para cada **vulnerabilidade ou falha de design** identificada, apresente de forma concisa e prática, utilizando formato Markdown para títulos e blocos de código:\n\n"
                    f"## [Nome da Vulnerabilidade/Falha de Design]\n"
                    f"**Categoria OWASP API Security Top 10 (2023):** [Ex: API1: Broken Object Level Authorization (BOLA), API8: Security Misconfiguration]. Se não se encaixar diretamente, use 'Falha de Design Geral'.\n"
                    f"**Severidade/Risco:** [Crítica/Alta/Média/Baixa - explique o impacto específico para esta API]\n"
                    f"**Localização na Especificação:** Indique o caminho exato ou uma descrição clara de onde a falha foi observada na especificação OpenAPI (ex: `/paths/{userId}/details GET`, `components/schemas/UserObject`).\n"
                    f"**Detalhes e Explicação:** Explique brevemente a falha, como ela se manifesta nesta especificação e o impacto potencial.\n"
                    f"**Exemplo de Cenário de Ataque/PoC (se aplicável):** Descreva um cenário de ataque que explore essa vulnerabilidade, ou um exemplo de requisição HTTP (com `curl` ou similar) que demonstre o problema. Encapsule em um bloco de código Markdown com linguagem `http` ou `bash` (` ```http `, ` ```bash `).\n"
                    f"**Ferramentas Sugeridas:** Liste ferramentas que podem ser usadas para testar ou validar este achado (ex: Postman, Burp Suite, OWASP ZAP, Kiterunner, FFUF, OpenAPI-fuzzer, Dastardly, etc.).\n"
                    f"**Recomendação/Mitigação:** Ações concretas e específicas para corrigir a vulnerabilidade ou melhorar o design da API, relevantes para a especificação OpenAPI fornecida (ex: adicionar autenticação/autorização, aplicar validação de esquema, limitar taxas).\n\n"
                    f"**Conteúdo da Especificação OpenAPI/Swagger (para sua referência):\n"
                    f"```" + code_lang + f"\n{st.session_state.swagger_input_content}\n```\n\n"
                    f"**Contexto Adicional:** {st.session_state.swagger_context_input if st.session_state.swagger_context_input else 'Nenhum contexto adicional fornecido.'}\n\n"
                    f"Se não encontrar vulnerabilidades ou falhas de design óbvias, indique isso claramente e sugira melhorias gerais de segurança para a API.\n"
                    f"Sua resposta deve ser direta, útil e focada em ações e informações completas para um pentester ou desenvolvedor."
                )

                analysis_result_raw = obter_resposta_llm(llm_model_text, [swagger_prompt])

                if analysis_result_raw:
                    st.session_state.swagger_summary, st.session_state.swagger_analysis_result_display = parse_vulnerability_summary(analysis_result_raw)
                else:
                    st.session_state.swagger_analysis_result_display = "Não foi possível obter a análise da especificação OpenAPI. Tente novamente."
                    st.session_state.swagger_summary = None

    if st.session_state.swagger_analysis_result_display:
        st.subheader("Resultados da Análise OpenAPI")
        if st.session_state.swagger_summary:
            cols = st.columns(5)
            cols[0].metric("Total", st.session_state.swagger_summary["Total"])
            cols[1].metric("Críticas", st.session_state.swagger_summary["Críticas"])
            cols[2].metric("Altas", st.session_state.swagger_summary["Altas"])
            cols[3].metric("Médias", st.session_state.swagger_summary["Médias"])
            cols[4].metric("Baixas", st.session_state.swagger_summary["Baixas"])
            st.markdown("---")
        st.markdown(st.session_state.swagger_analysis_result_display)
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="swagger_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="swagger_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")

EXPLOITDB_ROOT = os.path.join(os.path.dirname(__file__), "ExploitDB")
EXPLOITS_DIR = os.path.join(EXPLOITDB_ROOT, "exploits")
SHELLCODES_DIR = os.path.join(EXPLOITDB_ROOT, "shellcodes")
os.makedirs(EXPLOITDB_ROOT, exist_ok=True) # Garantir que a pasta raiz exista
os.makedirs(EXPLOITS_DIR, exist_ok=True)
os.makedirs(SHELLCODES_DIR, exist_ok=True)


def searchsploit_exploit_page(llm_model_text):
    st.header("Search Exploit 🔍")
    st.markdown("""
        Realize buscas no seu repositório local do Exploit-DB (`exploits/` e `shellcodes/`).
        Encontre Provas de Conceito (PoCs) e, em seguida, peça ao SentinelAI (LLM) para analisar o exploit selecionado,
        fornecendo dicas de exploração, ferramentas recomendadas e informações sobre o impacto.
    """)

    if 'searchsploit_query' not in st.session_state:
        st.session_state.searchsploit_query = ""
    if 'searchsploit_results' not in st.session_state:
        st.session_state.searchsploit_results = []
    if 'selected_exploit_path' not in st.session_state:
        st.session_state.selected_exploit_path = ""
    if 'exploit_content_display' not in st.session_state:
        st.session_state.exploit_content_display = ""
    if 'llm_exploit_analysis_result' not in st.session_state:
        st.session_state.llm_exploit_analysis_result = ""
    if 'selected_exploit_index' not in st.session_state:
        st.session_state.selected_exploit_index = 0

    def reset_searchsploit():
        st.session_state.searchsploit_query = ""
        st.session_state.searchsploit_results = []
        st.session_state.selected_exploit_path = ""
        st.session_state.exploit_content_display = ""
        st.session_state.llm_exploit_analysis_result = ""
        st.session_state.selected_exploit_index = 0
        st.rerun()

    if st.button("Limpar Busca", key="reset_searchsploit_button"):
        reset_searchsploit()

    st.info(f"Certifique-se de que suas pastas 'exploits' e 'shellcodes' do Exploit-DB estão em '{EXPLOITDB_ROOT}'.")
    if not os.path.exists(EXPLOITS_DIR) or not os.path.exists(SHELLCODES_DIR):
        st.warning(f"Diretórios do Exploit-DB não encontrados em '{EXPLOITDB_ROOT}'. A busca pode não retornar resultados.")

    search_query = st.text_input(
        "Termo de Busca (Ex: windows local, apache struts, wordpress plugin):",
        value=st.session_state.searchsploit_query,
        placeholder="Ex: windows local",
        key="searchsploit_query_input"
    )
    st.session_state.searchsploit_query = search_query.strip()

    if st.button("Buscar Exploits", key="perform_searchsploit"):
        if not st.session_state.searchsploit_query:
            st.error("Por favor, digite um termo de busca.")
            st.session_state.searchsploit_results = []
        else:
            st.session_state.searchsploit_results = []
            st.session_state.selected_exploit_path = ""
            st.session_state.exploit_content_display = ""
            st.session_state.llm_exploit_analysis_result = ""

            query_lower = st.session_state.searchsploit_query.lower()
            search_pattern = re.compile(r'\b' + re.escape(query_lower) + r'\b|\b' + re.escape(query_lower), re.IGNORECASE)

            with st.spinner(f"Buscando por '{st.session_state.searchsploit_query}' no Exploit-DB local..."):
                results = []
                # Buscar em exploits
                for root, _, files in os.walk(EXPLOITS_DIR):
                    for file in files:
                        full_path = os.path.join(root, file)
                        relative_path = os.path.relpath(full_path, EXPLOITDB_ROOT)

                        file_content_sample = ""
                        try:
                            # Ler as primeiras linhas para um título ou contexto
                            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                head_lines = [f.readline() for _ in range(10)]
                                file_content_sample = "".join(head_lines).lower()
                                if head_lines and len(head_lines[0].strip()) < 200:
                                    exploit_title = head_lines[0].strip()
                                else:
                                    exploit_title = os.path.basename(file)
                        except Exception:
                            exploit_title = os.path.basename(file)

                        # Check se o termo de busca está no nome do arquivo, caminho relativo ou amostra do conteúdo
                        if search_pattern.search(file.lower()) or \
                           search_pattern.search(relative_path.lower()) or \
                           search_pattern.search(file_content_sample):
                            
                            # Adicionar apenas se ainda não estiver nos resultados (evitar duplicatas)
                            if {"title": exploit_title, "path": relative_path, "full_path": full_path} not in results:
                                results.append({
                                    "title": exploit_title,
                                    "path": relative_path,
                                    "full_path": full_path
                                })
                
                # Buscar em shellcodes (opcional, pode ser removido se não quiser shellcodes na busca)
                for root, _, files in os.walk(SHELLCODES_DIR):
                    for file in files:
                        full_path = os.path.join(root, file)
                        relative_path = os.path.relpath(full_path, EXPLOITDB_ROOT)

                        file_content_sample = ""
                        try:
                            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                head_lines = [f.readline() for _ in range(10)]
                                file_content_sample = "".join(head_lines).lower()
                                if head_lines and len(head_lines[0].strip()) < 200:
                                    exploit_title = head_lines[0].strip()
                                else:
                                    exploit_title = os.path.basename(file)
                        except Exception:
                            exploit_title = os.path.basename(file)

                        if search_pattern.search(file.lower()) or \
                           search_pattern.search(relative_path.lower()) or \
                           search_pattern.search(file_content_sample):
                            
                            if {"title": exploit_title, "path": relative_path, "full_path": full_path} not in results:
                                results.append({
                                    "title": exploit_title,
                                    "path": relative_path,
                                    "full_path": full_path
                                })


                if results:
                    st.session_state.searchsploit_results = sorted(results, key=lambda x: x['path'])
                    st.session_state.selected_exploit_index = 0
                    st.success(f"Encontrados {len(st.session_state.searchsploit_results)} resultados para '{st.session_state.searchsploit_query}'.")
                else:
                    st.info(f"Nenhum exploit ou shellcode encontrado para '{st.session_state.searchsploit_query}'. Verifique o termo ou o caminho do Exploit-DB.")
                    st.session_state.searchsploit_results = []
                    st.session_state.selected_exploit_index = 0


    if st.session_state.searchsploit_results:
        st.markdown("---")
        st.subheader("Resultados da Busca:")

        display_options = [f"Exploit: {res['title']} | Path: {res['path']}" for res in st.session_state.searchsploit_results]

        if st.session_state.selected_exploit_index >= len(display_options):
            st.session_state.selected_exploit_index = 0

        selected_option_index = st.selectbox(
            "Selecione um Exploit para visualizar e analisar:",
            options=range(len(display_options)),
            format_func=lambda x: display_options[x],
            key="exploit_selection_box",
            index=st.session_state.selected_exploit_index
        )
        st.session_state.selected_exploit_index = selected_option_index

        if selected_option_index is not None and st.session_state.searchsploit_results:
            st.session_state.selected_exploit_path = st.session_state.searchsploit_results[selected_option_index]['full_path']

            if st.session_state.selected_exploit_path:
                with st.spinner(f"Carregando conteúdo de '{os.path.basename(st.session_state.selected_exploit_path)}'..."):
                    try:
                        with open(st.session_state.selected_exploit_path, 'r', encoding='utf-8', errors='ignore') as f:
                            st.session_state.exploit_content_display = f.read()
                        st.subheader("Conteúdo do Exploit:")
                        file_ext = os.path.splitext(st.session_state.selected_exploit_path)[1].lower()
                        lang = "text"
                        if file_ext in [".py", ".pyc"]: lang = "python"
                        elif file_ext in [".c", ".h"]: lang = "c"
                        elif file_ext in [".pl"]: lang = "perl"
                        elif file_ext in [".rb"]: lang = "ruby"
                        elif file_ext in [".sh"]: lang = "bash"
                        elif file_ext in [".php"]: lang = "php"
                        elif file_ext in [".js"]: lang = "javascript"
                        elif file_ext in [".ps1"]: lang = "powershell"
                        elif file_ext in [".html", ".htm"]: lang = "html"
                        elif file_ext in [".xml"]: lang = "xml"
                        
                        st.code(st.session_state.exploit_content_display, language=lang)

                    except FileNotFoundError:
                        st.error(f"Arquivo não encontrado: {st.session_state.selected_exploit_path}")
                        st.session_state.exploit_content_display = ""
                    except Exception as e:
                        st.error(f"Erro ao ler o arquivo do exploit: {e}")
                        st.session_state.exploit_content_display = ""
            
            if st.session_state.exploit_content_display and st.button("Analisar Exploit com LLM", key="analyze_exploit_llm_button"):
                with st.spinner("Analisando o exploit com o LLM e gerando dicas..."):
                    llm_exploit_prompt = (
                        f"Você é um especialista em pentest altamente experiente, com autorização para analisar e fornecer orientação sobre exploits."
                        f"Analise o seguinte código de exploit/PoC. Seu objetivo é ajudar um pentester a entender, preparar e executar este exploit de forma eficaz e ética em um ambiente autorizado.\n\n"
                        f"**Código do Exploit/PoC:**\n```\n{st.session_state.exploit_content_display}\n```\n\n"
                        f"**Nome/Caminho Sugerido do Exploit (para contexto):** {st.session_state.selected_exploit_path}\n\n"
                        f"Forneça um relatório detalhado com os seguintes tópicos, utilizando formatação Markdown para clareza:\n\n"
                        f"## 1. Resumo do Exploit e Vulnerabilidade Alvo\n"
                        f"Explique o que este exploit faz, qual vulnerabilidade específica ele visa (ex: RCE, LFI, PrivEsc), e qual o sistema/serviço/aplicação alvo. Mencione a severidade (Crítica/Alta/Média/Baixa) e o impacto potencial. "
                        f"**Tente identificar a(s) CVE(s) associada(s) a esta vulnerabilidade (ex: CVE-YYYY-NNNNN), se possível, ou indique se não houver uma CVE clara.**\n\n"
                        f"## 2. Preparação Necessária\n"
                        f"Quais são os pré-requisitos antes de tentar executar este exploit? (Ex: portas abertas, credenciais, ter acesso a uma shell reversa, instalar bibliotecas Python específicas, ter um serviço vulnerável rodando, etc.). Inclua comandos de instalação ou configuração se aplicável.\n\n"
                        f"## 3. Dicas de Exploração e Parâmetros Chave\n"
                        f"Como este exploit é usado na prática? Quais são os parâmetros mais importantes que o pentester precisa entender e configurar (ex: IP/Porta do alvo, IP/Porta do atacante, nome de usuário/senha, caminho de arquivo, etc.)? Forneça exemplos de uso do comando ou da script, se o exploit for um script.\n\n"
                        f"## 4. Ferramentas Adicionais Sugeridas\n"
                        f"Quais outras ferramentas (Ex: Nmap, Metasploit, Netcat, Wireshark, Burp Suite, debuggers) podem ser úteis antes, durante ou depois da execução deste exploit para reconhecimento, validação, persistência ou análise de tráfego?\n\n"
                        f"## 5. Dicas de Contorno para Firewall/Antivírus/IDS/IPS\n"
                        f"Com base na natureza deste exploit, forneça estratégias, técnicas e exemplos práticos (se aplicável) para contornar ou evadir a detecção de Firewalls, Antivírus, Sistemas de Detecção de Intrusão (IDS) ou Sistemas de Prevenção de Intrusão (IPS). Pense em modificações de payload, codificação, uso de protocolos alternativos, técnicas de tunelamento, ofuscação de tráfego ou tempo de execução.\n\n"
                        f"## 6. Informações a Coletar Após a Execução Bem-Sucedida\n"
                        f"Se o exploit for bem-sucedido, que tipo de informações ou evidências o pentester deve procurar para confirmar a exploração e documentar a falha? (Ex: acesso a shell, arquivos de configuração, credenciais, informações de sistema, listagem de diretórios, dados de banco de dados, etc.).\n\n"
                        f"## 7. Observações Éticas e de Segurança\n"
                        f"É absolutamente crucial obter AUTORIZAÇÃO explícita por escrito do proprietário do sistema antes de executar este ou qualquer outro exploit. Executar este exploit sem autorização é ilegal e pode resultar em consequências legais graves. Além disso, a execução inadequada pode causar instabilidade ou interrupção do serviço alvo, por isso, realize testes apenas em ambientes controlados e autorizados, com backups adequados." # Contexto legal mantido
                    )
                    llm_analysis_raw = obter_resposta_llm(llm_model_text, [llm_exploit_prompt])

                    if llm_analysis_raw:
                        st.session_state.llm_exploit_analysis_result = llm_analysis_raw
                    else:
                        st.session_state.llm_exploit_analysis_result = "Não foi possível analisar o exploit com o LLM. Tente novamente."

    if st.session_state.llm_exploit_analysis_result:
        st.markdown("---")
        st.subheader("Análise do Exploit pelo SentinelAI (LLM):")
        st.markdown(st.session_state.llm_exploit_analysis_result)
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="searchsploit_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="searchsploit_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")


RECON_TOOLS_DIR = os.path.join(os.path.dirname(__file__), "ReconTools")
WORDLIST_DIR = os.path.join(os.path.dirname(__file__), "Wordlist")

os.makedirs(RECON_TOOLS_DIR, exist_ok=True)
os.makedirs(os.path.join(WORDLIST_DIR, "Discovery", "Web-Content"), exist_ok=True)
os.makedirs(os.path.join(WORDLIST_DIR, "Fuzzing"), exist_ok=True)

def execute_tool(command_list, use_shell=False):
    output = ""
    error = ""
    process = None
    try:
        process = subprocess.run(command_list, capture_output=True, text=True, check=False, timeout=600, shell=use_shell)
        output = process.stdout.strip()
        error = process.stderr.strip()
        if process.returncode != 0 and not error:
            error = f"Tool returned non-zero exit code: {process.returncode}"
    except FileNotFoundError:
        exec_name = command_list[0] if isinstance(command_list, list) else command_list.split(" ")[0]
        error = f"ERRO: A ferramenta '{exec_name}' não foi encontrada. Verifique se está em '{RECON_TOOLS_DIR}' ou no PATH."
    except subprocess.CalledProcessError as e:
        error = f"ERRO ao executar a ferramenta: {e.stderr if e.stderr else e.stdout}"
    except subprocess.TimeoutExpired:
        if process:
            process.kill()
        error = "ERRO: A execução da ferramenta excedeu o tempo limite."
    except Exception as e:
        error = f"Um erro inesperado ocorreu: {e}"
    return output, error

def get_command_for_tool(tool_base_name_in_recon_tools, target, output_dir, tool_name_short, input_file=None, gobuster_status_codes_filter=None):
    tool_output_file = os.path.join(output_dir, f"{tool_name_short}_output.txt")

    cmd_list = []

    executable_full_path = os.path.join(RECON_TOOLS_DIR, tool_base_name_in_recon_tools)

    if sys.platform == "win32" and tool_name_short not in ["sublist3r"] and not executable_full_path.endswith(".exe"):
        executable_full_path += ".exe"
    if sys.platform == "win32" and tool_name_short == "sublist3r" and not executable_full_path.endswith(".py"):
        executable_full_path += ".py"

    if tool_name_short == "subfinder":
        cmd_list = [executable_full_path, "-d", target, "-silent", "-o", tool_output_file]
    elif tool_name_short == "ctfr":
        cmd_list = [executable_full_path, "-d", target, "-o", tool_output_file]
    elif tool_name_short == "sublist3r":
        cmd_list = ["python3", executable_full_path, "-d", target, "-o", tool_output_file]
    elif tool_name_short == "tlsx":
        if input_file and os.path.exists(input_file) and os.path.getsize(input_file) > 0:
            cmd_list = [executable_full_path, "-l", input_file, "-o", tool_output_file, "-cn", "-san", "-silent"]
        else:
            cmd_list = [executable_full_path, "-u", target, "-o", tool_output_file, "-cn", "-san", "-silent"]
    elif tool_name_short == "netlas":
        if not NETLAS_API_KEY:
            st.error("NETLAS_API_KEY não configurada no .env para Netlas.")
            return []
        cmd_list = [executable_full_path, "subdomains", "--query", target, "--api-key", NETLAS_API_KEY, "--output", tool_output_file]
    elif tool_name_short == "naabu":
        cmd_list = [executable_full_path, "-host", target, "-p", "top-100", "-silent", "-o", tool_output_file]
    elif tool_name_short == "httpx":
        if input_file and os.path.exists(input_file) and os.path.getsize(input_file) > 0:
            cmd_list = [executable_full_path, "-l", input_file, "-silent", "-sc", "-title", "-o", tool_output_file]
        else:
            cmd_list = [executable_full_path, "-u", target, "-silent", "-sc", "-title", "-o", tool_output_file]
    elif tool_name_short == "katana":
        if input_file and os.path.exists(input_file) and os.path.getsize(input_file) > 0:
            cmd_list = [executable_full_path, "-l", input_file, "-silent", "-d", "3", "-o", tool_output_file]
        else:
            cmd_list = [executable_full_path, "-u", target, "-silent", "-d", "3", "-o", tool_output_file]
    elif tool_name_short == "gau":
        if input_file and os.path.exists(input_file) and os.path.getsize(input_file) > 0:
            cmd_list = [executable_full_path, "-f", input_file, "-o", tool_output_file]
        else:
            cmd_list = [executable_full_path, target, "-o", tool_output_file]
    elif tool_name_short == "nuclei":
        if input_file and os.path.exists(input_file) and os.path.getsize(input_file) > 0:
             cmd_list = [executable_full_path, "-l", input_file, "-silent", "-tags", "cve,misconfig,exposure", "-o", tool_output_file]
        else:
            cmd_list = [executable_full_path, "-u", target, "-silent", "-tags", "cve,misconfig,exposure", "-o", tool_output_file]
    elif tool_name_short == "gobuster":
        wordlist_path = os.path.join(WORDLIST_DIR, "Discovery", "Web-Content", "big.txt")
        if not os.path.exists(wordlist_path):
            st.error(f"Wordlist para GoBuster não encontrada: {wordlist_path}")
            return []

        cmd_list = [executable_full_path, "dir", "-u", target, "-w", wordlist_path, "-q", "-o", tool_output_file]
        cmd_list.extend(["-b", "301,302,404,429,500"])

    elif tool_name_short == "ffuf":
        wordlist_path = os.path.join(WORDLIST_DIR, "Fuzzing", "fuzz.txt")
        if not os.path.exists(wordlist_path):
            st.error(f"Wordlist para ffuf não encontrada: {wordlist_path}")
            return []
        cmd_list = [executable_full_path, "-u", f"{target}/FUZZ", "-w", wordlist_path, "-mc", "200", "-o", tool_output_file]

    return cmd_list

def active_recon_page(llm_model_vision, llm_model_text):
    st.header("Advanced Reconnaissance 🌐")
    st.markdown("""
        Realize diferentes tipos de reconhecimento ativo (subdomínios, portas, HTTP) para um alvo.
        O SentinelAI orquestrará ferramentas CLI e, em seguida, o LLM analisará os resultados
        para fornecer insights de segurança, identificar vulnerabilidades e sugerir próximos passos.
    """)

    if 'recon_target' not in st.session_state:
        st.session_state.recon_target = ""
    if 'selected_recon_tools' not in st.session_state:
        st.session_state.selected_recon_tools = []
    if 'recon_results_output' not in st.session_state:
        st.session_state.recon_results_output = ""
    if 'recon_llm_analysis' not in st.session_state:
        st.session_state.recon_llm_analysis = ""
    if 'recon_summary' not in st.session_state:
        st.session_state.recon_summary = None
    if 'recon_context_objective' not in st.session_state:
        st.session_state.recon_context_objective = ""
    if 'httpx_status_codes_filter' not in st.session_state:
        st.session_state.httpx_status_codes_filter = ["200", "403", "500"]

    def reset_active_recon():
        st.session_state.recon_target = ""
        st.session_state.selected_recon_tools = []
        st.session_state.recon_results_output = ""
        st.session_state.recon_llm_analysis = ""
        st.session_state.recon_summary = None
        st.session_state.recon_context_objective = ""
        st.session_state.httpx_status_codes_filter = ["200", "403", "500"]
        st.rerun()

    if st.button("Limpar Reconhecimento", key="reset_active_recon_button"):
        reset_active_recon()

    target_input = st.text_input(
        "Alvo (Domínio ou IP/Range, ex: example.com ou 192.168.1.0/24):",
        value=st.session_state.recon_target,
        placeholder="Ex: culturainglesa.com.br",
        key="recon_target_input"
    )
    st.session_state.recon_target = target_input.strip()

    recon_context_objective_input = st.text_area(
        "Contexto / Objetivo do Reconhecimento (Opcional, para refinar a análise do LLM):",
        value=st.session_state.recon_context_objective,
        placeholder="Ex: 'Procurar por subdomínios antigos ou esquecidos', 'Identificar endpoints de API', 'Descobrir painéis de administração expostos.'",
        key="recon_context_objective_input"
    )
    st.session_state.recon_context_objective = recon_context_objective_input.strip()

    st.markdown("---")
    st.subheader("Ferramentas de Reconhecimento CLI")
    st.info("Para usar estas ferramentas, elas devem estar instaladas na pasta 'ReconTools' do seu projeto SentinelAI, e as wordlists na pasta 'Wordlist'.")

    RECON_TOOLS_DIR = os.path.join(os.path.dirname(__file__), "ReconTools")
    WORDLIST_DIR = os.path.join(os.path.dirname(__file__), "Wordlist")

    os.makedirs(RECON_TOOLS_DIR, exist_ok=True)
    os.makedirs(os.path.join(WORDLIST_DIR, "Discovery", "Web-Content"), exist_ok=True)
    os.makedirs(os.path.join(WORDLIST_DIR, "Fuzzing"), exist_ok=True)

    def check_tool_installation(tool_name):
        tool_path_base = os.path.join(RECON_TOOLS_DIR, tool_name)
        
        if sys.platform == "win32":
            tool_path_exe = tool_path_base + ".exe"
            if os.path.exists(tool_path_exe):
                try:
                    if tool_name == "netlas":
                        return True
                    subprocess.run([tool_path_exe, "-h"], capture_output=True, check=True, text=True, timeout=2)
                    return True
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                    pass
            
            if tool_name == "sublist3r": 
                tool_path_py = tool_path_base + ".py"
                if os.path.exists(tool_path_py):
                    try:
                        subprocess.run(["python3", tool_path_py, "-h"], capture_output=True, check=True, text=True, timeout=2)
                        return True
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                        pass
            
            if tool_name == "netlas" and os.path.exists(tool_path_base): 
                return True

        else:
            if os.path.exists(tool_path_base):
                try:
                    if tool_name == "sublist3r":
                        subprocess.run(["python3", tool_path_base, "-h"], capture_output=True, check=True, text=True, timeout=2)
                    elif tool_name == "netlas":
                         if os.path.exists(tool_path_base): return True 
                    else:
                        subprocess.run([tool_path_base, "-h"], capture_output=True, check=True, text=True, timeout=2)
                    return True
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                    pass
        return False

    all_recon_tools = {
        "Subfinder (Subdomínios)": "subfinder",
        "CTFR (Certificate Transparency)": "ctfr", 
        "Sublist3r (Multi-Engine)": "sublist3r", 
        "TLSX (TLS Certificate Info)": "tlsx", 
        "Netlas (API Recon)": "netlas", 
        "Naabu (Port Scan)": "naabu",
        "Httpx (HTTP Prober)": "httpx",
        "Nuclei (Vulnerabilidade Templates)": "nuclei",
        "GoBuster (Dir/File/VHost Brute-force)": "gobuster",
        "ffuf (Web Fuzzer)": "ffuf",
        "Katana (Crawler/Scraper)": "katana",
        "Gau (Get All URLs)": "gau",
    }

    available_tools = {}
    st.markdown("#### Selecione as ferramentas a serem executadas:")
    cols_tools = st.columns(3)
    idx = 0
    
    current_selected_from_ui = []
    for tool_display_name, tool_cmd_short_name in all_recon_tools.items():
        is_installed = check_tool_installation(tool_cmd_short_name)
        
        checkbox_label = f"✅ {tool_display_name}" if is_installed else f"❌ {tool_display_name} (Não Encontrado)"
        
        selected = cols_tools[idx % 3].checkbox(checkbox_label, value=(tool_cmd_short_name in st.session_state.selected_recon_tools), disabled=not is_installed, key=f"tool_checkbox_{tool_cmd_short_name}")
        
        if selected:
            current_selected_from_ui.append(tool_cmd_short_name)
        
        available_tools[tool_cmd_short_name] = is_installed
        idx += 1
    
    st.session_state.selected_recon_tools = current_selected_from_ui

    if "httpx" in st.session_state.selected_recon_tools:
        st.markdown("#### Opções para HTTPX:")
        selected_httpx_status_codes = st.multiselect(
            "Filtrar resultados do HTTPX por Status Code (para análise do LLM):",
            options=["200", "403", "500", "401", "301", "302", "Other"],
            default=st.session_state.httpx_status_codes_filter,
            help="O LLM priorizará a análise de URLs com esses status codes. O HTTPX rodará normalmente."
        )
        st.session_state.httpx_status_codes_filter = selected_httpx_status_codes

    if st.button("Iniciar Reconhecimento Ativo", key="start_active_recon_button"):
        if not st.session_state.recon_target:
            st.error("Por favor, digite o alvo para iniciar o reconhecimento.")
        elif not st.session_state.selected_recon_tools:
            st.error("Por favor, selecione pelo menos uma ferramenta de reconhecimento.")
        else:
            st.session_state.recon_results_output = "" 
            st.session_state.recon_llm_analysis = ""
            st.session_state.recon_summary = None
            
            individual_tool_outputs = [] 
            
            sanitized_target_name = re.sub(r'[\\/:*?"<>|]', '_', st.session_state.recon_target).replace('.', '_')
            
            current_time_str = time.strftime("%Y%m%d-%H%M%S")
            scan_id = f"{sanitized_target_name}_{current_time_str}_{str(uuid.uuid4())[:8]}" 
            scan_results_dir = os.path.join(os.path.dirname(__file__), "scan_results", scan_id)
            os.makedirs(scan_results_dir, exist_ok=True)

            temp_subdomain_files = {
                "subfinder": os.path.join(scan_results_dir, "subdomains_subfinder.txt"),
                "ctfr": os.path.join(scan_results_dir, "subdomains_ctfr.txt"),
                "sublist3r": os.path.join(scan_results_dir, "subdomains_sublist3r.txt"),
                "tlsx": os.path.join(scan_results_dir, "subdomains_tlsx.txt"),
                "netlas": os.path.join(scan_results_dir, "subdomains_netlas.txt"),
                "naabu": os.path.join(scan_results_dir, "naabu_hosts.txt")
            }
            combined_hosts_for_http_tools_file = os.path.join(scan_results_dir, "combined_hosts_for_http_tools.txt")
            httpx_live_urls_file = os.path.join(scan_results_dir, "httpx_live_urls.txt")
            combined_urls_for_vulnerability_scan_file = os.path.join(scan_results_dir, "combined_urls_for_vulnerability_scan.txt")
            
            pipeline_stages = {
                "subdomain_and_host_discovery": ["subfinder", "ctfr", "sublist3r", "tlsx", "netlas", "naabu"],
                "http_probing": ["httpx"],
                "url_crawling_and_gathering": ["katana", "gau"],
                "vulnerability_scanning": ["nuclei"],
                "directory_and_fuzzing": ["gobuster", "ffuf"] 
            }

            any_subdomain_tool_selected = any(tool in st.session_state.selected_recon_tools for tool in pipeline_stages["subdomain_and_host_discovery"])
            if any_subdomain_tool_selected: 
                st.markdown("### Etapa 1: Descoberta de Subdomínios e Hosts")
                for tool_cmd_short in pipeline_stages["subdomain_and_host_discovery"]:
                    if tool_cmd_short in st.session_state.selected_recon_tools:
                        tool_display_name = ""
                        for k, v in all_recon_tools.items():
                            if v == tool_cmd_short: 
                                tool_display_name = k
                                break

                        if not available_tools.get(tool_cmd_short, False):
                            st.warning(f"Pulando {tool_display_name} ({tool_cmd_short}): Não está instalado ou no PATH.")
                            continue

                        st.subheader(f"Executando {tool_display_name}...")
                        with st.spinner(f"Executando {tool_cmd_short} para {st.session_state.recon_target}..."):
                            tool_base_name_for_path = tool_cmd_short
                            
                            command_list = get_command_for_tool(
                                tool_base_name_for_path, 
                                st.session_state.recon_target, 
                                scan_results_dir, 
                                tool_cmd_short, 
                                input_file=None 
                            )
                            
                            if command_list:
                                output, error = execute_tool(command_list) 
                                
                                tool_report_content = ""
                                output_file_path = temp_subdomain_files.get(tool_cmd_short) 
                                if os.path.exists(output_file_path):
                                    with open(output_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                        tool_report_content = f.read().strip()
                                
                                final_display_content = tool_report_content if tool_report_content else (error if error else "Nenhum output ou erro da ferramenta.")

                                individual_tool_outputs.append({
                                    "name": tool_display_name,
                                    "command": " ".join(command_list), 
                                    "output": final_display_content,
                                    "error": error
                                })
                                
                                if error:
                                    st.error(f"Erro na execução de {tool_display_name}. Veja o expander abaixo para detalhes.")
                                else:
                                    st.success(f"{tool_display_name} concluído.")
                            else:
                                st.warning(f"Comando para {tool_display_name} não pôde ser gerado ou a ferramenta não foi executada.")
                
                unique_hosts = set()
                for file_path in temp_subdomain_files.values():
                    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                host = line.strip()
                                if host:
                                    unique_hosts.add(host)
                
                if unique_hosts:
                    with open(combined_hosts_for_http_tools_file, 'w') as f:
                        for host in sorted(list(unique_hosts)):
                            f.write(f"{host}\n")
                    st.info(f"Consolidado {len(unique_hosts)} hosts/subdomínios únicos em '{os.path.basename(combined_hosts_for_http_tools_file)}' para análise HTTP.")
                elif any_subdomain_tool_selected: 
                    st.warning(f"Nenhum host/subdomínio encontrado pelas ferramentas de descoberta selecionadas. Próximas etapas dependentes podem ter resultados limitados.")
            else:
                st.info("Nenhuma ferramenta de descoberta de subdomínios/hosts selecionada. Esta etapa será pulada.") 

            if "httpx" in st.session_state.selected_recon_tools:
                st.markdown("### Etapa 2: Probing HTTP (HTTPX)")
                tool_display_name = all_recon_tools["Httpx (HTTP Prober)"]
                tool_cmd_short = "httpx"
                if available_tools.get(tool_cmd_short, False):
                    st.subheader(f"Executando {tool_display_name}...")
                    with st.spinner(f"Executando {tool_cmd_short}..."):
                        tool_base_name_for_path = tool_cmd_short
                        
                        command_list = get_command_for_tool(
                            tool_base_name_for_path, 
                            st.session_state.recon_target, 
                            scan_results_dir, 
                            tool_cmd_short, 
                            input_file=combined_hosts_for_http_tools_file if os.path.exists(combined_hosts_for_http_tools_file) and os.path.getsize(combined_hosts_for_http_tools_file) > 0 else None
                        )
                        
                        if command_list:
                            output, error = execute_tool(command_list)
                            tool_report_content = ""
                            if os.path.exists(httpx_live_urls_file):
                                with open(httpx_live_urls_file, 'r', encoding='utf-8', errors='ignore') as f:
                                    tool_report_content = f.read().strip()
                            
                            final_display_content = tool_report_content if tool_report_content else (error if error else "Nenhum output ou erro da ferramenta.")
                            
                            individual_tool_outputs.append({
                                "name": tool_display_name,
                                "command": " ".join(command_list),
                                "output": final_display_content,
                                "error": error
                            })

                            if error:
                                st.error(f"Erro na execução de {tool_display_name}. Veja o expander abaixo para detalhes.")
                            else:
                                st.success(f"{tool_display_name} concluído. {len(tool_report_content.splitlines())} URLs ativas encontradas.")
                        else:
                            st.warning(f"Comando para {tool_display_name} não pôde ser gerado ou a ferramenta não foi executada.")
                else:
                    st.warning(f"Pulando HTTPX: Não está instalado ou no PATH.")
            else:
                st.info("HTTPX não selecionado. Esta etapa será pulada.")


            any_crawler_tool_selected = any(tool in st.session_state.selected_recon_tools for tool in pipeline_stages["url_crawling_and_gathering"])
            if any_crawler_tool_selected: 
                st.markdown("### Etapa 3: Coleta de URLs Adicionais (Crawlers)")
                crawler_outputs = []
                for tool_cmd_short in pipeline_stages["url_crawling_and_gathering"]:
                    if tool_cmd_short in st.session_state.selected_recon_tools:
                        tool_display_name = ""
                        for k, v in all_recon_tools.items():
                            if v == tool_cmd_short:
                                tool_display_name = k
                                break

                        if not available_tools.get(tool_cmd_short, False):
                            st.warning(f"Pulando {tool_display_name} ({tool_cmd_short}): Não está instalado ou no PATH.")
                            continue
                        
                        st.subheader(f"Executando {tool_display_name}...")
                        with st.spinner(f"Executando {tool_cmd_short}..."):
                            tool_base_name_for_path = tool_cmd_short
                            
                            command_list = get_command_for_tool(
                                tool_base_name_for_path, 
                                st.session_state.recon_target, 
                                scan_results_dir, 
                                tool_cmd_short, 
                                input_file=httpx_live_urls_file if os.path.exists(httpx_live_urls_file) and os.path.getsize(httpx_live_urls_file) > 0 else None
                            )
                            
                            if command_list:
                                output, error = execute_tool(command_list)
                                current_tool_output_file = os.path.join(scan_results_dir, f"{tool_cmd_short}_output.txt")
                                tool_report_content = ""
                                if os.path.exists(current_tool_output_file):
                                    with open(current_tool_output_file, 'r', encoding='utf-8', errors='ignore') as f:
                                        tool_report_content = f.read().strip()
                                
                                final_display_content = tool_report_content if tool_report_content else (error if error else "Nenhum output ou erro da ferramenta.")
                                
                                individual_tool_outputs.append({
                                    "name": tool_display_name,
                                    "command": " ".join(command_list),
                                    "output": final_display_content,
                                    "error": error
                                })
                                crawler_outputs.append(tool_report_content)

                                if error:
                                    st.error(f"Erro na execução de {tool_display_name}. Veja o expander abaixo para detalhes.")
                                else:
                                    st.success(f"{tool_display_name} concluído.")
                            else:
                                st.warning(f"Comando para {tool_display_name} não pôde ser gerado ou a ferramenta não foi executada.")
                
                all_crawled_urls = set()
                for output_content in crawler_outputs:
                    for line in output_content.splitlines():
                        url = line.strip()
                        if url:
                            all_crawled_urls.add(url)
                
                if all_crawled_urls:
                    with open(combined_urls_for_vulnerability_scan_file, 'w') as f:
                        for url in sorted(list(all_crawled_urls)):
                            f.write(f"{url}\n")
                    st.info(f"Consolidado {len(all_crawled_urls)} URLs únicas em '{os.path.basename(combined_urls_for_vulnerability_scan_file)}' para varredura de vulnerabilidades.")
                elif any_crawler_tool_selected: 
                    st.warning("Nenhuma URL adicional encontrada pelas ferramentas de coleta de URLs selecionadas. Varredura de vulnerabilidades pode ter resultados limitados.")
            else:
                st.info("Nenhuma ferramenta de coleta de URLs selecionada. Esta etapa será pulada.")


            if "nuclei" in st.session_state.selected_recon_tools:
                st.markdown("### Etapa 4: Varredura de Vulnerabilidades (Nuclei)")
                tool_display_name = all_recon_tools["Nuclei (Vulnerabilidade Templates)"]
                tool_cmd_short = "nuclei"
                if available_tools.get(tool_cmd_short, False):
                    st.subheader(f"Executando {tool_display_name}...")
                    with st.spinner(f"Executando {tool_cmd_short}..."):
                        tool_base_name_for_path = tool_cmd_short
                        
                        command_list = get_command_for_tool(
                            tool_base_name_for_path, 
                            st.session_state.recon_target, 
                            scan_results_dir, 
                            tool_cmd_short, 
                            input_file=combined_urls_for_vulnerability_scan_file if os.path.exists(combined_urls_for_vulnerability_scan_file) and os.path.getsize(combined_urls_for_vulnerability_scan_file) > 0 else None
                        )
                        
                        if command_list:
                            output, error = execute_tool(command_list)
                            current_tool_output_file = os.path.join(scan_results_dir, f"{tool_cmd_short}_output.txt")
                            tool_report_content = ""
                            if os.path.exists(current_tool_output_file):
                                with open(current_tool_output_file, 'r', encoding='utf-8', errors='ignore') as f:
                                    tool_report_content = f.read().strip()
                            
                            final_display_content = tool_report_content if tool_report_content else (error if error else "Nenhum output ou erro da ferramenta.")
                            
                            individual_tool_outputs.append({
                                "name": tool_display_name,
                                "command": " ".join(command_list),
                                "output": final_display_content,
                                "error": error
                            })

                            if error:
                                st.error(f"Erro na execução de {tool_display_name}. Veja o expander abaixo para detalhes.")
                            else:
                                st.success(f"{tool_display_name} concluído.")
                        else:
                            st.warning(f"Comando para {tool_display_name} não pôde ser gerado ou a ferramenta não foi executada.")
                else:
                    st.info(f"Nuclei não selecionado. Esta etapa será pulada.")

            any_brute_force_tool_selected = any(tool in st.session_state.selected_recon_tools for tool in pipeline_stages["directory_and_fuzzing"])
            if any_brute_force_tool_selected: 
                st.markdown("### Etapa 5: Brute-force e Fuzzing")
                for tool_cmd_short in pipeline_stages["directory_and_fuzzing"]:
                    if tool_cmd_short in st.session_state.selected_recon_tools:
                        tool_display_name = ""
                        for k, v in all_recon_tools.items():
                            if v == tool_cmd_short:
                                tool_display_name = k
                                break

                        if not available_tools.get(tool_cmd_short, False):
                            st.warning(f"Pulando {tool_display_name} ({tool_cmd_short}): Não está instalado ou no PATH.")
                            continue

                        st.subheader(f"Executando {tool_display_name}...")
                        with st.spinner(f"Executando {tool_cmd_short}..."):
                            tool_base_name_for_path = tool_cmd_short
                            
                            gobuster_filter_arg = None 

                            command_list = get_command_for_tool(
                                tool_base_name_for_path, 
                                st.session_state.recon_target, 
                                scan_results_dir, 
                                tool_cmd_short, 
                                input_file=None, 
                                gobuster_status_codes_filter=gobuster_filter_arg 
                            )
                            
                            if command_list:
                                output, error = execute_tool(command_list)
                                current_tool_output_file = os.path.join(scan_results_dir, f"{tool_cmd_short}_output.txt")
                                tool_report_content = ""
                                if os.path.exists(current_tool_output_file):
                                    with open(current_tool_output_file, 'r', encoding='utf-8', errors='ignore') as f:
                                        tool_report_content = f.read().strip()
                                
                                final_display_content = tool_report_content if tool_report_content else (error if error else "Nenhum output ou erro da ferramenta.")
                                
                                individual_tool_outputs.append({
                                    "name": tool_display_name,
                                    "command": " ".join(command_list),
                                    "output": final_display_content,
                                    "error": error
                                })

                                if error:
                                    st.error(f"Erro na execução de {tool_display_name}. Veja o expander abaixo para detalhes.")
                                else:
                                    st.success(f"{tool_display_name} concluído.")
                            else:
                                st.warning(f"Comando para {tool_display_name} não pôde ser gerado ou a ferramenta não foi executada.")
            else:
                st.info("Nenhuma ferramenta de força bruta/fuzzing selecionada. Esta etapa será pulada.")
            
            final_consolidated_output_for_download = ""
            for tool_data in individual_tool_outputs:
                final_consolidated_output_for_download += f"--- Output de {tool_data['name']} (Comando: {tool_data['command']}) ---\n"
                final_consolidated_output_for_download += tool_data['output'] + "\n\n"
                if tool_data['error']:
                    final_consolidated_output_for_download += f"--- STDERR/ERROR de {tool_data['name']} ---\n"
                    final_consolidated_output_for_download += tool_data['error'] + "\n\n"
            st.session_state.recon_results_output = final_consolidated_output_for_download

            st.markdown("---")
            st.subheader("Outputs Detalhados das Ferramentas:")
            if individual_tool_outputs:
                for tool_data in individual_tool_outputs:
                    command_str = tool_data['command'] 
                    with st.expander(f"Output de {tool_data['name']} (Comando: `{command_str}`)", expanded=False):
                        if tool_data['output']:
                            st.code(tool_data['output'], language="bash")
                        if tool_data['error']:
                            st.error(f"Erro/Stderr: {tool_data['error']}")
                        if not tool_data['output'] and not tool_data['error']:
                            st.info("Nenhum resultado ou erro registrado para esta ferramenta.")
            else:
                st.info("Nenhum resultado de ferramenta para exibir.")

            if st.session_state.recon_results_output:
                st.download_button(
                    label="Download Output Bruto Consolidado (.txt)",
                    data=st.session_state.recon_results_output.encode('utf-8'),
                    file_name=f"recon_output_{sanitized_target_name}_{current_time_str}_{str(uuid.uuid4())[:8]}.txt", 
                    mime="text/plain",
                    help="Baixa um arquivo de texto com os resultados brutos de todas as ferramentas executadas."
                )
            
            if st.session_state.recon_results_output.strip() and "ERRO" not in st.session_state.recon_results_output:
                with st.spinner("Analisando resultados agregados com LLM para insights de segurança..."):
                    llm_prompt = (
                        f"Você é um especialista em pentest e reconhecimento, analisando resultados de várias ferramentas de linha de comando para o alvo '{st.session_state.recon_target}'. "
                        f"Seu objetivo é correlacionar os dados brutos fornecidos por ferramentas como Subfinder, Naabu, Httpx, Nuclei, GoBuster, ffuf, Katana e Gau, e extrair insights de segurança acionáveis. "
                        f"Identifique padrões, tecnologias expostas, vulnerabilidades potenciais (mapeando para OWASP Top 10 se aplicável), e sugira próximos passos para um pentester.\n"
                        f"\n**Contexto/Objetivo do Reconhecimento Fornecido pelo Usuário:** {st.session_state.recon_context_objective if st.session_state.recon_context_objective else 'Nenhum contexto adicional fornecido.'}\n"
                        f"\n**Instruções Específicas para HTTPX:** O usuário demonstrou interesse particular em status codes HTTP {', '.join(st.session_state.httpx_status_codes_filter)}. Priorize a análise e interpretação de URLs que retornaram esses status, explicando o potencial de segurança e próximos passos para cada um."
                        f"\n**Resultados Agregados das Ferramentas CLI:**\n```\n{st.session_state.recon_results_output}\n```\n\n"
                        f"**RESUMO:** Forneça um resumo quantitativo na PRIMEIRA LINHA da sua resposta, no formato exato: `Total de Insights: X | Críticos: Y | Altos: Z | Médios: W | Baixas: V` (substitua X,Y,Z,W,V pelos números correspondentes). Se não houver insights óbvios, use 0.\n\n"
                        f"Para cada insight identificado, use o formato Markdown, incluindo:\n\n"
                        f"## Insight: [Nome do Insight/Vulnerabilidade Potencial] (Ex: Subdomínio de Desenvolvimento Exposto, Porta de Serviço Vulnerável, Falha de Configuração de HTTP)\n"
                        f"**Severidade/Risco Potencial:** [Crítica/Alta/Média/Baixa/Informativo]\n"
                        f"**Dados Relacionados:** Cite os trechos dos resultados brutos que levaram a este insight (ex: 'subdomínio dev.target.com encontrado pelo Subfinder', 'porta 8080 aberta e serviço Jenkins detectado pelo Naabu/Httpx').\n"
                        f"**Explicação/Implicação de Segurança:** Explique a implicação de segurança deste achado. Mapeie para OWASP Top 10 (2021) se for aplicável. Por exemplo, um diretório '.git' exposto é uma 'A05: Security Misconfiguration'. Para status codes HTTP, interprete o significado de segurança (ex: 403 pode indicar bypass, 500 pode indicar exposição de erros/informações).\n"
                        f"**Próximos Passos para Pentest & Ferramentas Sugeridas:** Descreva ações concretas para validar ou explorar este insight. Sugira ferramentas específicas (ex: 'Acessar URL no navegador', 'Usar Nmap NSE scripts', 'Tentar autenticação padrão com Hydra', 'Fuzzing com ffuf', 'Burp Suite Intruder'). Forneça exemplos de comandos ou payloads se for direto.\n\n"
                        f"Se não houver insights de segurança óbvios ou se os dados forem insuficientes, indique isso claramente e sugira que mais reconhecimento ou um escaneamento mais profundo é necessário."
                    )
                    
                    llm_analysis_raw = obter_resposta_llm(llm_model_text, [llm_prompt])

                    if llm_analysis_raw:
                        st.session_state.recon_summary, st.session_state.recon_llm_analysis = parse_vulnerability_summary(llm_analysis_raw)
                        if not isinstance(st.session_state.recon_summary, dict) or \
                           any(key not in st.session_state.recon_summary for key in ["Total", "Críticas", "Altas", "Médias", "Baixas"]):
                            st.warning("O LLM não conseguiu gerar o resumo de insights no formato esperado. As métricas podem não ser exibidas corretamente.")
                            st.session_state.recon_summary = {
                                "Total": 0, "Críticas": 0, "Altas": 0, "Médias": 0, "Baixas": 0
                            }
                    else:
                        st.session_state.recon_llm_analysis = "Não foi possível obter insights do LLM sobre os resultados agregados."
                        st.session_state.recon_summary = None
            else:
                st.session_state.recon_llm_analysis = "Nenhum output válido de ferramentas para analisar com o LLM."
                st.session_state.recon_summary = None
    
    if st.session_state.recon_llm_analysis:
        st.markdown("---")
        st.subheader("Insights do LLM sobre o Reconhecimento:")
        if st.session_state.recon_summary and isinstance(st.session_state.recon_summary, dict):
            cols = st.columns(5)
            cols[0].metric("Total", st.session_state.recon_summary.get("Total", 0))
            cols[1].metric("Críticos", st.session_state.recon_summary.get("Críticos", 0))
            cols[2].metric("Altos", st.session_state.recon_summary.get("Altos", 0))
            cols[3].metric("Médios", st.session_state.recon_summary.get("Médios", 0))
            cols[4].metric("Baixas", st.session_state.recon_summary.get("Baixas", 0))
            st.markdown("---")
        else:
             st.warning("Não foi possível exibir o resumo dos insights. Formato inesperado do LLM.")
        st.markdown(st.session_state.recon_llm_analysis)
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="recon_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="recon_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")


def tactical_command_orchestrator_page(llm_model_text):
    st.header("Tactical Command Orchestrator 🤖")
    st.markdown("""
        Descreva o seu cenário de pentest, o alvo, e qual ferramenta ou tipo de ação você precisa.
        O SentinelAI irá sugerir os comandos mais eficazes e otimizados, adaptados ao seu ambiente e objetivo.
    """)

    if 'command_scenario_input' not in st.session_state:
        st.session_state.command_scenario_input = ""
    if 'command_analysis_result' not in st.session_state:
        st.session_state.command_analysis_result = ""
    if 'command_tool_selection' not in st.session_state:
        st.session_state.command_tool_selection = "Qualquer Ferramenta"
    if 'command_os_selection' not in st.session_state:
        st.session_state.command_os_selection = "Linux/macOS (Bash)"

    def reset_command_orchestrator():
        st.session_state.command_scenario_input = ""
        st.session_state.command_analysis_result = ""
        st.session_state.command_tool_selection = "Qualquer Ferramenta"
        st.session_state.command_os_selection = "Linux/macOS (Bash)"
        st.rerun()

    if st.button("Limpar Orquestrador", key="reset_command_orchestrator_button"):
        reset_command_orchestrator()

    scenario_input = st.text_area(
        "Descreva o cenário e seu objetivo (Ex: 'Preciso de um comando Nmap para escanear portas UDP em 192.168.1.100', 'Como faço um brute-force de login em um formulário web com Hydra?'):",
        value=st.session_state.command_scenario_input,
        placeholder="Ex: Escanear portas TCP em um host, encontrar diretórios ocultos, criar payload de shell reverso.",
        height=150,
        key="command_scenario_input_area"
    )
    st.session_state.command_scenario_input = scenario_input.strip()

    tool_options = [
        "Qualquer Ferramenta", "Nmap", "Metasploit", "Burp Suite (comandos curl/HTTP)",
        "SQLmap", "Hydra", "ffuf", "Nuclei", "Subfinder", "Httpx", "Other"
    ]
    selected_tool = st.selectbox(
        "Ferramenta Preferida (Opcional):",
        options=tool_options,
        index=tool_options.index(st.session_state.command_tool_selection),
        key="command_tool_select"
    )
    st.session_state.command_tool_selection = selected_tool

    os_options = ["Linux/macOS (Bash)", "Windows (PowerShell/CMD)"]
    selected_os = st.selectbox(
        "Sistema Operacional para o Comando:",
        options=os_options,
        index=os_options.index(st.session_state.command_os_selection),
        key="command_os_select"
    )
    st.session_state.command_os_selection = selected_os

    if st.button("Gerar Comando Tático", key="generate_command_button"):
        if not st.session_state.command_scenario_input:
            st.error("Por favor, descreva o cenário para gerar o comando.")
        else:
            with st.spinner("Gerando comando tático otimizado..."):
                target_tool_text = f"Usando a ferramenta '{st.session_state.command_tool_selection}'." if st.session_state.command_tool_selection != "Qualquer Ferramenta" else ""
                target_os_text = f"O comando deve ser para o sistema operacional '{st.session_state.command_os_selection}'."

                command_prompt = (
                    f"Você é um especialista em pentest e automação, com vasto conhecimento em ferramentas de linha de comando. "
                    f"Sua tarefa é gerar um comando de linha de comando preciso e otimizado para o seguinte cenário:\n"
                    f"**Cenário do Usuário:** '{st.session_state.command_scenario_input}'.\n"
                    f"{target_tool_text}\n"
                    f"{target_os_text}\n\n"
                    f"Forneça as seguintes informações em Markdown:\n\n"
                    f"## 1. Comando Sugerido\n"
                    f"Apresente o comando COMPLETO e PRONTO PARA USO. Encapsule-o em um bloco de código Markdown (` ```bash `, ` ```powershell `, ` ```cmd ` ou similar, de acordo com o OS). "
                    f"Inclua todos os parâmetros necessários e exemplos de placeholder (ex: `<IP_ALVO>`, `<USUARIO>`, `<SENHA_LIST>`).\n\n"
                    f"## 2. Explicação do Comando\n"
                    f"Explique cada parte do comando, seus parâmetros e por que ele é eficaz para o cenário. Detalhe como o usuário pode adaptá-lo.\n\n"
                    f"## 3. Observações de Segurança/Melhores Práticas\n"
                    f"Adicione quaisquer observações de segurança, como a necessidade de autorização, riscos potenciais, ou considerações sobre o ambiente (ex: firewalls, WAFs). Sugira variações ou próximos passos.\n\n"
                    f"Seu objetivo é ser extremamente prático, útil e direto. Se o cenário for inviável ou muito genérico, explique por que e sugira um refinamento."
                )

                command_result_raw = obter_resposta_llm(llm_model_text, [command_prompt])

                if command_result_raw:
                    st.session_state.command_analysis_result = command_result_raw
                else:
                    st.session_state.command_analysis_result = "Não foi possível gerar o comando. Tente refinar a descrição do cenário."

    if st.session_state.command_analysis_result:
        st.subheader("Comando Tático Gerado")
        st.markdown(st.session_state.command_analysis_result)
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="command_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="command_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")


# --- NOVAS PÁGINAS IMPLEMENTADAS COM PLACEHOLDERS E FEEDBACK ---

def pentest_playbook_generator_page(llm_model_text):
    st.header("Pentest Playbook Generator 📖")
    st.markdown("""
        Descreva o escopo e os objetivos do seu pentest, e o SentinelAI irá gerar um playbook
        com etapas sugeridas, ferramentas e considerações para cada fase do teste de intrusão.
        **ATENÇÃO:** Este playbook é um guia e deve ser adaptado à sua metodologia e ao ambiente real.
    """)

    # Inicialização de variáveis de estado
    if 'playbook_scope' not in st.session_state:
        st.session_state.playbook_scope = ""
    if 'playbook_objectives' not in st.session_state:
        st.session_state.playbook_objectives = ""
    if 'playbook_output' not in st.session_state:
        st.session_state.playbook_output = ""

    def reset_playbook_generator():
        st.session_state.playbook_scope = ""
        st.session_state.playbook_objectives = ""
        st.session_state.playbook_output = ""
        st.rerun()

    if st.button("Limpar Playbook", key="reset_playbook_button"):
        reset_playbook_generator()

    scope_input = st.text_area(
        "Escopo do Pentest (ex: 'Aplicação web e API REST', 'Rede interna', 'Ambiente de nuvem AWS'):",
        value=st.session_state.playbook_scope,
        placeholder="Ex: Sistema web de e-commerce, IP 192.168.1.0/24",
        height=100,
        key="playbook_scope_input"
    )
    st.session_state.playbook_scope = scope_input.strip()

    objectives_input = st.text_area(
        "Objetivos do Pentest (ex: 'Obter acesso a dados de clientes', 'Comprometer servidor web', 'Escalada de privilégios'):",
        value=st.session_state.playbook_objectives,
        placeholder="Ex: Identificar XSS e SQLi, testar controle de acesso, validar configurações de segurança",
        height=100,
        key="playbook_objectives_input"
    )
    st.session_state.playbook_objectives = objectives_input.strip()

    if st.button("Gerar Playbook", key="generate_playbook_button"):
        if not st.session_state.playbook_scope or not st.session_state.playbook_objectives:
            st.error("Por favor, forneça o escopo e os objetivos do pentest.")
        else:
            with st.spinner("Gerando playbook de pentest..."):
                playbook_prompt = (
                    f"Você é um especialista em testes de intrusão, com profundo conhecimento em metodologias de pentest (OSSTMM, PTES, OWASP TOP 10, MITRE ATT&CK). "
                    f"Sua tarefa é gerar um playbook detalhado para um pentest com o seguinte escopo e objetivos:\n\n"
                    f"**Escopo:** {st.session_state.playbook_scope}\n"
                    f"**Objetivos:** {st.session_state.playbook_objectives}\n\n"
                    f"O playbook deve cobrir as principais fases de um pentest e, para cada fase/seção, incluir:\n"
                    f"- **Descrição:** O que esta fase envolve.\n"
                    f"- **Passos Chave:** Ações detalhadas a serem tomadas.\n"
                    f"- **Ferramentas Sugeridas:** Ferramentas específicas e comandos de exemplo (quando aplicável, em blocos de código markdown).\n"
                    f"- **Resultados Esperados:** O que procurar ou coletar.\n"
                    f"- **Considerações de Segurança/Ética:** Alertas e boas práticas.\n\n"
                    f"As fases a serem abordadas incluem (mas não se limitam a):"
                    f"1.  **Reconhecimento (Passivo e Ativo)**\n"
                    f"2.  **Mapeamento/Enumeração**\n"
                    f"3.  **Análise de Vulnerabilidades**\n"
                    f"4.  **Exploração**\n"
                    f"5.  **Pós-Exploração (Se aplicável, com foco em persistência, elevação de privilégios, movimento lateral, coleta de dados)**\n"
                    f"6.  **Geração de Relatório**\n\n"
                    f"Seja conciso, prático e acionável. Use Markdown para títulos e formatação clara. Inclua exemplos de comandos quando fizer sentido (ex: Nmap, dirb, SQLmap, Metasploit, etc.)."
                )

                playbook_raw = obter_resposta_llm(llm_model_text, [playbook_prompt])

                if playbook_raw:
                    st.session_state.playbook_output = playbook_raw
                else:
                    st.session_state.playbook_output = "Não foi possível gerar o playbook. Tente refinar o escopo e os objetivos."

    if st.session_state.playbook_output:
        st.subheader("Playbook de Pentest Gerado")
        st.markdown(st.session_state.playbook_output)
        
        # Botão para download
        st.download_button(
            label="Download Playbook (.md)",
            data=st.session_state.playbook_output.encode('utf-8'),
            file_name=f"pentest_playbook_{re.sub(r'[^a-zA-Z0-9_]', '', st.session_state.playbook_scope[:20])}_{int(time.time())}.md",
            mime="text/markdown",
            help="Baixa o playbook gerado em formato Markdown."
        )
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="playbook_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="playbook_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")


def intelligent_log_analyzer_page(llm_model_text):
    st.header("Intelligent Log Analyzer 🪵")
    st.markdown("""
        Cole trechos de logs de segurança ou de aplicações. O SentinelAI irá analisar os logs
        em busca de anomalias, atividades suspeitas, tentativas de ataque, erros de segurança,
        e fornecer insights sobre possíveis incidentes ou vulnerabilidades.
    """)

    # Inicialização de variáveis de estado
    if 'log_input_content' not in st.session_state:
        st.session_state.log_input_content = ""
    if 'log_analysis_result' not in st.session_state:
        st.session_state.log_analysis_result = ""
    if 'log_summary' not in st.session_state:
        st.session_state.log_summary = None
    if 'log_context' not in st.session_state:
        st.session_state.log_context = ""

    def reset_log_analyzer():
        st.session_state.log_input_content = ""
        st.session_state.log_analysis_result = ""
        st.session_state.log_summary = None
        st.session_state.log_context = ""
        st.rerun()

    if st.button("Limpar Análise de Log", key="reset_log_analysis_button"):
        reset_log_analyzer()

    log_content = st.text_area(
        "Cole o trecho do log aqui:",
        value=st.session_state.log_input_content,
        placeholder="Ex: 'Jun 1 10:30:05 webserver suhosin[12345]: ALERT - configured request variable name length limit exceeded (attacker '...GET /admin.php?id=1 union select...')'",
        height=300,
        key="log_input_area"
    )
    st.session_state.log_input_content = log_content.strip()

    log_context = st.text_area(
        "Forneça contexto sobre o log (tipo de sistema, aplicação, etc. - opcional):",
        value=st.session_state.log_context,
        placeholder="Ex: 'Log do Apache access.log', 'Log de firewall do FortiGate', 'Logs de auditoria do Linux'",
        height=80,
        key="log_context_input"
    )
    st.session_state.log_context = log_context.strip()

    if st.button("Analisar Log", key="analyze_log_button"):
        if not st.session_state.log_input_content:
            st.error("Por favor, cole o conteúdo do log para análise.")
        else:
            with st.spinner("Analisando logs em busca de insights de segurança..."):
                log_prompt = (
                    f"Você é um analista de segurança e especialista em análise de logs e SIEM. "
                    f"Analise o seguinte trecho de log(s) e o contexto fornecido. Seu objetivo é identificar e correlacionar:\n"
                    f"- Atividades suspeitas e anomalias.\n"
                    f"- Tentativas de ataque (ex: injeções, varreduras de portas, brute-force, acesso não autorizado).\n"
                    f"- Erros ou configurações de segurança que possam indicar vulnerabilidades.\n"
                    f"- Informações que ajudem em uma resposta a incidentes ou análise forense.\n\n"
                    f"**Log(s) para análise:**\n```\n{st.session_state.log_input_content}\n```\n\n"
                    f"**Contexto Adicional:** {st.session_state.log_context if st.session_state.log_context else 'Nenhum contexto adicional fornecido.'}\n\n"
                    f"**RESUMO:** Forneça um resumo quantitativo na PRIMEIRA LINHA da sua resposta, no formato exato: `Total de Eventos: X | Críticos: Y | Altos: Z | Médios: W | Baixas: V` (substitua X,Y,Z,W,V pelos números correspondentes). Se não houver eventos relevantes, use 0.\n\n"
                    f"Para cada **evento ou anomalia de segurança** identificado, apresente de forma concisa e prática, utilizando formato Markdown:\n\n"
                    f"## [Tipo de Evento/Anomalia] (Ex: Tentativa de SQL Injection, Varredura de Portas, Falha de Autenticação Bruteforce)\n"
                    f"**Severidade/Risco:** [Crítica/Alta/Média/Baixa/Informativo]\n"
                    f"**Linha(s) de Log Afetada(s):** Cite a(s) linha(s) ou trecho(s) do log que indica(m) o evento.\n"
                    f"**Detalhes e Implicação de Segurança:** Explique o que o evento significa, como ele foi detectado no log e qual a sua potencial implicação de segurança (ex: comprometimento, reconhecimento, negação de serviço).\n"
                    f"**Ações Recomendadas para Resposta a Incidentes/Investigação:** Quais os próximos passos para investigar ou mitigar? (Ex: 'Verificar logs de autenticação para o usuário X', 'Bloquear IP Y no firewall', 'Coletar mais contexto do servidor Z', 'Alertar equipe de resposta a incidentes').\n\n"
                    f"Se não encontrar eventos de segurança óbvios, ou se o log for muito genérico/curto, indique isso claramente e sugira que mais logs ou contexto são necessários."
                )

                log_analysis_raw = obter_resposta_llm(llm_model_text, [log_prompt])

                if log_analysis_raw:
                    st.session_state.log_summary, st.session_state.log_analysis_result = parse_vulnerability_summary(log_analysis_raw)
                else:
                    st.session_state.log_analysis_result = "Não foi possível analisar o log. Tente novamente ou forneça mais dados."
                    st.session_state.log_summary = None

    if st.session_state.log_analysis_result:
        st.subheader("Resultados da Análise de Log")
        if st.session_state.log_summary:
            cols = st.columns(5)
            cols[0].metric("Total de Eventos", st.session_state.log_summary["Total"])
            cols[1].metric("Críticos", st.session_state.log_summary["Críticas"])
            cols[2].metric("Altos", st.session_state.log_summary["Altas"])
            cols[3].metric("Médios", st.session_state.log_summary["Médias"])
            cols[4].metric("Baixos", st.session_state.log_summary["Baixas"])
            st.markdown("---")
        st.markdown(st.session_state.log_analysis_result)
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="log_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="log_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")

# --- NOVAS PÁGINAS DE INTEGRAÇÃO COM RAPID7 (Validacao e Exploracao) ---

def get_insightvm_vulnerabilities(target_identifiers, llm_text_model):
    """
    Função para buscar vulnerabilidades no Rapid7 InsightVM via API.
    ATENÇÃO: ESTE É UM CÓDIGO PLACEHOLDER. VOCÊ PRECISA IMPLEMENTAR A LÓGICA REAL
    DE INTERAÇÃO COM A API DO RAPID7 INSIGHTVM.

    Isso geralmente envolve:
    1. Autenticação (obtendo um token de sessão, se necessário, ou usando X-Api-Key diretamente).
    2. Buscando IDs de ativos pelos IPs/Nomes de Host fornecidos (usando /api/3/assets/search).
    3. Para cada ativo, buscando as vulnerabilidades associadas (usando /api/3/assets/{asset_id}/vulnerabilities).
    4. Tratamento de paginação, erros e limites de taxa.

    Documentação da API: https://help.rapid7.com/insightvm/en-us/api/v3/docs.html
    """
    if not RAPID7_INSIGHTVM_API_KEY:
        st.error("ERRO: A variável de ambiente 'RAPID7_INSIGHTVM_API_KEY' não está configurada no .env. Configure para usar esta funcionalidade.")
        return {"error": "RAPID7_INSIGHTVM_API_KEY não configurada."}

    api_base_url = RAPID7_API_BASE_URLS.get(RAPID7_INSIGHTVM_REGION.lower(), RAPID7_API_BASE_URLS["us"])
    headers = {
        "X-Api-Key": RAPID7_INSIGHTVM_API_KEY, # Sua chave de API
        "Content-Type": "application/json",
        "Accept": "application/json;charset=UTF-8"
    }

    all_vulns_by_identifier = {} # Para armazenar vulnerabilidades por IP/hostname fornecido pelo usuário

    # Loop através de cada IP/Hostname que o usuário digitou
    for identifier in target_identifiers:
        st.info(f"Buscando ativo e vulnerabilidades no Rapid7 InsightVM para: {identifier}")
        asset_id = None
        
        # Determine se é um IP ou hostname para usar o filtro correto na API
        search_field = "ip-address"
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", identifier): # Não parece um IP, assume hostname
            search_field = "host-name"
        
        # Payload para buscar o ativo
        search_payload = {
            "filters": [
                {"field": search_field, "operator": "IN", "values": [identifier]}
            ],
            "match": "ANY" 
        }

        try:
            # 1. Busca o ID do Ativo (Asset ID) no Rapid7 InsightVM
            # Este é um POST para /api/3/assets/search
            asset_search_url = f"{api_base_url}/api/3/assets/search"
            asset_response = requests.post(asset_search_url, headers=headers, json=search_payload)
            asset_response.raise_for_status() # Lança exceção para erros HTTP (4xx ou 5xx)

            assets_found = asset_response.json().get('resources', [])
            
            if assets_found:
                # Pega o primeiro ativo encontrado, ou itera se houver múltiplos
                asset_id = assets_found[0].get('id') 
                st.success(f"Ativo '{identifier}' encontrado no InsightVM com ID: {asset_id}")
            else:
                st.warning(f"Ativo '{identifier}' NÃO ENCONTRADO no InsightVM. Verifique o IP/Nome ou se o ativo foi varrido.")
                all_vulns_by_identifier[identifier] = [] # Nenhuma vulnerabilidade se o ativo não for encontrado
                continue # Pula para o próximo identificador

        except requests.exceptions.RequestException as e:
            st.error(f"Erro na API do Rapid7 InsightVM ao buscar ativo '{identifier}': {e}. Verifique sua chave de API e região.")
            all_vulns_by_identifier[identifier] = []
            continue # Pula para o próximo identificador

        # 2. Se o Asset ID foi encontrado, busca as vulnerabilidades para esse Asset ID
        if asset_id:
            try:
                vulns_url = f"{api_base_url}/api/3/assets/{asset_id}/vulnerabilities"
                vulns_response = requests.get(vulns_url, headers=headers)
                vulns_response.raise_for_status()

                asset_vulns = vulns_response.json().get('resources', [])
                all_vulns_by_identifier[identifier] = asset_vulns
                st.success(f"Encontradas {len(asset_vulns)} vulnerabilidades para o ativo {identifier}.")

            except requests.exceptions.RequestException as e:
                st.error(f"Erro na API do Rapid7 InsightVM ao buscar vulnerabilidades para ativo ID {asset_id} ('{identifier}'): {e}")
                all_vulns_by_identifier[identifier] = []
        else:
            all_vulns_by_identifier[identifier] = [] # Se o asset_id não foi encontrado, não há vulns para ele

    return all_vulns_by_identifier


def rapid7_vulnerability_validation_page(llm_model_text):
    st.header("Rapid7 Vulnerability Validation 🚀")
    st.markdown("""
        Forneça IPs ou nomes de host varridos pelo Rapid7 InsightVM. O SentinelAI consultará as vulnerabilidades
        desses ativos e, em seguida, buscará PoCs/exploits relevantes no seu Exploit-DB local para validação.
        Um LLM auxiliará na contextualização e sugestão de passos para exploração.
    """)

    # Variáveis de estado para esta página
    if 'rapid7_target_ips' not in st.session_state: st.session_state.rapid7_target_ips = ""
    if 'rapid7_validation_results' not in st.session_state: st.session_state.rapid7_validation_results = ""
    if 'rapid7_validation_summary' not in st.session_state: st.session_state.rapid7_validation_summary = None

    def reset_rapid7_validation():
        st.session_state.rapid7_target_ips = ""
        st.session_state.rapid7_validation_results = ""
        st.session_state.rapid7_validation_summary = None
        st.rerun()

    if st.button("Limpar Validação", key="reset_rapid7_validation_button"):
        reset_rapid7_validation()

    target_ips_input = st.text_area(
        "IPs ou Nomes de Host (separados por vírgula ou nova linha):",
        value=st.session_state.rapid7_target_ips,
        placeholder="Ex: 10.0.0.10, 10.0.0.20, meu-servidor-prod.com",
        height=100,
        key="rapid7_target_ips_input"
    )
    st.session_state.rapid7_target_ips = target_ips_input.strip()

    if st.button("Validar Vulnerabilidades Rapid7", key="trigger_rapid7_validation_button"):
        if not RAPID7_INSIGHTVM_API_KEY:
            st.error("ERRO: A variável de ambiente 'RAPID7_INSIGHTVM_API_KEY' não está configurada no .env.")
            st.info("Por favor, adicione 'RAPID7_INSIGHTVM_API_KEY=SUA_CHAVE_AQUI' ao seu arquivo .env.")
            st.stop()
        
        if not st.session_state.rapid7_target_ips:
            st.error("Por favor, forneça pelo menos um IP ou nome de host para validação.")
            st.session_state.rapid7_validation_results = ""
            st.session_state.rapid7_validation_summary = None
            return

        target_list = [id.strip() for id in st.session_state.rapid7_target_ips.replace('\n', ',').split(',') if id.strip()]

        with st.spinner("Consultando Rapid7 InsightVM e buscando exploits locais..."):
            # Chama a função que agora tentará a integração real
            insightvm_data = get_insightvm_vulnerabilities(target_list, llm_model_text)

            if "error" in insightvm_data:
                st.error(insightvm_data["error"])
                st.session_state.rapid7_validation_results = ""
                st.session_state.rapid7_validation_summary = None
                return

            all_vulnerabilities_for_llm = []
            total_vulns = 0
            critical_vulns = 0
            high_vulns = 0
            medium_vulns = 0
            low_vulns = 0

            for identifier, vulns in insightvm_data.items():
                for vuln in vulns:
                    total_vulns += 1
                    severity = vuln.get('severity', '').upper()
                    if severity == 'CRITICAL':
                        critical_vulns += 1
                    elif severity == 'HIGH':
                        high_vulns += 1
                    elif severity == 'MEDIUM':
                        medium_vulns += 1
                    elif severity == 'LOW':
                        low_vulns += 1

                    # Formato para o LLM
                    all_vulnerabilities_for_llm.append(
                        f"Ativo: {identifier}, Título: {vuln.get('title')}, CVE: {vuln.get('cve', 'N/A')}, "
                        f"Severidade: {vuln.get('severity')}, CVSS: {vuln.get('cvss_score')}, "
                        f"Descrição: {vuln.get('description')}"
                    )

            if not all_vulnerabilities_for_llm:
                st.info(f"Nenhuma vulnerabilidade encontrada no Rapid7 InsightVM para os identificadores: {', '.join(target_list)}. Ou a API não retornou dados.")
                st.session_state.rapid7_validation_results = "Nenhuma vulnerabilidade relevante encontrada ou erro na comunicação com a API."
                st.session_state.rapid7_validation_summary = {"Total": 0, "Críticas": 0, "Altas": 0, "Médias": 0, "Baixas": 0}
                return

            # Construir o prompt para o LLM
            prompt_parts = [
                f"Você é um pentester e especialista em validação de vulnerabilidades, com acesso a resultados de varreduras do Rapid7 InsightVM e a um repositório local de exploits (Exploit-DB/Metasploit)."
                f"Analise as seguintes vulnerabilidades reportadas para os alvos: {', '.join(target_list)}."
                f"Para cada vulnerabilidade, faça o seguinte:\n\n"
                f"**RESUMO:** Forneça um resumo quantitativo na PRIMEIRA LINHA da sua resposta, no formato exato: `Total de Achados: {total_vulns} | Críticos: {critical_vulns} | Altos: {high_vulns} | Médios: {medium_vulns} | Baixos: {low_vulns}`.\n\n"
                f"Para cada achado, forneça:\n"
                f"## Vulnerabilidade: [Título da Vulnerabilidade] (Ativo: [IP/Hostname Alvo])\n"
                f"**CVE:** [CVE ID, se disponível, ex: CVE-YYYY-NNNNN]\n"
                f"**Severidade Rapid7:** [Severidade original do Rapid7, ex: CRITICAL, HIGH]\n"
                f"**Descrição Detalhada:** Explique a vulnerabilidade e como ela se manifesta no contexto do ativo.\n"
                f"**Busca no Exploit-DB Local & Correlação:** Tente correlacionar a vulnerabilidade com PoCs ou exploits conhecidos no seu repositório local do Exploit-DB (ou que seriam típicos do Metasploit). Mencione o tipo de exploit esperado (ex: RCE, LFI, Credential Disclosure).\n"
                f"**Passos para Validação/Exploração & Ferramentas:** Forneça um guia passo a passo sobre como um pentester validaria ou tentaria explorar essa vulnerabilidade. Inclua comandos de exemplo (Metasploit, curl, nmap, etc.) com placeholders (`<IP_ALVO>`, `<PORTA_ALVO>`). Se houver um exploit específico que faria sentido, mencione-o.\n"
                f"**Exemplo de Comando/PoC:** Forneça um bloco de código `bash`, `python`, `http` ou `msfconsole` com um exemplo de PoC ou comando de exploração, adaptado para o IP e detalhes da vulnerabilidade.\n"
                f"**Dicas de Contorno/Considerações:** Qualquer observação sobre WAF, IDS/IPS, ou como a exploração pode ser sutil.\n"
                f"**Prioridade de Ação Sugerida:** [Crítica/Alta/Média/Baixa] - uma prioridade de remediação recomendada por você, considerando a exploração.\n"
                f"--- \n"
                f"**Dados brutos das vulnerabilidades do Rapid7 InsightVM para referência:**\n"
            ]
            for vuln_line in all_vulnerabilities_for_llm:
                prompt_parts.append(f"- {vuln_line}\n")
            
            validation_result_raw = obter_resposta_llm(llm_model_text, "".join(prompt_parts))

            if validation_result_raw:
                st.session_state.rapid7_validation_summary, st.session_state.rapid7_validation_results = parse_vulnerability_summary(validation_result_raw)
            else:
                st.session_state.rapid7_validation_results = "Não foi possível obter a análise de validação do LLM."
                st.session_state.rapid7_validation_summary = {"Total": 0, "Críticas": 0, "Altas": 0, "Médias": 0, "Baixas": 0} # Fallback summary

    if st.session_state.rapid7_validation_results:
        st.subheader("Resultados da Validação de Vulnerabilidades Rapid7")
        if st.session_state.rapid7_validation_summary:
            cols = st.columns(5)
            cols[0].metric("Total Achados", st.session_state.rapid7_validation_summary["Total"])
            cols[1].metric("Críticos", st.session_state.rapid7_validation_summary["Críticas"])
            cols[2].metric("Altos", st.session_state.rapid7_validation_summary["Altas"])
            cols[3].metric("Médios", st.session_state.rapid7_validation_summary["Médias"])
            cols[4].metric("Baixos", st.session_state.rapid7_validation_summary["Baixas"])
            st.markdown("---")
        st.markdown(st.session_state.rapid7_validation_results)
        # Feedback Buttons
        cols_feedback = st.columns(2)
        if cols_feedback[0].button("👍 Útil", key="rapid7_validation_feedback_good"):
            st.toast("Obrigado pelo seu feedback! Isso nos ajuda a melhorar.", icon="😊")
        if cols_feedback[1].button("👎 Precisa de Melhoria", key="rapid7_validation_feedback_bad"):
            st.toast("Obrigado pelo seu feedback. Continuaremos trabalhando para aprimorar.", icon="😔")


# --- Lógica Principal do Aplicativo Streamlit ---

# Inicialização de todos os session_state no início, antes de qualquer lógica de UI
if 'llm_models' not in st.session_state:
    st.session_state.llm_models = {'vision_model': None, 'text_model': None, 'initialized': False}

llm_model_vision, llm_model_text = get_gemini_models_cached()


# Inicialização de variáveis de estado para as páginas existentes
if 'owasp_text_input_falha' not in st.session_state: st.session_state.owasp_text_input_falha = ""
if 'owasp_text_analysis_result' not in st.session_state: st.session_state.owasp_text_analysis_result = ""
if 'owasp_text_context_input' not in st.session_state: st.session_state.owasp_text_context_input = ""
if 'owasp_text_consider_waf_state' not in st.session_state: st.session_state.owasp_text_consider_waf_state = False

if 'http_request_input_url' not in st.session_state: st.session_state.http_request_input_url = ""
if 'http_request_input_raw' not in st.session_state: st.session_state.http_request_input_raw = ""
if 'http_request_analysis_result' not in st.session_state: st.session_state.http_request_analysis_result = ""
if 'http_request_consider_waf_state' not in st.session_state: st.session_state.http_request_consider_waf_state = False
if 'http_request_summary' not in st.session_state: st.session_state.http_request_summary = None

if 'owasp_image_uploaded' not in st.session_state: st.session_state.owasp_image_uploaded = None
if 'owasp_question_text' not in st.session_state: st.session_state.owasp_question_text = ""
if 'owasp_analysis_result' not in st.session_state: st.session_state.owasp_analysis_result = ""
if 'owasp_consider_waf_state' not in st.session_state: st.session_state.owasp_consider_waf_state = False

if 'stride_image_uploaded' not in st.session_state: st.session_state.stride_image_uploaded = None 
if 'stride_description_text' not in st.session_state: st.session_state.stride_description_text = ""
if 'stride_analysis_result' not in st.session_state: st.session_state.stride_analysis_result = ""
if 'stride_summary' not in st.session_state: st.session_state.stride_summary = None

if 'lab_vulnerability_selected' not in st.session_state: st.session_state.lab_vulnerability_selected = None
if 'lab_html_poc' not in st.session_state: st.session_state.lab_html_poc = ""
if 'lab_explanation' not in st.session_state: st.session_state.lab_explanation = ""
if 'lab_payload_example' not in st.session_state: st.session_state.lab_payload_example = ""

if 'poc_gen_vulnerability_input' not in st.session_state: st.session_state.poc_gen_vulnerability_input = ""
if 'poc_gen_context_input' not in st.session_state: st.session_state.poc_gen_context_input = ""
if 'poc_gen_html_output' not in st.session_state: st.session_state.poc_gen_html_output = ""
if 'poc_gen_instructions' not in st.session_state: st.session_state.poc_gen_instructions = ""
if 'poc_gen_payload_example' not in st.session_state: st.session_state.poc_gen_payload_example = ""

if 'swagger_input_content' not in st.session_state: st.session_state.swagger_input_content = ""
if 'swagger_analysis_result' not in st.session_state: st.session_state.swagger_analysis_result = [] 
if 'swagger_analysis_result_display' not in st.session_state: st.session_state.swagger_analysis_result_display = "" 
if 'swagger_context_input' not in st.session_state: st.session_state.swagger_context_input = ""
if 'swagger_summary' not in st.session_state: st.session_state.swagger_summary = None

if 'code_input_content' not in st.session_state: st.session_state.code_input_content = ""
if 'code_analysis_result' not in st.session_state: st.session_state.code_analysis_result = ""
if 'code_language_selected' not in st.session_state: st.session_state.code_language_selected = "Python" 

if 'searchsploit_query' not in st.session_state: st.session_state.searchsploit_query = ""
if 'searchsploit_results' not in st.session_state: st.session_state.searchsploit_results = []
if 'selected_exploit_path' not in st.session_state: st.session_state.selected_exploit_path = ""
if 'exploit_content_display' not in st.session_state: st.session_state.exploit_content_display = ""
if 'llm_exploit_analysis_result' not in st.session_state: st.session_state.llm_exploit_analysis_result = ""
if 'selected_exploit_index' not in st.session_state: st.session_state.selected_exploit_index = 0

if 'recon_target' not in st.session_state: st.session_state.recon_target = ""
if 'selected_recon_tools' not in st.session_state: st.session_state.selected_recon_tools = []
if 'recon_results_output' not in st.session_state: st.session_state.recon_results_output = ""
if 'recon_llm_analysis' not in st.session_state: st.session_state.recon_llm_analysis = ""
if 'recon_summary' not in st.session_state: st.session_state.recon_summary = None
if 'recon_context_objective' not in st.session_state: st.session_state.recon_context_objective = ""
if 'httpx_status_codes_filter' not in st.session_state: st.session_state.httpx_status_codes_filter = ["200", "403", "500"]
if 'gobuster_status_codes_filter' not in st.session_state: st.session_state.gobuster_status_codes_filter = ["200", "403"]

if 'command_scenario_input' not in st.session_state: st.session_state.command_scenario_input = ""
if 'command_analysis_result' not in st.session_state: st.session_state.command_analysis_result = ""
if 'command_tool_selection' not in st.session_state: st.session_state.command_tool_selection = "Qualquer Ferramenta"
if 'command_os_selection' not in st.session_state: st.session_state.command_os_selection = "Linux/macOS (Bash)"

# Assegure que as variáveis de estado para as novas páginas customizadas estejam inicializadas
if 'playbook_scope' not in st.session_state: st.session_state.playbook_scope = ""
if 'playbook_objectives' not in st.session_state: st.session_state.playbook_objectives = ""
if 'playbook_output' not in st.session_state: st.session_state.playbook_output = ""

if 'log_input_content' not in st.session_state: st.session_state.log_input_content = ""
if 'log_analysis_result' not in st.session_state: st.session_state.log_analysis_result = ""
if 'log_summary' not in st.session_state: st.session_state.log_summary = None
if 'log_context' not in st.session_state: st.session_state.log_context = ""

# Variáveis de estado para as funcionalidades Rapid7
if 'rapid7_target_ips' not in st.session_state: st.session_state.rapid7_target_ips = ""
if 'rapid7_validation_results' not in st.session_state: st.session_state.rapid7_validation_results = ""
if 'rapid7_validation_summary' not in st.session_state: st.session_state.rapid7_validation_summary = None

# AQUI ESTÁ A LISTA DE NAVEGAÇÃO COMPLETA NA BARRA LATERAL
selected_page = st.sidebar.radio(
    "Navegação",
    [
        "Início", 
        "OWASP Vulnerability Details", 
        "Análise de Requisições HTTP", 
        "OWASP Image Analyzer", 
        "PoC Generator (HTML)", 
        "OpenAPI Analyzer", 
        "Static Code Analyzer", 
        "Search Exploit", 
        "Advanced Reconnaissance", 
        "Tactical Command Orchestrator",
        "Pentest Playbook Generator",
        "Intelligent Log Analyzer",
        "Rapid7 Vulnerability Validation"
    ],
    index=0 
)

# AQUI ESTÃO AS CHAMADAS DAS FUNÇÕES DE PÁGINA COM BASE NA SELEÇÃO DA BARRA LATERAL
if selected_page == "Início":
    home_page()
elif selected_page == "OWASP Vulnerability Details":
    owasp_text_analysis_page(llm_model_vision, llm_model_text)
elif selected_page == "Análise de Requisições HTTP":
    http_request_analysis_page(llm_model_vision, llm_model_text)
elif selected_page == "OWASP Image Analyzer":
    owasp_scout_visual_page(llm_model_vision, llm_model_text)
elif selected_page == "PoC Generator (HTML)":
    poc_generator_html_page(llm_model_vision, llm_model_text)
elif selected_page == "OpenAPI Analyzer":
    swagger_openapi_analyzer_page(llm_model_vision, llm_model_text)
elif selected_page == "Static Code Analyzer":
    static_code_analyzer_page(llm_model_vision, llm_model_text)
elif selected_page == "Search Exploit":
    searchsploit_exploit_page(llm_model_text)
elif selected_page == "Advanced Reconnaissance":
    active_recon_page(llm_model_vision, llm_model_text)
elif selected_page == "Tactical Command Orchestrator":
    tactical_command_orchestrator_page(llm_model_text)
elif selected_page == "Pentest Playbook Generator":
    pentest_playbook_generator_page(llm_model_text)
elif selected_page == "Intelligent Log Analyzer":
    intelligent_log_analyzer_page(llm_model_text)
elif selected_page == "Rapid7 Vulnerability Validation":
    rapid7_vulnerability_validation_page(llm_model_text)
