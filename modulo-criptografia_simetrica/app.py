import base64
import streamlit as st
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


st.set_page_config(
    page_title="Criptografia Simétrica",
    page_icon="🔐",
    layout="centered"
)


def gerar_chave():
    """Gera uma chave AES de 256 bits."""
    return AESGCM.generate_key(bit_length=256)


def criptografar(mensagem, chave):
    """Criptografa uma mensagem utilizando AES-GCM."""
    aesgcm = AESGCM(chave)

    # O nonce deve ser único para cada operação com a mesma chave.
    nonce = os.urandom(12)

    mensagem_bytes = mensagem.encode("utf-8")

    texto_cifrado = aesgcm.encrypt(
        nonce,
        mensagem_bytes,
        None
    )

    # O nonce precisa ser armazenado junto ao conteúdo cifrado.
    resultado = nonce + texto_cifrado

    return base64.b64encode(resultado).decode("utf-8")


def descriptografar(texto_cifrado_base64, chave):
    """Descriptografa e autentica o conteúdo recebido."""
    dados = base64.b64decode(
        texto_cifrado_base64.strip(),
        validate=True
    )

    if len(dados) < 12 + 16:
        raise ValueError("O conteúdo criptografado é inválido.")

    nonce = dados[:12]
    texto_cifrado = dados[12:]

    aesgcm = AESGCM(chave)

    mensagem_bytes = aesgcm.decrypt(
        nonce,
        texto_cifrado,
        None
    )

    return mensagem_bytes.decode("utf-8")


def decodificar_chave(chave_base64):
    """Converte a chave exibida em Base64 para bytes."""
    chave = base64.b64decode(
        chave_base64.strip(),
        validate=True
    )

    if len(chave) != 32:
        raise ValueError("A chave AES-256 deve possuir 32 bytes.")

    return chave


st.title("🔐 Criptografia Simétrica")
st.write(
    "Demonstração prática de criptografia e descriptografia "
    "utilizando o algoritmo AES-256-GCM."
)

st.info(
    "A criptografia simétrica utiliza a mesma chave secreta "
    "para criptografar e descriptografar os dados."
)

if "chave" not in st.session_state:
    st.session_state.chave = ""

if "texto_cifrado" not in st.session_state:
    st.session_state.texto_cifrado = ""

if "mensagem_original" not in st.session_state:
    st.session_state.mensagem_original = ""

st.header("1. Mensagem original")

mensagem = st.text_area(
    "Digite a mensagem que deseja proteger:",
    placeholder="Exemplo: Esta mensagem é confidencial.",
    height=120
)

st.header("2. Chave secreta")

coluna1, coluna2 = st.columns(2)

with coluna1:
    if st.button("Gerar chave secreta", use_container_width=True):
        chave_bytes = gerar_chave()

        st.session_state.chave = base64.b64encode(
            chave_bytes
        ).decode("utf-8")

with coluna2:
    if st.button("Limpar campos", use_container_width=True):
        st.session_state.chave = ""
        st.session_state.texto_cifrado = ""
        st.session_state.mensagem_original = ""
        st.rerun()

chave_digitada = st.text_input(
    "Chave secreta em Base64:",
    value=st.session_state.chave,
    type="password",
    help="Gere uma chave ou cole uma chave AES-256 válida."
)

st.session_state.chave = chave_digitada

st.caption(
    "A chave possui 256 bits. Mantenha-a em segurança "
    "e não a compartilhe com pessoas não autorizadas."
)

st.header("3. Criptografia")

if st.button("Criptografar mensagem", use_container_width=True):
    if not mensagem:
        st.error("Digite uma mensagem antes de criptografar.")

    elif not chave_digitada:
        st.error("Gere ou informe uma chave secreta.")

    else:
        try:
            chave_bytes = decodificar_chave(chave_digitada)

            st.session_state.texto_cifrado = criptografar(
                mensagem,
                chave_bytes
            )

            st.session_state.mensagem_original = mensagem

            st.success("Mensagem criptografada com sucesso!")

        except Exception:
            st.error(
                "Não foi possível criptografar. "
                "Verifique a chave informada."
            )

if st.session_state.texto_cifrado:
    st.text_area(
        "Texto criptografado (Base64):",
        value=st.session_state.texto_cifrado,
        height=150
    )

st.header("4. Descriptografia")

texto_para_descriptografar = st.text_area(
    "Conteúdo que será descriptografado:",
    value=st.session_state.texto_cifrado,
    height=120
)

if st.button("Descriptografar mensagem", use_container_width=True):
    if not texto_para_descriptografar:
        st.error("Informe o conteúdo criptografado.")

    elif not chave_digitada:
        st.error("Informe a chave secreta.")

    else:
        try:
            chave_bytes = decodificar_chave(chave_digitada)

            mensagem_recuperada = descriptografar(
                texto_para_descriptografar,
                chave_bytes
            )

            st.success("Descriptografia realizada com sucesso!")

            st.text_area(
                "Mensagem recuperada:",
                value=mensagem_recuperada,
                height=100
            )

            if mensagem_recuperada == st.session_state.mensagem_original:
                st.success(
                    "Teste aprovado: a mensagem original foi recuperada."
                )

        except Exception:
            st.error(
                "Falha na descriptografia. A chave pode estar incorreta "
                "ou o conteúdo pode ter sido alterado."
            )

st.divider()

st.caption(
    "Algoritmo: AES-256-GCM | "
    "Bibliotecas: Python Cryptography e Streamlit"
)