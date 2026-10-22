import streamlit as st
import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from crypto_utils import (
    gerar_chaves,
    gerar_certificado,
    carregar_chave_privada
)


st.set_page_config(
    page_title="Assinatura Digital",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 Assinatura Digital e Certificado Digital")

st.write(
    "Aplicação acadêmica para geração de chaves RSA, "
    "assinatura digital e verificação de arquivos."
)

aba_chaves, aba_assinar, aba_verificar = st.tabs([
    "🔑 Chaves e Certificado",
    "✍️ Assinar Arquivo",
    "✅ Verificar Assinatura"
])


# ==========================================
# ABA 1 - GERAR CHAVES E CERTIFICADO
# ==========================================

with aba_chaves:

    st.header("Gerar chaves e certificado")

    st.write(
        "Gere um par de chaves RSA de 2048 bits e "
        "um certificado digital X.509 autoassinado."
    )

    senha = st.text_input(
        "Defina uma senha para a chave privada:",
        type="password",
        key="senha_geracao"
    )

    if st.button("Gerar chaves e certificado"):

        if len(senha.encode("utf-8")) < 8:
            st.error("A senha deve possuir pelo menos 8 bytes.")

        else:
            chave_privada, chave_publica = gerar_chaves()

            privada_pem = chave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    senha.encode("utf-8")
                )
            )

            publica_pem = chave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Gera o certificado em memória,
            # sem salvar no Codespaces.
            certificado = gerar_certificado(
                chave_privada,
                chave_publica
            )

            certificado_pem = certificado.public_bytes(
                serialization.Encoding.PEM
            )

            st.session_state["arquivos_gerados"] = {
                "privada": privada_pem,
                "publica": publica_pem,
                "certificado": certificado_pem
            }

            st.success("Chaves e certificado gerados com sucesso!")

    if "arquivos_gerados" in st.session_state:

        arquivos = st.session_state["arquivos_gerados"]

        st.download_button(
            "Baixar chave privada",
            data=arquivos["privada"],
            file_name="chave_privada.pem",
            mime="application/x-pem-file"
        )

        st.download_button(
            "Baixar chave pública",
            data=arquivos["publica"],
            file_name="chave_publica.pem",
            mime="application/x-pem-file"
        )

        st.download_button(
            "Baixar certificado digital",
            data=arquivos["certificado"],
            file_name="certificado.pem",
            mime="application/x-pem-file"
        )

        st.warning(
            "O certificado é autoassinado e destinado apenas "
            "a testes acadêmicos. Ele não comprova a identidade "
            "do titular por uma Autoridade Certificadora confiável."
        )


# ==========================================
# ABA 2 - ASSINAR ARQUIVO
# ==========================================

with aba_assinar:

    st.header("Assinar arquivo digitalmente")

    arquivo = st.file_uploader(
        "Selecione o arquivo que deseja assinar:",
        key="arquivo_assinatura"
    )

    arquivo_chave = st.file_uploader(
        "Selecione a chave privada (.pem):",
        type=["pem"],
        key="chave_assinatura"
    )

    senha_assinatura = st.text_input(
        "Senha da chave privada:",
        type="password",
        key="senha_assinatura"
    )

    if st.button("Gerar assinatura digital"):

        if arquivo is None or arquivo_chave is None:
            st.error("Selecione o arquivo e a chave privada.")

        else:
            try:
                chave_privada = (
                    serialization.load_pem_private_key(
                        arquivo_chave.getvalue(),
                        password=senha_assinatura.encode("utf-8")
                    )
                )

                conteudo = arquivo.getvalue()

                assinatura = chave_privada.sign(
                    conteudo,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.DIGEST_LENGTH
                    ),
                    hashes.SHA256()
                )

                st.session_state["assinatura_gerada"] = {
                    "dados": assinatura,
                    "nome": arquivo.name + ".sig",
                    "hash_documento": hashlib.sha256(
                        conteudo
                    ).hexdigest(),
                    "hash_chave": hashlib.sha256(
                        arquivo_chave.getvalue()
                    ).hexdigest()
                }

                st.success("Assinatura digital gerada com sucesso!")

            except (ValueError, TypeError):
                st.error(
                    "Não foi possível carregar a chave privada. "
                    "Verifique a senha e o arquivo selecionado."
                )

            except Exception:
                st.error("Não foi possível gerar a assinatura.")


    if "assinatura_gerada" in st.session_state:

        resultado = st.session_state["assinatura_gerada"]

        documento_atual = (
            hashlib.sha256(arquivo.getvalue()).hexdigest()
            if arquivo is not None else None
        )

        chave_atual = (
            hashlib.sha256(arquivo_chave.getvalue()).hexdigest()
            if arquivo_chave is not None else None
        )

        if (
            resultado["hash_documento"] == documento_atual
            and resultado["hash_chave"] == chave_atual
        ):
            st.download_button(
                "Baixar assinatura digital",
                data=resultado["dados"],
                file_name=resultado["nome"],
                mime="application/octet-stream"
            )

        else:
            del st.session_state["assinatura_gerada"]



# ==========================================
# ABA 3 - VERIFICAR ASSINATURA
# ==========================================

with aba_verificar:

    st.header("Verificar assinatura digital")

    arquivo_original = st.file_uploader(
        "Selecione o arquivo original:",
        key="arquivo_verificacao"
    )

    arquivo_assinatura = st.file_uploader(
        "Selecione o arquivo de assinatura (.sig):",
        type=["sig"],
        key="assinatura_verificacao"
    )

    arquivo_certificado = st.file_uploader(
        "Selecione o certificado digital (.pem):",
        type=["pem"],
        key="certificado_verificacao"
    )

    if st.button("Verificar assinatura"):

        if (
            arquivo_original is None
            or arquivo_assinatura is None
            or arquivo_certificado is None
        ):
            st.error("Selecione todos os arquivos necessários.")

        else:
            try:
                certificado = x509.load_pem_x509_certificate(
                    arquivo_certificado.getvalue()
                )

                chave_publica = certificado.public_key()

                chave_publica.verify(
                    arquivo_assinatura.getvalue(),
                    arquivo_original.getvalue(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.DIGEST_LENGTH
                    ),
                    hashes.SHA256()
                )

                st.success(
                    "ASSINATURA VÁLIDA! "
                    "O arquivo corresponde à assinatura e "
                    "à chave pública utilizada."
                )

            except InvalidSignature:
                st.error(
                    "ASSINATURA INVÁLIDA! "
                    "O arquivo, a assinatura ou a chave "
                    "pública não correspondem."
                )

            except Exception:
                st.error(
                    "Não foi possível verificar a assinatura. "
                    "Confira os arquivos selecionados."
                )

            st.info(
                "A verificação criptográfica não comprova, "
                "por si só, a identidade do titular do certificado. "
                "Certificados autoassinados não possuem "
                "confiança automática de uma AC reconhecida."
            )