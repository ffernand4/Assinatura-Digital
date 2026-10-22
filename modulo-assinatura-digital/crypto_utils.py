from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature


def gerar_chaves():
    """Gera um par de chaves RSA de 2048 bits."""

    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    chave_publica = chave_privada.public_key()

    return chave_privada, chave_publica


def salvar_chaves(chave_privada, chave_publica, senha):
    """Salva as chaves nos formatos PEM."""

    if not senha:
        raise ValueError("Informe uma senha para proteger a chave privada.")

    senha_bytes = senha.encode("utf-8")

    if len(senha_bytes) < 8:
        raise ValueError("A senha deve ter pelo menos 8 bytes.")

    privada_pem = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            senha_bytes
        )
    )

    publica_pem = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("chave_privada.pem", "wb") as arquivo:
        arquivo.write(privada_pem)

    with open("chave_publica.pem", "wb") as arquivo:
        arquivo.write(publica_pem)


def gerar_certificado(chave_privada, chave_publica, salvar=False):
    """
    Cria um certificado X.509 autoassinado para testes.

    salvar=False: gera o certificado apenas em memória.
    salvar=True: salva também no arquivo certificado.pem.
    """

    nome = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "Certificado de Teste - Assinatura Digital"
        ),
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME,
            "Projeto Academico de Criptografia"
        ),
        x509.NameAttribute(
            NameOID.COUNTRY_NAME,
            "BR"
        )
    ])

    agora = datetime.now(timezone.utc)

    certificado = (
        x509.CertificateBuilder()
        .subject_name(nome)
        .issuer_name(nome)
        .public_key(chave_publica)
        .serial_number(x509.random_serial_number())
        .not_valid_before(agora)
        .not_valid_after(agora + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .sign(chave_privada, hashes.SHA256())
    )

    if salvar:
        certificado_pem = certificado.public_bytes(
            serialization.Encoding.PEM
        )

        with open("certificado.pem", "wb") as arquivo:
            arquivo.write(certificado_pem)

    return certificado


def carregar_chave_privada(caminho, senha):
    """Carrega uma chave privada PEM protegida por senha."""

    with open(caminho, "rb") as arquivo:
        dados = arquivo.read()

    chave_privada = serialization.load_pem_private_key(
        dados,
        password=senha.encode("utf-8")
    )

    return chave_privada


def assinar_arquivo(caminho_arquivo, chave_privada):
    """Gera a assinatura digital de um arquivo usando RSA-PSS."""

    with open(caminho_arquivo, "rb") as arquivo:
        conteudo = arquivo.read()

    assinatura = chave_privada.sign(
        conteudo,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.DIGEST_LENGTH
        ),
        hashes.SHA256()
    )

    return assinatura


def salvar_assinatura(assinatura, caminho_saida):
    """Salva a assinatura digital em um arquivo separado."""

    with open(caminho_saida, "wb") as arquivo:
        arquivo.write(assinatura)


def carregar_certificado(caminho):
    """Carrega um certificado digital X.509 no formato PEM."""

    with open(caminho, "rb") as arquivo:
        dados = arquivo.read()

    return x509.load_pem_x509_certificate(dados)


def verificar_assinatura(caminho_arquivo, caminho_assinatura, certificado):
    """Verifica a assinatura RSA-PSS usando a chave pública do certificado."""

    with open(caminho_arquivo, "rb") as arquivo:
        conteudo = arquivo.read()

    with open(caminho_assinatura, "rb") as arquivo:
        assinatura = arquivo.read()

    chave_publica = certificado.public_key()

    try:
        chave_publica.verify(
            assinatura,
            conteudo,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except InvalidSignature:
        return False


if __name__ == "__main__":
    print("=== Gerador de Chaves e Certificado Digital ===")

    from getpass import getpass

    senha = getpass("Digite uma senha para proteger a chave privada: ")

    chave_privada, chave_publica = gerar_chaves()

    salvar_chaves(chave_privada, chave_publica, senha)

    gerar_certificado(chave_privada, chave_publica, salvar=True)

    print("Chaves RSA geradas com sucesso!")
    print("Certificado X.509 autoassinado criado!")
    print("Arquivos gerados:")
    print("- chave_privada.pem")
    print("- chave_publica.pem")
    print("- certificado.pem")