# Módulo de Assinatura Digital e Certificado Digital

## 1. Descrição

Este módulo integra o projeto acadêmico Fundamentos de Criptografia Aplicada e implementa funcionalidades de geração de chaves criptográficas, criação de certificados digitais, assinatura e verificação de arquivos.

A aplicação foi desenvolvida em Python, utilizando Streamlit para a interface gráfica e a biblioteca Cryptography para as operações criptográficas.

## 2. Tecnologias utilizadas

- Python
- Streamlit
- Cryptography
- RSA de 2048 bits
- RSA-PSS com SHA-256
- Certificados digitais X.509
- OpenSSL para testes de certificados

## 3. Funcionalidades

### Geração de chaves e certificado

Permite gerar um par de chaves RSA de 2048 bits, proteger a chave privada com senha e criar um certificado digital X.509 autoassinado.

Os arquivos podem ser baixados separadamente nos formatos PEM.

### Assinatura digital

Permite selecionar um arquivo, carregar uma chave privada protegida por senha e gerar uma assinatura digital utilizando RSA-PSS e SHA-256.

A assinatura é disponibilizada para download em um arquivo separado, com extensão `.sig`.

### Verificação de assinatura

Permite selecionar o documento, a assinatura e o certificado digital correspondente.

A aplicação extrai a chave pública do certificado e verifica criptograficamente a assinatura, apresentando uma mensagem de validade ou invalidade.

## 4. Estrutura dos arquivos

- `app.py`: interface gráfica desenvolvida com Streamlit.
- `crypto_utils.py`: funções de geração de chaves, certificados, assinatura e verificação.
- `requirements.txt`: dependências necessárias para executar a aplicação.
- `README.md`: documentação do módulo.

## 5. Como executar

No terminal, acesse a pasta do módulo:

```bash
cd modulo-assinatura-digital
```

Instale as dependências:

```bash
python -m pip install -r requirements.txt
```

Execute a aplicação:

```bash
python -m streamlit run app.py
```

No GitHub Codespaces, abra a aplicação pela porta 8501.

## 6. Testes realizados

Foram executados cinco cenários:

1. Documento original com assinatura correspondente: assinatura válida.
2. Documento alterado após a assinatura: assinatura inválida.
3. Assinatura digital modificada: assinatura inválida.
4. Certificado contendo chave pública diferente: assinatura inválida.
5. Certificado autoassinado: aceito quando explicitamente fornecido como referência de confiança e rejeitado na verificação sem âncora de confiança.

Os testes demonstraram o funcionamento dos mecanismos criptográficos implementados.

## 7. Considerações de segurança

A chave privada é protegida por senha, e os arquivos criptográficos de teste são excluídos do versionamento por meio do `.gitignore`.

Os certificados autoassinados são utilizados exclusivamente para fins acadêmicos e não possuem confiança automática de uma Autoridade Certificadora reconhecida.

A aplicação realiza a verificação criptográfica das assinaturas, mas não implementa validação completa da cadeia de certificação, consulta de revogação ou comprovação independente da identidade do titular.

## 8. Integração

O módulo foi desenvolvido de forma independente para permitir sua integração ao projeto compartilhado de criptografia aplicada.