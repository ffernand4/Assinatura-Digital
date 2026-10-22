
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static string pasta = AppContext.BaseDirectory;
    static string arquivoPublica = Path.Combine(pasta, "chave_publica.pem");
    static string arquivoPrivada = Path.Combine(pasta, "chave_privada.pem");

    static string mensagemOriginal = "";
    static string mensagemCriptografada = "";

    static void Main()
    {
        int opcao = -1;

        while (opcao != 0)
        {
            Console.WriteLine("\n=== CRIPTOGRAFIA ASSIMETRICA RSA ===");
            Console.WriteLine("1 - Gerar chaves");
            Console.WriteLine("2 - Criptografar mensagem");
            Console.WriteLine("3 - Descriptografar mensagem");
            Console.WriteLine("4 - Testar chave privada incorreta");
            Console.WriteLine("0 - Sair");
            Console.Write("Escolha: ");

            if (!int.TryParse(Console.ReadLine(), out opcao))
            {
                Console.WriteLine("Digite uma opcao valida.");
                opcao = -1;
                continue;
            }

            try
            {
                switch (opcao)
                {
                    case 1:
                        GerarChaves();
                        break;

                    case 2:
                        Criptografar();
                        break;

                    case 3:
                        Descriptografar();
                        break;

                    case 4:
                        TestarChaveIncorreta();
                        break;

                    case 0:
                        Console.WriteLine("Programa encerrado.");
                        break;

                    default:
                        Console.WriteLine("Opcao invalida.");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erro: " + ex.Message);
            }
        }
    }

    static void GerarChaves()
    {
        using (RSA rsa = RSA.Create(2048))
        {
            string publica = rsa.ExportSubjectPublicKeyInfoPem();
            string privada = rsa.ExportPkcs8PrivateKeyPem();

            File.WriteAllText(arquivoPublica, publica);
            File.WriteAllText(arquivoPrivada, privada);
        }

        mensagemOriginal = "";
        mensagemCriptografada = "";

        Console.WriteLine("\nChaves geradas com sucesso!");
        Console.WriteLine("Chave publica: " + arquivoPublica);
        Console.WriteLine("Chave privada: " + arquivoPrivada);
        Console.WriteLine("A chave privada deve ser mantida em seguranca.");
    }

    static void Criptografar()
    {
        if (!File.Exists(arquivoPublica))
        {
            Console.WriteLine("Gere as chaves primeiro.");
            return;
        }

        Console.Write("Digite uma mensagem curta: ");
        mensagemOriginal = Console.ReadLine() ?? "";

        if (Encoding.UTF8.GetByteCount(mensagemOriginal) > 190)
        {
            Console.WriteLine("A mensagem deve ter no maximo 190 bytes.");
            return;
        }

        using (RSA rsa = RSA.Create())
        {
            rsa.ImportFromPem(File.ReadAllText(arquivoPublica));

            byte[] dados = Encoding.UTF8.GetBytes(mensagemOriginal);

            byte[] criptografados = rsa.Encrypt(
                dados,
                RSAEncryptionPadding.OaepSHA256
            );

            mensagemCriptografada =
                Convert.ToBase64String(criptografados);
        }

        Console.WriteLine("\nMensagem criptografada:");
        Console.WriteLine(mensagemCriptografada);
    }

    static void Descriptografar()
    {
        if (!File.Exists(arquivoPrivada))
        {
            Console.WriteLine("Gere as chaves primeiro.");
            return;
        }

        if (string.IsNullOrEmpty(mensagemCriptografada))
        {
            Console.WriteLine("Criptografe uma mensagem primeiro.");
            return;
        }

        using (RSA rsa = RSA.Create())
        {
            rsa.ImportFromPem(File.ReadAllText(arquivoPrivada));

            byte[] dados = Convert.FromBase64String(
                mensagemCriptografada
            );

            byte[] descriptografados = rsa.Decrypt(
                dados,
                RSAEncryptionPadding.OaepSHA256
            );

            string resultado = Encoding.UTF8.GetString(
                descriptografados
            );

            Console.WriteLine("\nMensagem recuperada:");
            Console.WriteLine(resultado);

            Console.WriteLine(
                resultado == mensagemOriginal
                ? "Teste aprovado: a mensagem confere!"
                : "A mensagem nao confere."
            );
        }
    }

    static void TestarChaveIncorreta()
    {
        if (string.IsNullOrEmpty(mensagemCriptografada))
        {
            Console.WriteLine("Criptografe uma mensagem primeiro.");
            return;
        }

        using (RSA outraChave = RSA.Create(2048))
        {
            try
            {
                byte[] dados = Convert.FromBase64String(
                    mensagemCriptografada
                );

                byte[] resultado = outraChave.Decrypt(
                    dados,
                    RSAEncryptionPadding.OaepSHA256
                );

                Console.WriteLine(
                    "Resultado inesperado: " +
                    Encoding.UTF8.GetString(resultado)
                );
            }
            catch (CryptographicException)
            {
                Console.WriteLine(
                    "Teste aprovado: a chave privada incorreta " +
                    "nao conseguiu descriptografar a mensagem."
                );
            }
        }
    }
}
