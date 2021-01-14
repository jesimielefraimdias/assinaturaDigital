/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package assinaturadigital;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Scanner;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;

/**
 *
 * @author jesim
 */
public class AssinaturaDigitalWrite {

    public static String signature(String p12, String text) {
        try {

            String keyStoreEntryAlias = "SAS_user";
            String keyStorePassword = "Seguranca";
            String keyPassword = "Seguranca";
            Signature signature;
            signature = Signature.getInstance("SHA1WithRSA");

            FileInputStream is = new FileInputStream(p12);
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(is, keyStorePassword.toCharArray());

            Key key = keyStore.getKey(keyStoreEntryAlias, keyPassword.toCharArray());
            Certificate certificate = keyStore.getCertificate(keyStoreEntryAlias);
            PublicKey publicKey = certificate.getPublicKey();
            KeyPair keyPair = new KeyPair(publicKey, (PrivateKey) key);

            signature.initSign(keyPair.getPrivate());
            signature.update(text.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = signature.sign();

            return Base64.getEncoder().encodeToString(signatureBytes);

        } catch (NoSuchAlgorithmException | IOException | KeyStoreException | CertificateException | UnrecoverableKeyException | InvalidKeyException | SignatureException ex) {
            System.out.println(ex.getMessage());
            return null;
        }
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            Scanner leEntrada = new Scanner(System.in);

            System.out.println("Digite o nome do arquivo txt a ser assinado com a extensão");
            String nomeArquivo = leEntrada.nextLine();
            System.out.println("Digite o nome do arquivo p12 com a extensão");
            String p12 = leEntrada.nextLine();

            //Funções para ler o arquivo a ser escrito.
            FileReader fr = new FileReader(nomeArquivo);
            BufferedReader br = new BufferedReader(fr);
            //String que receberá o texto.
            String text = "";
            String subText;

            //Pego linha a linha do texto e concateno na string text.
            while ((subText = br.readLine()) != null) {
                text += subText;
            }
            //Codifico o texto para base 64.
            String encoded = Base64.getEncoder().encodeToString(text.getBytes());
            //Nome do arquivo de saída+extensão.
            String outDoc = "outDoc.txt";
            //Assinatura do arquivo.
            String assinatura = signature(p12, text);
            if (assinatura == null) {
                throw new Error("Não foi possível assinar o documento");
            }

            String doc = "-----BEGIN DOCSIGNED-----\n"
                    + "doc:" + nomeArquivo + "\n"
                    + "alg:RSA\n"
                    + "hash:SHA1\n"
                    + "assinante:" + p12.split("[.]")[0]
                    + "\n\n-----BEGIN DOC-----\n";
            doc += encoded;
            doc += "\n-----END DOC-----\n"
                    + "-----BEGIN SIGNATURE-----\n";
            doc += assinatura + "\n";
            doc += "-----END SIGNATURE-----\n"
                    + "-----END DOCSIGNED-----\n";

            FileWriter fw = new FileWriter(outDoc);
            PrintWriter pw = new PrintWriter(fw);

            pw.print(doc);

            pw.close();
        } catch (FileNotFoundException e) {
            System.err.println("Arquivo a ser escrito não foi encontrado.");
        } catch (IOException ex) {
            System.err.println("Ocorreu um erro, tente novamente!");
        } catch (Error e) {
            System.err.println("Ocorreu um erro na sua assinatura!");
        }
    }

}
