/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package assinaturadigital;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Scanner;

/**
 *
 * @author jesim
 */
public class AssinaturaDigitalRead {

    public static boolean verifySignedString(String base64signature, String base64text, String crt) {
        try {
            FileInputStream fin = new FileInputStream(crt);
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            Certificate certificate = f.generateCertificate(fin);
            PublicKey pk = certificate.getPublicKey();

            byte[] signatureBytes = Base64.getDecoder().decode(base64signature);
            String text = new String(Base64.getDecoder().decode(base64text));

            Signature signature;
            signature = Signature.getInstance("SHA1WithRSA");

            signature.initVerify(pk);
            signature.update(text.getBytes(StandardCharsets.UTF_8));

            return signature.verify(signatureBytes);

        } catch (InvalidKeyException | SignatureException | FileNotFoundException | NoSuchAlgorithmException | CertificateException e) {
            System.out.println(e.getMessage());
            return false;
        }
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here

        try {
            Scanner leEntrada = new Scanner(System.in);
            
            System.out.println("Digite o nome do arquivo txt a ser verificado com extensão");
            String nomeArquivo = leEntrada.nextLine();
            System.out.println("Digite o nome do arquivo crt com extensão");
            String crt = leEntrada.nextLine();
            String base64text = null;
            String base64signature = null;
            String subscriber = null;

            FileReader fr = new FileReader(nomeArquivo);
            BufferedReader br = new BufferedReader(fr);

            String str;

            for (int i = 0; (str = br.readLine()) != null; i++) {
                if (i == 4) {
                    subscriber = str.split(":")[1];
                } else if (i == 7) {
                    base64text = str;
                } else if (i == 10) {
                    base64signature = str;
                    break;
                }
            }


            if (verifySignedString(base64signature, base64text, crt)) {
                System.out.printf("Documento íntegro e assinado por %s\n", subscriber);
            } else {
                System.out.println("Documento não é íntegro");
            }

        } catch (FileNotFoundException e) {
            System.err.println("Arquivo não encontrado.");
        } catch (IOException ex) {
            System.err.println("Ocorreu um erro, tente novamente!");
        }
    }

}
