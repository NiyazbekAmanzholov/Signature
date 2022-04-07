package realySignature;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
//        ����� ������ ������� ����������, �� ������� ������� ��������� ������ Signature. ��� ����� ��� �����
//        �������� �������. ����� �� �������������� ������� ����� �������� ������:

//        �������� �������, ������� �� �������, SHA256withRSA � ���� �������, ������������ ����� ����������
//        ��������� ����������� � ��������� ����������.
        Signature signature = Signature.getInstance("SHA256withRSA");
        SignerUser signerUser = new SignerUser();//���������
        signature.initSign(signerUser.getPrivateKey());



//        ����� ���������� � ���������� ������� ������ ���������:
        byte[] messageBytes = Files.readAllBytes(Paths.get("C:\\Users\\DELL\\IdeaProjects\\test\\src\\main\\java\\realySignature\\message.txt"));

        signature.update(messageBytes);
        byte[] digitalSignature = signature.sign();

        //�� ����� ��������� ������� � ���� ��� ����������� ��������:
        Files.write(Paths.get("C:\\Users\\DELL\\IdeaProjects\\test\\src\\main\\java\\realySignature\\digital_signature_2.txt"), digitalSignature);








        //6.2. �������� �������

        //����� ��������� ���������� �������, �� ����� ������� ��������� �������:
        Signature signature2 = Signature.getInstance("SHA256withRSA");

        //����� �� �������������� ������ ������� ��� ��������, ������� ����� initVerify, ������� ��������� �������� ����:
        signature2.initVerify(signerUser.getPublicKey());

        //����� ��� ����� �������� ���������� ����� ��������� � ������ �������, ������ ����� update:
        byte[] messageBytes2 = Files.readAllBytes(Paths.get("C:\\Users\\DELL\\IdeaProjects\\test\\src\\main\\java\\realySignature\\message.txt"));

        //����� ��� ����� �������� ���������� ����� ��������� � ������ �������, ������ ����� update:
        signature2.update(messageBytes2);

        //�, �������, �� ����� ��������� �������, ������ ����� verify:
        boolean isCorrect = signature2.verify(digitalSignature);
        System.out.println(isCorrect);
    }


    ////////////////////user
    static class SignerUser {
        private PublicKey publicKey;
        private PrivateKey privateKey;

        public SignerUser() throws NoSuchAlgorithmException {

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            SecureRandom secRan = new SecureRandom();
            kpg.initialize(512, secRan);
            KeyPair keyP = kpg.generateKeyPair();
            this.publicKey= keyP.getPublic();
            this.privateKey = keyP.getPrivate();
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(PrivateKey privateKey) {
            this.privateKey = privateKey;
        }
    }
}