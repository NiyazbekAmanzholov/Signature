package realySignature;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
//        Чтобы начать процесс подписания, мы сначала создаем экземпляр класса Signature. Для этого нам нужен
//        алгоритм подписи. Затем мы инициализируем подпись нашим закрытым ключом:

//        Алгоритм подписи, который мы выбрали, SHA256withRSA в этом примере, представляет собой комбинацию
//        алгоритма хеширования и алгоритма шифрования.
        Signature signature = Signature.getInstance("SHA256withRSA");
        SignerUser signerUser = new SignerUser();//Подписант
        signature.initSign(signerUser.getPrivateKey());



//        Далее приступаем к подписанию массива байтов сообщения:
        byte[] messageBytes = Files.readAllBytes(Paths.get("C:\\Users\\DELL\\IdeaProjects\\test\\src\\main\\java\\realySignature\\message.txt"));

        signature.update(messageBytes);
        byte[] digitalSignature = signature.sign();

        //Мы можем сохранить подпись в файл для последующей передачи:
        Files.write(Paths.get("C:\\Users\\DELL\\IdeaProjects\\test\\src\\main\\java\\realySignature\\digital_signature_2.txt"), digitalSignature);








        //6.2. Проверка подписи

        //Чтобы проверить полученную подпись, мы снова создаем экземпляр подписи:
        Signature signature2 = Signature.getInstance("SHA256withRSA");

        //Далее мы инициализируем объект подписи для проверки, вызывая метод initVerify, который принимает открытый ключ:
        signature2.initVerify(signerUser.getPublicKey());

        //Затем нам нужно добавить полученные байты сообщения в объект подписи, вызвав метод update:
        byte[] messageBytes2 = Files.readAllBytes(Paths.get("C:\\Users\\DELL\\IdeaProjects\\test\\src\\main\\java\\realySignature\\message.txt"));

        //Затем нам нужно добавить полученные байты сообщения в объект подписи, вызвав метод update:
        signature2.update(messageBytes2);

        //И, наконец, мы можем проверить подпись, вызвав метод verify:
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