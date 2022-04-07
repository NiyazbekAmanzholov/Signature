package digitalSignatureBaeldung;
//https://www.baeldung.com/java-digital-signature#encrypting_hash
import javax.crypto.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws IOException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
            NoSuchPaddingException, InvalidKeyException {

        System.out.println("Генерация хэша сообщения");
        byte[] messageBytes = Files.readAllBytes(Paths.get("C:\\Users\\DELL\\IdeaProjects\\test\\src\\main\\java\\digitalSignatureBaeldung\\msg.txt"));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = md.digest(messageBytes);
        System.out.println(Arrays.toString(messageHash));

///////////////////////////////////2 various

        System.out.println("5.2. Шифрование сгенерированного хэша");

        SignerUser signerUser = new SignerUser();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, signerUser.getPrivateKey());
        byte[] digitalSignature = cipher.doFinal(messageHash);
        Files.write(Paths.get("C:\\Users\\DELL\\IdeaProjects\\test\\src\\main\\java\\digitalSignatureBaeldung\\file.txt"), digitalSignature);

//////////////////////////////////3 various

//        System.out.println("5.3. Проверка подписи");
//
//        byte[] encryptedMessageHash = Files.readAllBytes(Paths.get("C:\\Users\\DELL\\IdeaProjects\\SuperPractice\\src\\main\\java\\folder\\My\\digitalSignatureBaeldung\\digital_signature_1.txt"));
//        //Для расшифровки мы создаем экземпляр шифра. Затем мы вызываем метод doFinal:
//
//        cipher.init(Cipher.DECRYPT_MODE, signerUser.getPrivateKey());
//        byte[] decryptedMessageHash = cipher.doFinal(encryptedMessageHash);
//        //Далее мы генерируем новый хэш сообщения из полученного сообщения:
//
//        byte[] newMessageHash = md.digest(messageBytes);
//        //И, наконец, мы проверяем, совпадает ли вновь сгенерированный хэш сообщения с расшифрованным:
//
//        boolean isCorrect = Arrays.equals(decryptedMessageHash, newMessageHash);
//        //В этом примере мы использовали текстовый файл message.txt чтобы смоделировать сообщение, которое мы хотим отправить,
//        // или расположение тела сообщения, которое мы получили. Обычно мы ожидаем получить наше сообщение вместе с подписью.
//
//        System.out.println(isCorrect);
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

