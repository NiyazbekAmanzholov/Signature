/*
 * Чтобы изменить этот заголовок лицензии, выберите Заголовки лицензий в Свойствах проекта.
 * Чтобы изменить этот файл шаблона, выберите Инструменты | Шаблоны
 * и откройте шаблон в редакторе.
 */
package digitalSignature;

import java.security.*;


//The Digital Signature Algorithm (DSA)
//Алгоритм DSA включает в себя четыре операции: генерацию ключа (которая создает пару ключей), распределение ключей, подписание и проверку подписи.
public class DSA {
     public static void main(String[] args) {
            try{
                //Отправитель Формирует Цифровую Подпись для Сообщения
                  SignerUser  signer = new SignerUser ();
                  String message = "Every sunset give us one day less to live. But every sunrise give uso ne day more to hope.";
                                 
                byte[] sign = signMessage(message.getBytes(), signer.getPrivateKey());
                
                //Сохраняет открытый Ключ, чтобы быть Отправлено Получателю
                PublicKey pubKey = signer.getPubKey();

                System.out.println("--- Пример с действительной подписью ---");
                validateMessageSignature(pubKey, message.getBytes(), sign);

                System.out.println("--- Example with a invalid signature: the message was changed - Пример с недопустимой подписью: сообщение было изменено  ---");
                String anotherMessage = "Don't let yesterday take up too much of today.";
                validateMessageSignature(pubKey, anotherMessage.getBytes(), sign);

                String message2 = "The pessimist sees difficulty in every opportunity.";
                SignerUser signerB = new SignerUser ();
                PublicKey pubKey2 = signerB.getPubKey();
                byte[] sign2 = signMessage(message2.getBytes(), signerB.getPrivateKey());
                

                System.out.println("--- Example with a invalid signature: using signature that does not match with the current message - Пример с недопустимой подписью: использование подписи, которая не совпадает с текущим сообщением ---");
                validateMessageSignature(pubKey, message.getBytes(), sign2);

                System.out.println("--- Example with a invalid signature: using public key from another user - Пример с недопустимой подписью: использование открытого ключа от другого пользователя ---");
                validateMessageSignature(pubKey2, message.getBytes(), sign);

        }catch(Exception e){
            e.printStackTrace();
        }
    }
    
    

    public static void validateMessageSignature(PublicKey publicKey, byte[] message, byte[] signature) throws
        NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature clientSig = Signature.getInstance("DSA");
        clientSig.initVerify(publicKey);
        clientSig.update(message);
        if (clientSig.verify(signature)) {
           System.out.println("The message is properly signed - Сообщение подписано должным образом.");
        } else {
           System.err.println("It is not possible to validate the signature - Невозможно проверить подпись.");
        }
    }
    
     public static byte[] signMessage(byte[] message,PrivateKey privateKey) throws NoSuchAlgorithmException,
        InvalidKeyException, SignatureException {
              Signature sig = Signature.getInstance("DSA");
              sig.initSign(privateKey);
              sig.update(message);
              byte[] sign= sig.sign();
              return sign;
        }
    
    
    public static class SignerUser {
        private PublicKey publicKey;
        private PrivateKey privateKey;
        public PublicKey getPubKey() {
              return publicKey;
        }
        
        public SignerUser() throws NoSuchAlgorithmException{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
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