

public class Main {
    public static String encryptMessage(String message, PrivateKey privateKeyA, PublicKey publicKeyB) throws Exception {
        // Generate the first AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // AES-256
        SecretKey aesKey1 = keyGen.generateKey();

        // Encrypt the message with the first AES key
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey1);
        byte[] encryptedMessageBytes = aesCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        String encryptedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);

        // Encrypt the first AES key with Client A's private key
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, privateKeyA);
        byte[] encryptedAesKey1Bytes = rsaCipher.doFinal(aesKey1.getEncoded());
        String firstEncryptedAesKey = Base64.getEncoder().encodeToString(encryptedAesKey1Bytes);

        // Generate the second AES key
        SecretKey aesKey2 = keyGen.generateKey();

        // Encrypt the already encrypted message with the second AES key
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey2);
        encryptedMessageBytes = aesCipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        encryptedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);

        // Encrypt the second AES key with Client B's public key
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKeyB);
        byte[] encryptedAesKey2Bytes = rsaCipher.doFinal(aesKey2.getEncoded());
        String secondEncryptedAesKey = Base64.getEncoder().encodeToString(encryptedAesKey2Bytes);

        // Concatenate and return
        return firstEncryptedAesKey + ":" + secondEncryptedAesKey + ":" + encryptedMessage;
    }

    public static String decryptMessage(String encryptedData, PrivateKey privateKeyB, PublicKey publicKeyA) throws Exception {
        // Split the encrypted data to get the two encrypted AES keys and the encrypted message
        String[] parts = encryptedData.split(":");
        String firstEncryptedAesKey = parts[0];
        String secondEncryptedAesKey = parts[1];
        String encryptedMessage = parts[2];

        // Decode the second encrypted AES key
        byte[] secondEncryptedAesKeyBytes = Base64.getDecoder().decode(secondEncryptedAesKey);

        // Decrypt the second AES key with Client B's private key
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKeyB);
        byte[] aesKey2Bytes = rsaCipher.doFinal(secondEncryptedAesKeyBytes);

        // Reconstruct the second AES key
        SecretKey aesKey2 = new javax.crypto.spec.SecretKeySpec(aesKey2Bytes, "AES");

        // Decrypt the message with the second AES key
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey2);
        byte[] encryptedMessageBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedMessageBytes = aesCipher.doFinal(encryptedMessageBytes);

        // Decode the first encrypted AES key
        byte[] firstEncryptedAesKeyBytes = Base64.getDecoder().decode(firstEncryptedAesKey);

        // Decrypt the first AES key with Client A's public key
        rsaCipher.init(Cipher.DECRYPT_MODE, publicKeyA);
        byte[] aesKey1Bytes = rsaCipher.doFinal(firstEncryptedAesKeyBytes);

        // Reconstruct the first AES key
        SecretKey aesKey1 = new javax.crypto.spec.SecretKeySpec(aesKey1Bytes, "AES");

        // Decrypt the message with the first AES key
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey1);
        decryptedMessageBytes = aesCipher.doFinal(decryptedMessageBytes);

        // Convert decrypted bytes to string
        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
    }
}