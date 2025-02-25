import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.*;

/**
 * @author Vinlaw Mudehwe (vzm@case.edu)
 **/

public class PasswordManager {



    // Static variables for global access
    private static final Scanner scanner = new Scanner(System.in);
    private static final String filePath = "passwords.txt";
    private static final File passwordsFile = new File(filePath);
    private static final Cipher cipher;

    static {
        try {
            cipher = Cipher.getInstance("AES"); // ✅ Initialize Cipher properly
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    // Helper method to generate a salt if it does not exist
    public static byte[] generateSalt(){
        SecureRandom random = new SecureRandom();
        byte [] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    // Helper method to generate the private key from salt and password
    public static SecretKeySpec generateKey(byte[] salt, String keyString){
        KeySpec spec = new PBEKeySpec(keyString.toCharArray(), salt, 1024, 128);

        try{
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey privateKey = factory.generateSecret(spec);
            return new SecretKeySpec(privateKey.getEncoded(), "AES");

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    // Helper method to load all the passwords in the file
    public static LinkedHashMap<String, String> loadPasswords(){
        LinkedHashMap<String, String> passwords = new LinkedHashMap<>();

        try(BufferedReader reader = new BufferedReader(new FileReader(filePath))){
            String line;
            while ((line = reader.readLine()) != null) {
                String[] valuePairs = line.split(":", 2);
                passwords.put(valuePairs[0], valuePairs[1]);
            }
        }catch (IOException e){
            throw new RuntimeException(e);
        }
        return passwords;
    }

    // Helper method to get the salt
    public static String getSalt(String filePath) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            return reader.readLine().split(":")[0];
        }
    }

    // Helper method to get the corresponding password when a label is provided
    public static String getPassword(String label){
        Map<String, String> passwords = loadPasswords();
        return passwords.getOrDefault(label, null);
    }

    // Helper method to push a new password to the manager
    public static void pushPassword(String label, String value) {
        LinkedHashMap<String, String> passwords = loadPasswords(); // Load existing passwords

        passwords.put(label, value); // Update or add new password

        // Write everything back to the file
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath, false))) {
            for (Map.Entry<String, String> entry : passwords.entrySet()) {
                writer.write(entry.getKey() + ":" + entry.getValue());
                writer.newLine();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    // Helper method to verify entered password to the true one
    public static boolean verifyPassword(String enteredPassword, String storedKey, String salt){
        byte[] saltBytes = Base64.getDecoder().decode(salt);
        SecretKeySpec derivedKey = generateKey(saltBytes, enteredPassword);
        String derivedKeyString = Base64.getEncoder().encodeToString(derivedKey.getEncoded());
        return derivedKeyString.equals(storedKey);
    }

    // Helper method for encrypting the provided password
    public static String encrypt(SecretKeySpec key, String password){

        try{
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte [] encryptedPassword = cipher.doFinal(password.getBytes());
            return new String(Base64.getEncoder().encode(encryptedPassword));

        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    // Helper method for decrypting existing passwords
    public static String decrypt(SecretKeySpec key, String password){

        byte [] encryptedPassword = Base64.getDecoder().decode(password);
        try{
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte [] decryptedPassword = cipher.doFinal(encryptedPassword);
            return new String(decryptedPassword);

        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    //Main method exposing the workflow of the password manager
    public static void main(String[] args) throws IOException {

        System.out.println("Enter the passcode to access your passwords: ");
        String enteredPassword = scanner.nextLine();

        if(!passwordsFile.exists()){
            try{
                System.out.println("No password file detected. Creating a new password file.");
                boolean success = passwordsFile.createNewFile();

                if (success){
                    System.out.println("A new password file has been successfully created.");

                    byte [] salt = generateSalt();
                    SecretKeySpec key = generateKey(salt, enteredPassword);
                    String keyString = Base64.getEncoder().encodeToString(key.getEncoded());
                    String saltString = Base64.getEncoder().encodeToString(salt);
                    pushPassword(saltString, keyString);
                }
                else{
                    System.out.println("Password file could not be created.");
                    return;
                }
            }
            catch (IOException e){
                System.out.println("There was an error creating the passwords file: " + e.getMessage());
                return;
            }
        }

        String salt = getSalt(filePath);
        String managerPassword = getPassword(salt);
        boolean validPassword = verifyPassword(enteredPassword, managerPassword, salt);

        if(!validPassword){
            System.out.println("Invalid password provided");
            return;
        }

        byte[] decodedKey = Base64.getDecoder().decode(managerPassword);
        SecretKeySpec key = new SecretKeySpec(decodedKey, "AES");

        while(true) {

            System.out.print(
                    "a : Add Password\n" +
                            "r : Read Password\n" +
                            "q : Quit\n" +
                            "Enter choice: ");

            String choice = scanner.nextLine();

            switch (choice) {
                case "a":
                    System.out.println("Enter label for password: ");
                    String entryLabel = scanner.nextLine();
                    System.out.println("Enter password to store: ");
                    String newPassword = scanner.nextLine();
                    String newEncryptedPassword = encrypt(key, newPassword);
                    pushPassword(entryLabel, newEncryptedPassword);
                    System.out.println("Password successfully added.");
                    break;


                case "r":
                    System.out.println("Enter label for password: ");
                    String retrievalLabel = scanner.nextLine();
                    String encryptedRetrievedPassword = getPassword(retrievalLabel);

                    if (encryptedRetrievedPassword == null) {
                        System.out.println("Password label does not exist.");
                        break;
                    }

                    String retrievedPassword = decrypt(key, encryptedRetrievedPassword);
                    System.out.println("Found: " + retrievedPassword);
                    break;

                case "q":
                    System.out.println("Quitting");
                    return;

                default:
                    System.out.println("Invalid choice chosen. Exiting program");
                    break;
            }
        }
    }
}