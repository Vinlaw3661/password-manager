import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Scanner;

public class Main {

    // Helper method to generate a salt if it does not exist
    public static byte[] generateSalt(){
        SecureRandom random = new SecureRandom();
        byte [] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    public static byte[] generatePrivateKey(byte[] salt, String keyString){
        KeySpec spec = new PBEKeySpec(keyString.toCharArray(), salt, 1024, 128);

        try{
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey privateKey = factory.generateSecret(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        return salt;
    }

    //Helper method for encrypting the provided password
    public static String encrypt(){
        return "";
    }

    //Helper method for decrypting existing passwords
    public static String decrypt(){
        return "";
    }



    //Main method exposing the workflow of the password manager
    public static void main(String[] args) throws IOException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter the passcode to access your passwords: ");
        String passCode = scanner.nextLine();

        File passwordsFIle = new File("passwords.txt");

        if(!passwordsFIle.exists()){
            try{
                boolean success = passwordsFIle.createNewFile();

                if (success){
                    System.out.println("A new password file has been created.");
                }

                else{
                    System.out.println("Password file could not be created.");
                }
            }
            catch (IOException e){
                System.out.println("There was an error creating the passwords file.");
            }

        }

        else{
            return;
        }
    }
}