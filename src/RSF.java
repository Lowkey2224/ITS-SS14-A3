import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;

/**
 * Created by abe180 on 20.05.14.
 */
public class RSF {
    public static void main(String[] args) {
        String privateKeyfile = "MHuebner.prv";
        String publicKeyfile = "MHuebner.pub";
        String datafile = "foo.ssf";
        String outputFile = "foo.pdf";
        PublicKey publicKey = SSF.readPublicKeyFromFile(publicKeyfile, "RSA");
        PrivateKey privateKey = SSF.readPrivateKeyFromFile(privateKeyfile, "RSA");
        SecretKey sk;
        File encryptedFile = new File(datafile);
        DataInputStream is;
        try {
            long fileLength = encryptedFile.length();
            is = new DataInputStream(new FileInputStream(encryptedFile));
            int skLength = is.readInt();
            byte[] keyArray = new byte[skLength];
            is.read(keyArray);
            int signatureLength = is.readInt();
            byte[] sigArray = new byte[signatureLength];
            is.read(sigArray);
            long sum = skLength+signatureLength;
            long restBytes = (fileLength-sum);
            if(Integer.MAX_VALUE < restBytes)
            {
                System.out.println("FUCK!");
                return;
            }
            byte[] message = new byte[(int)restBytes];
            is.read(message);
            is.close();
            sk = decryptSecretKey(keyArray, privateKey);
            byte[] decryptedData = decryptDataFile(datafile, sk, outputFile);
//            File out = new File(outputFile);
//            DataOutputStream os = new DataOutputStream(new FileOutputStream(out));
//            os.write(decryptedData);
//            os.close();



        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }


    public static SecretKey decryptSecretKey(byte[] sk,PrivateKey pk)
    {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, pk);
//            System.out.println("Cipher Parameter: "
//                    + cipher.getParameters().toString());
//            AlgorithmParameters ap = cipher.getParameters();

            // die zu schuetzenden Daten


            // nun werden die Daten verschluesselt
            // (update wird bei grossen Datenmengen mehrfach aufgerufen werden!)
//            byte[] encData = cipher.update();

            // mit doFinal abschliessen (Rest inkl. Padding ..)
            byte[] encRest = cipher.doFinal(sk);
//            byte[] both = new byte[encData.length+encRest.length];
//
//            System.arraycopy(encData, 0, both, 0, encData.length);
//            System.arraycopy(encRest, 0, both, encData.length, encRest.length);
////            KeyFactory keyFactory = KeyFactory.getInstance("AES");

            return new SecretKeySpec(encRest, "AES");




        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] decryptDataFile(String filename, SecretKey secretKey, String outFile)
    {
        DataInputStream is = null;
        try {
//            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            Cipher cipher = Cipher.getInstance("AES");

            // Initialisierung

            byte[] v = new byte[16];
            File ivFile = new File("iv");
            DataInputStream foo = new DataInputStream(new FileInputStream(ivFile));
            foo.readFully(v);
            foo.close();

//            cipher.init(Cipher.DECRYPT_MODE, skey, new IvParameterSpec(v));
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            // Der Initialisierungsvektor IV muss dem EMPFAENGER spaeter als
            // Parameter mit uebergeben werden (falls nicht Betrieb im
            // ECB-Modus), daher muessen die erzeugten Parameter aus dem
            // Cipher-Objekt ausgelesen werden.
            if(cipher.getParameters() != null){
                System.out.println("Cipher Parameter: "
                        + cipher.getParameters().toString());
                AlgorithmParameters ap = cipher.getParameters();
            }


            // die zu schuetzenden Daten
            File file = new File(filename);
            File out = new File(outFile);
            DataOutputStream os = new DataOutputStream(new FileOutputStream(out));
            is = new DataInputStream(new FileInputStream(
                    file));

            byte[] plain = new byte[16];
            int bytesRead = 0;
            int fileLengthModulo = (int)(file.length()%16);
            while (( bytesRead =is.read(plain)) == 16)
            {
                os.write(cipher.update(plain));
                plain = new byte[16];
            }
            if(fileLengthModulo!=0)
            {
                byte[] rest = new byte[bytesRead];
                System.arraycopy(plain, 0, rest, 0, bytesRead);
                os.write(cipher.doFinal(rest));
            }else{
                os.write(cipher.doFinal());
            }
//            is.readFully(plain);
//            System.out.println("Daten: " + new String(plain));

            // nun werden die Daten verschluesselt
            // (update wird bei grossen Datenmengen mehrfach aufgerufen werden!)
//            byte[] encData = cipher.update();

            // mit doFinal abschliessen (Rest inkl. Padding ..)
//            byte[] encRest = cipher.doFinal(plain);
//            byte[] both = new byte[encData.length+encRest.length];
//
//            System.arraycopy(encData, 0, both, 0, encData.length);
//            System.arraycopy(encRest, 0, both, encData.length, encRest.length);
            os.close();
            return plain;
        }catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }

    }

}
