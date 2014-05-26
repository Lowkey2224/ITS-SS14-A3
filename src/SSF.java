


import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by Loki on 19.05.2014.
 */
public class SSF {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";
//    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final boolean WITH_IV = false;

    public static void main(String[] args) {
        if(args.length != 4){
            System.out.println("Wrong Parameters given!");
            return;
        }
        String prvkeyFile = args[0];
        System.out.println("Private Key: "+ prvkeyFile);
        String pubkeyFile = args[1];
        System.out.println("Public Key: "+ pubkeyFile);
        String datafile = args[2];
        System.out.println("file to be encrypted: "+ datafile);
        String outputFile = args[3];
        System.out.println("encrypted file: "+ outputFile);

//        String prvkeyFile = "MHuebner.prv";
//        String pubkeyFile = "MHuebner.pub";
//        String datafile = "src/ITSAufgabe3.pdf";
//        String outputFile = "foo.ssf";

        PrivateKey prvKey =  readPrivateKeyFromFile(prvkeyFile);

        PublicKey pubKey = readPublicKeyFromFile(pubkeyFile);
        SecretKey sk = createSecretKey();

        byte[] encryptedSecretKey = encryptSecretKey(sk, pubKey);
        byte[] singedKey = signSecretKey(sk, prvKey);

        File outFile = new File(outputFile);
        DataOutputStream os;
        try {
            os= new DataOutputStream(new FileOutputStream(outFile));
            int f = encryptedSecretKey.length;
            os.writeInt(f);


//            os.write(encryptedSecretKey.length);

            os.write(encryptedSecretKey);
            os.writeInt(singedKey.length);
            os.write(singedKey);
            byte[] encryptedFileData = encryptDataFile(datafile, sk, os);
//            os.write(encryptedFileData);
            os.close();
            System.out.println("File Encrypted");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static PrivateKey readPrivateKeyFromFile(String filename)
    {
        PrivateKey ret = null;
        byte[] message = null;
        DataInputStream is = null;
        try {
            is = new DataInputStream(new FileInputStream(
                    filename));

            // die Nachricht
            int nameLength  = is.readInt();
            message = new byte[nameLength];
            //TODO Check return value of read
            is.read(message);
            int keyLength = is.readInt();
            message = new byte[keyLength];
            is.read(message);
            is.close();
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec =  new PKCS8EncodedKeySpec(message);
            ret = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        } catch (java.io.IOException e) {
            e.printStackTrace();
        }finally {

            return ret;

        }
    }

    public static PublicKey readPublicKeyFromFile(String filename)
    {
        PublicKey ret = null;
        byte[] message;
        DataInputStream is;
        try {
            is = new DataInputStream(new FileInputStream(
                    filename));

            // die Nachricht
            int nameLength  = is.readInt();
            message = new byte[nameLength];
            //TODO Check return value of read
            is.read(message);
            int keyLength = is.readInt();
            message = new byte[keyLength];
            is.read(message);
            is.close();
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            X509EncodedKeySpec x509EncodedKeySpec =  new X509EncodedKeySpec(message);
            return keyFactory.generatePublic(x509EncodedKeySpec);

        } catch (java.io.IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();

        }
        return null;
    }

    public static SecretKey createSecretKey()
    {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(AES_ALGORITHM);
            kg.init(128); // Schluessellaenge
            return kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

    }

    public static byte[] signSecretKey(SecretKey key, PrivateKey privateKey)
    {

        Signature rsaSig;
        byte[] signature;
        try {
            // als Erstes erzeugen wir das Signatur-Objekt
            rsaSig = Signature.getInstance("SHA1withRSA");
            // zum Signieren benoetigen wir den privaten Schluessel (hier: RSA)
            rsaSig.initSign(privateKey);
            // Daten fuer die kryptographische Hashfunktion (hier: SHA1) liefern
            rsaSig.update(key.getEncoded());
            // Signatur durch Verschluesselung des Hashwerts (mit privatem RSA-Schluessel) erzeugen
            return rsaSig.sign();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] encryptSecretKey(SecretKey sk,PublicKey pk)
    {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pk);
            return cipher.doFinal(sk.getEncoded());

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

    public static byte[] encryptDataFile(String filename, SecretKey skey, DataOutput os)
    {
        DataInputStream is = null;
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);

            // Initialisierung
            cipher.init(Cipher.ENCRYPT_MODE, skey);

            // Der Initialisierungsvektor IV muss dem EMPFAENGER spaeter als
            // Parameter mit uebergeben werden (falls nicht Betrieb im
            // ECB-Modus), daher muessen die erzeugten Parameter aus dem
            // Cipher-Objekt ausgelesen werden.
            if(cipher.getParameters() != null){
                System.out.println("Cipher Parameter: "
                        + cipher.getParameters().toString());
                AlgorithmParameters ap = cipher.getParameters();
                byte[] v = cipher.getIV();
                File ivFile = new File("iv");
                DataOutputStream foo = new DataOutputStream(new FileOutputStream(ivFile));
                foo.write(v);
                foo.close();
            }


            // die zu schuetzenden Daten
            File file = new File(filename);
            is = new DataInputStream(new FileInputStream(
                    file));
            long length = file.length();
            if((Integer.MAX_VALUE - length) < 0)
            {
                return null;
            }


            byte[] plain = new byte[16];
            int bytesRead;
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


//            byte[] plain = new byte[(int)length];
//            is.readFully(plain);
//            System.out.println("Daten: " + new String(plain));

            // nun werden die Daten verschluesselt
            // (update wird bei grossen Datenmengen mehrfach aufgerufen werden!)
//            byte[] encData = cipher.update(plain);
//
//            mit doFinal abschliessen (Rest inkl. Padding ..)
//            byte[] encRest = cipher.doFinal();
//            byte[] both = new byte[encData.length+encRest.length];
//
//            System.arraycopy(encData, 0, both, 0, encData.length);
//            System.arraycopy(encRest, 0, both, encData.length, encRest.length);
            return plain;
        }catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }

    }


}
