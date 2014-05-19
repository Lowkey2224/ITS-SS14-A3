import sun.security.rsa.RSAPrivateKeyImpl;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by Loki on 19.05.2014.
 */
public class sendSecureFile {

    private PrivateKey readPrivateKeyFromFile(String filename, String algorithm)
    {
        PrivateKey ret = null;
        byte[] message = null;
        DataInputStream is = null;
        try {
            is = new DataInputStream(new FileInputStream(
                    filename));
            int len = is.readInt();

            // die Nachricht
            int nameLength  = is.readInt();
            message = new byte[nameLength];
            //TODO Check return value of read
            is.read(message);
            int keyLength = is.readInt();
            message = new byte[keyLength];
            is.read(message);
            is.close();
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec =  new PKCS8EncodedKeySpec(message);
            ret = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
//            ret = new RSAPrivateKeyImpl();

        } catch (java.io.IOException e) {
            e.printStackTrace();
        }finally {

            return ret;

        }
    }

    private PublicKey readPublicKeyFromFile(String filename, String algorithm)
    {
        PublicKey ret = null;
        byte[] message = null;
        DataInputStream is = null;
        try {
            is = new DataInputStream(new FileInputStream(
                    filename));
            int len = is.readInt();

            // die Nachricht
            int nameLength  = is.readInt();
            message = new byte[nameLength];
            //TODO Check return value of read
            is.read(message);
            int keyLength = is.readInt();
            message = new byte[keyLength];
            is.read(message);
            is.close();
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            X509EncodedKeySpec x509EncodedKeySpec =  new X509EncodedKeySpec(message);
            ret = keyFactory.generatePublic(x509EncodedKeySpec);
//            ret = new RSAPrivateKeyImpl();

        } catch (java.io.IOException e) {
            e.printStackTrace();
        }finally {

            return ret;

        }
    }

    private SecretKey createSecretKey(String algorithm)
    {
        KeyGenerator kg = null;
        try {
            kg = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        kg.init(128); // Schluessellaenge
        SecretKey skey = kg.generateKey();
        return  skey;
    }

    private byte[] signSecretKey(SecretKey key, PrivateKey privateKey)
    {
        byte[] keyBytes = key.getEncoded();
        Signature rsaSig = null;
        byte[] signature = null;
        try {
            // als Erstes erzeugen wir das Signatur-Objekt
            rsaSig = Signature.getInstance("SHA1withRSA");
            // zum Signieren benoetigen wir den privaten Schluessel (hier: RSA)
            rsaSig.initSign(privateKey);
            // Daten fuer die kryptographische Hashfunktion (hier: SHA1) liefern
            rsaSig.update(keyBytes);
            // Signatur durch Verschluesselung des Hashwerts (mit privatem RSA-Schluessel) erzeugen
            signature = rsaSig.sign();
            return signature;
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
}
