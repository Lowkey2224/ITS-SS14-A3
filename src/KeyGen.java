import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

/**
 * Created by Loki on 19.05.2014.
 */
public class KeyGen {

    /**
     * Diese Methode generiert ein neues Schluesselpaar.
     */
    public void generateKeyPair(String userName) {
        try {
            // als Algorithmus verwenden wir RSA
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            // mit gewuenschter Schluessellaenge initialisieren
            gen.initialize(2048);
            KeyPair keyPair = gen.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            //write Public Key
            //TODO Funktioniert das wirklich so mit dem Datei erstellen?
            DataOutputStream os = new DataOutputStream(new FileOutputStream(userName+".pub"));
            os.writeInt(userName.length());
            os.write(userName.getBytes());
            byte[] bary = publicKey.getEncoded();
            os.writeInt(bary.length);
            os.write(bary);
            os.close();

            //Write private Key
            //TODO Funktioniert das wirklichva   so mit dem Datei erstellen?
            os = new DataOutputStream(new FileOutputStream(userName+".prv"));
            os.writeInt(userName.length());
            os.write(userName.getBytes());
            bary = privateKey.getEncoded();
            os.writeInt(bary.length);
            os.write(bary);
            os.close();

        } catch (NoSuchAlgorithmException ex) {
            showErrorAndExit("Es existiert kein KeyPairGenerator fuer RSA", ex);
        } catch (IOException ex){
            showErrorAndExit("IOException", ex);
        }
    }

    /**
     * Diese Methode gibt eine Fehlermeldung sowie eine Beschreibung der
     * Ausnahme aus. Danach wird das Programm beendet.
     *
     * @param msg eine Beschreibung fuer den Fehler
     * @param ex  die Ausnahme, die den Fehler ausgeloest hat
     */
    private void showErrorAndExit(String msg, Exception ex) {
        System.out.println(msg);
        System.out.println(ex.getMessage());
        System.exit(0);
    }
}
