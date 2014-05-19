import java.security.*;
import java.io.*;

/**
 * In diesem Beispiel wird ein RSA-Schluesselpaar erzeugt, anschliessend eine
 * Nachricht signiert und zusammen mit der Signatur und dem oeffentlichen
 * Schluessel in einer Datei gespeichert.
 */

/*
 * Dateibeschreibung: 1. Laenge der Nachricht 2. Nachrichtenbytes 3. Laenge der
 * Signatur 4. Signaturbytes 5. Laenge des oeff. Schluessels 6. Schluesselbytes
 */

public class SignMessage extends Object {

    // Name der Datei, in die die signierte Nachricht gespeichert wird
    public String fileName;
    // das Schluesselpaar
    private KeyPair keyPair = null;

    // Konstruktor
    public SignMessage(String fileName) {
        this.fileName = fileName;
    }

    public static void main(String args[]) {
        // Name der zu erzeugenden Signaturdatei = 1. Argument der Kommandozeile
        // Zu signierende Nachricht = 2. Argument der Kommandozeile
        if (args.length < 2) {
            System.out.println("Usage: java SignMessage outFilename messageString");
        } else {
            SignMessage sm = new SignMessage(args[0]);
            // als erstes wird ein neues Schluesselpaar erzeugt
            sm.generateKeyPair("foo");
            // eine Nachricht wird signiert und gespeichert
            sm.signAndSaveMessage(args[1]);
        }
    }

    /**
     * Diese Methode generiert ein neues Schluesselpaar.
     */
    public void generateKeyPair(String userName) {
        try {
            // als Algorithmus verwenden wir RSA
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            // mit gewuenschter Schluessellaenge initialisieren
            gen.initialize(2048);
            keyPair = gen.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            //write Public Key
            //TODO Funktioniert das wirklich so mit dem Datei erstellen?
            DataOutputStream os = new DataOutputStream(new FileOutputStream(userName+".pub"));
            os.write(userName.length());
            os.write(userName.getBytes());
            byte[] bary = publicKey.getEncoded();
            os.write(bary.length);
            os.write(bary);
            os.close();

            //Write private Key
            //TODO Funktioniert das wirklich so mit dem Datei erstellen?
            os = new DataOutputStream(new FileOutputStream(userName+".prv"));
            os.write(userName.length());
            os.write(userName.getBytes());
            bary = privateKey.getEncoded();
            os.write(bary.length);
            os.write(bary);
            os.close();

        } catch (NoSuchAlgorithmException ex) {
            showErrorAndExit("Es existiert kein KeyPairGenerator fuer RSA", ex);
        } catch (IOException ex){
            showErrorAndExit("IOException", ex);
        }
    }

    /**
     * Die angegebene Nachricht wird signiert und dann zusammen mit der Signatur
     * und dem oeffentlichen Schluessel (X.509-Format) in eine Datei gespeichert.
     */
    public void signAndSaveMessage(String message) {

        // die Nachricht als Byte-Array
        byte[] msg = message.getBytes();
        Signature rsaSig = null;
        byte[] signature = null;
        try {
            // als Erstes erzeugen wir das Signatur-Objekt
            rsaSig = Signature.getInstance("SHA1withRSA");
            // zum Signieren benoetigen wir den privaten Schluessel (hier: RSA)
            rsaSig.initSign(keyPair.getPrivate());
            // Daten fuer die kryptographische Hashfunktion (hier: SHA1) liefern
            rsaSig.update(msg);
            // Signatur durch Verschluesselung des Hashwerts (mit privatem RSA-Schluessel) erzeugen
            signature = rsaSig.sign();
        } catch (NoSuchAlgorithmException ex) {
            showErrorAndExit("Keine Implementierung fuer SHA1withRSA!", ex);
        } catch (InvalidKeyException ex) {
            showErrorAndExit("Falscher Schluessel!", ex);
        } catch (SignatureException ex) {
            showErrorAndExit("Fehler beim Signieren der Nachricht!", ex);
        }

        // der oeffentliche Schluessel vom Schluesselpaar
        PublicKey pubKey = keyPair.getPublic();
        // wir benoetigen die Default-Kodierung
        byte[] pubKeyEnc = pubKey.getEncoded();
        System.out
                .println("Der Public Key wird in folgendem Format gespeichert: "
                        + pubKey.getFormat());

        try {
            // eine Datei wird erzeugt und danach die Nachricht, die Signatur
            // und der oeffentliche Schluessel darin gespeichert
            DataOutputStream os = new DataOutputStream(new FileOutputStream(
                    fileName));
            os.writeInt(msg.length);
            os.write(msg);
            os.writeInt(signature.length);
            os.write(signature);
            os.writeInt(pubKeyEnc.length);
            os.write(pubKeyEnc);
            os.close();
        } catch (IOException ex) {
            showErrorAndExit("Fehler beim Schreiben der signierten Nachricht.", ex);
        }
        // Bildschirmausgabe
        System.out.println("Erzeugte SHA1/RSA-Signatur: ");
        for (int i = 0; i < signature.length; ++i) {
            System.out.print(toHexString(signature[i]) + " ");
        }
        System.out.println();
    }

    /**
     * Konvertiert ein Byte in einen Hex-String.
     */
    private String toHexString(byte b) {
        // Vorzeichenbits ggf. eliminieren
        // --> obere 3 Byte auf Null setzen und zu String konvertieren
        String ret = Integer.toHexString(b & 0xFF).toUpperCase();
        // ggf. fuehrende Null einfuegen
        ret = (ret.length() < 2 ? "0" : "") + ret;
        return ret;
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