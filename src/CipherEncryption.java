import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * Dieses Beispiel zeigt die Verwendung der Klasse Cipher zum Verschluesseln von
 * beliebigen Daten.
 */
public class CipherEncryption {

    public static void main(String[] argv) {

        try {
            // AES-Schluessel generieren
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128); // Schluessellaenge
            SecretKey skey = kg.generateKey();

            // Cipher-Objekt erzeugen und initialisieren mit AES-Algorithmus und
            // Parametern (z.B. IV-Erzeugung)
            // SUN-Default ist ECB-Modus (damit kein IV uebergeben werden muss)
            // und PKCS5Padding
            // Fuer Default-Parameter genuegt: Cipher.getInstance("AES")
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Initialisierung
            cipher.init(Cipher.ENCRYPT_MODE, skey);

            // Der Initialisierungsvektor IV muss dem EMPFAENGER spaeter als
            // Parameter mit uebergeben werden (falls nicht Betrieb im
            // ECB-Modus), daher muessen die erzeugten Parameter aus dem
            // Cipher-Objekt ausgelesen werden.
            System.out.println("Cipher Parameter: "
                    + cipher.getParameters().toString());
            AlgorithmParameters ap = cipher.getParameters();

            // die zu schuetzenden Daten
            byte[] plain = "Das ist nur ein Test!".getBytes();
            System.out.println("Daten: " + new String(plain));

            // nun werden die Daten verschluesselt
            // (update wird bei grossen Datenmengen mehrfach aufgerufen werden!)
            byte[] encData = cipher.update(plain);

            // mit doFinal abschliessen (Rest inkl. Padding ..)
            byte[] encRest = cipher.doFinal();


            // und angezeigt
            System.out.println("Verschluesselte Daten: " + new String(encData)
                    + new String(encRest));
            // zeigt den Algorithmus des Schluessels
            System.out.println("Schluesselalgorithmus: " + skey.getAlgorithm());
            // zeigt das Format des Schluessels
            System.out.println("Schluesselformat: " + skey.getFormat());

            // nun wird der kodierte Schluessel als Bytefolge gespeichert
            byte[] raw_key = skey.getEncoded();

            // hier findet die Uebertragung statt (ist ja nur ein Beispiel) ...

            // sollen die Daten wieder entschluesselt werden, so muss zuerst
            // aus der Bytefolge eine neue AES-Schluesselspezifikation erzeugt
            // werden (transparenter Schluessel)
            SecretKeySpec skspec = new SecretKeySpec(raw_key, "AES");

            // mit diesem Schluessel wird nun die AES-Chiffre im DECRYPT MODE
            // initialisiert (inkl. AlgorithmParameters fuer den IV)
            cipher.init(Cipher.DECRYPT_MODE, skspec, ap);

            // und die Daten entschluesselt
            byte[] decData = cipher.update(encData);

            // mit doFinal abschliessen (Rest inkl. Padding ..)
            byte[] decRest = cipher.doFinal(encRest);

            // anzeigen der entschluesselten Daten
            System.out.println("Entschluesselte Daten: " + new String(decData)
                    + new String(decRest));

        } catch (Exception ex) {
            // ein Fehler???
            System.out.println("Error: " + ex.getMessage());
        }
    }
}