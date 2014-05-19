/* MD.java */

import java.io.*;
import java.security.*;

/**
 * In diesem Beispiel wird der Message Digest fuer eine Datei berechnet und
 * angezeigt. Der Algorithmus fuer die kryptographische Hashfunktion (z.B. "SHA-1", "SHA-256"
 * oder "MD5") und der Dateiname werden als Argument von der Kommandozeile
 * gelesen.
 */
public class MD {

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java MD md-algorithm filename");
            System.exit(0);
        }
        try {
            // MessageDigest-Objekt erstellen (Algorithmus z.B. SHA-1 oder MD5)
            MessageDigest md = MessageDigest.getInstance(args[0]);
            System.out.println(md.getAlgorithm() + "-Message Digest:");
            // Datei oeffnen
            FileInputStream in = new FileInputStream(args[1]);
            int len;
            byte[] data = new byte[1024];
            // Datei lesen
            while ((len = in.read(data)) > 0) {
                // MessageDigest updaten
                md.update(data, 0, len);
            }
            in.close();
            // MessageDigest (kryptogr. Hashwert) berechnen
            byte[] result = md.digest();
            // MessageDigest ausgeben
            for (int i = 0; i < result.length; ++i) {
                System.out.print(toHexString(result[i]) + " ");
            }
            System.out.println();
        } catch (Exception e) {
            System.err.println(e.toString());
            System.exit(1);
        }
    }

    /**
     * Konvertiert ein Byte in einen Hex-String.
     */
    public static String toHexString(byte b) {
        // Vorzeichenbits ggf. eliminieren
        // --> obere 3 Byte auf Null setzen und zu String konvertieren
        String ret = Integer.toHexString(b & 0xFF).toUpperCase();
        // ggf. fuehrende Null einfuegen
        ret = (ret.length() < 2 ? "0" : "") + ret;
        return ret;
    }
}