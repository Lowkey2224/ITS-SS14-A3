import java.security.*;

/**
 * Dieses Beispiel gibt alle installierten Kryptographie-Provider aus.
 */
public class Prov {
    public static void main(String[] args) {
        int i;
        Provider[] p = Security.getProviders();
        for (i = 0; i < p.length; i++)
            System.out.println("Provider " + i + ": " + p[i].getInfo());
    }
}