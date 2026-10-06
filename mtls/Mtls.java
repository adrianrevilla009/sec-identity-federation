import com.sun.net.httpserver.*;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.*;
import java.security.KeyStore;
import javax.net.ssl.*;

/** Two services over mutual TLS: the server identifies the caller by its client-certificate subject. */
public class Mtls {
    static KeyStore load(String f, String pw) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (var in = new FileInputStream(f)) {
            ks.load(in, pw.toCharArray());
        }
        return ks;
    }

    static SSLContext ctx(String dir, String pw, String keystore) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(load(dir + "/trust.p12", pw));
        KeyManager[] km = null;
        if (keystore != null) {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
            kmf.init(load(dir + "/" + keystore, pw), pw.toCharArray());
            km = kmf.getKeyManagers();
        }
        SSLContext c = SSLContext.getInstance("TLSv1.3");
        c.init(km, tmf.getTrustManagers(), null);
        return c;
    }

    static String call(SSLContext c) throws Exception {
        var client = HttpClient.newBuilder().sslContext(c).build();
        var req = HttpRequest.newBuilder(URI.create("https://localhost:8443/whoami")).build();
        return client.send(req, HttpResponse.BodyHandlers.ofString()).body();
    }

    public static void main(String[] a) throws Exception {
        String dir = a[0], pw = a[1];
        var https = HttpsServer.create(new InetSocketAddress("localhost", 8443), 0);
        SSLContext sc = ctx(dir, pw, "server.p12");
        https.setHttpsConfigurator(new HttpsConfigurator(sc) {
            public void configure(HttpsParameters p) {
                SSLParameters sp = sc.getDefaultSSLParameters();
                sp.setNeedClientAuth(true);
                p.setSSLParameters(sp);
            }
        });
        https.createContext("/whoami", ex -> {
            String who = ((HttpsExchange) ex).getSSLSession().getPeerPrincipal().getName();
            byte[] b = ("hello " + who).getBytes();
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        https.start();
        try {
            String ok = call(ctx(dir, pw, "client.p12"));
            System.out.println("with client cert   : " + ok);
            if (!ok.contains("CN=client")) throw new AssertionError(ok);
            try {
                call(ctx(dir, pw, null));
                throw new AssertionError("call without client cert must fail");
            } catch (java.io.IOException e) {
                System.out.println("without client cert: rejected (" + e.getClass().getSimpleName() + ")");
            }
            System.out.println("OK");
        } finally {
            https.stop(0);
        }
    }
}
