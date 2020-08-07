package ro.mobilPay.util;


import java.io.StringReader;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/*import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import javax.servlet.http.HttpServletResponse;

import javax.servlet.jsp.JspWriter;*/


import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.encoders.Base64;
import sun.security.util.Pem;

@Slf4j
public class OpenSSL {

    private OpenSSL() {
    }

    public static ListItem openssl_seal(String cert, String xml) {
        try {
            StringReader sr = new StringReader(cert);
            PEMParser pm = new PEMParser(sr);
            X509CertificateHolder x509 = (X509CertificateHolder) pm.readObject();
            pm.close();
            PublicKey p509Key = BouncyCastleProvider.getPublicKey(x509.getSubjectPublicKeyInfo());

            KeyGenerator generator = KeyGenerator.getInstance("ARCFOUR");
            generator.init(128);
            SecretKey key = generator.generateKey();

            Cipher cc = Cipher.getInstance("ARCFOUR");
            cc.init(Cipher.ENCRYPT_MODE, key);

            byte[] ksrc = cc.doFinal(xml.getBytes());

            Cipher ccRSA = Cipher.getInstance("RSA");
            ccRSA.init(Cipher.ENCRYPT_MODE, p509Key);
            byte[] evk = ccRSA.doFinal(key.getEncoded());

            return new ListItem("" + 1, new String(Base64.encode(evk)), new String(Base64.encode(ksrc)));
        } catch (Exception e) {
            log.error("Error generating SSL Certificate", e);
        }
        return null;
    }

    public static String openssl_unseal(String data, String envKey, String prvkey) {
        try {

            StringReader sr = new StringReader(prvkey);
            PEMParser pm = new PEMParser(sr);
            Object o = pm.readObject();
            pm.close();
            Key key;

            if (o != null && o instanceof PEMKeyPair) {
                PEMKeyPair kpr = (PEMKeyPair) o;

                key = BouncyCastleProvider.getPrivateKey(kpr.getPrivateKeyInfo());
            } else {
                log.error("1 ERROR private key probably DER not PEM. user openssl to convert: " + prvkey);
                return null;
            }

            Cipher ccRSA = Cipher.getInstance("RSA");
            ccRSA.init(Cipher.DECRYPT_MODE, key);
            byte[] envb = Base64.decode(envKey);
            byte[] decrkey = ccRSA.doFinal(envb);

            SecretKeySpec sc = new SecretKeySpec(decrkey, "ARCFOUR");

            Cipher cc = Cipher.getInstance("ARCFOUR");
            cc.init(Cipher.DECRYPT_MODE, sc);

            byte[] ksrc = cc.doFinal(Base64.decode(data));

            return new String(ksrc);
        } catch (Exception e) {
            String aux = " : data - " + data + "<br/>envKey=" + envKey + "<br/>";
            log.error("2 ERROR unseal : " + e.getMessage() + aux, e);
        }
        return null;
    }

    public static void extraInit() {
        Security.addProvider(new BouncyCastleProvider());
    }
}
