
/*IBM Confidential
* OCO Source Materials
* 5725-V89 5725-V90
*
* Copyright IBM Corp. 2019
*
* The source code for this program is not published or otherwise divested of its trade secrets,
* irrespective of what has been deposited with the U.S. Copyright Office.
*/
package com.isfs.util;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECField;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import com.ibm.iam.isfs.v2.impl.data.Base64String;
import com.ibm.iam.isfs.v2.impl.data.RandomUtil;

public class CertUtils implements java.io.Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 5384670213712592314L;

    public static final String EC_PRIVATE_KEY_B64 = "MIGHAgEAMBMGByqGSM49AgEGCC"
            + "qGSM49AwEHBG0wawIBAQQg6HaC8U6Wv+ATL/1NZh5xF4v9kdUMWPdnJGNhYf0/862hRANCAAR4yBAG"
            + "GG5wFRqCMvrXWn1FZbPwrwTvW0ZYdiRxqhXAOrfCmLHgQkMkCoqFcOzeyzJvKi9+XpX7VMq/Q/XKd47j";

    public static final String EC_PUBLIC_KEY_B64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0"
            + "DAQcDQgAEeMgQBhhucBUagjL611p9RWWz8K8E71tGWHYkcaoVwDq3wpix4EJDJAqKhXDs3ssybyovf"
            + "l6V+1TKv0P1yneO4w==";
    
    public static final String EC_CA_PRIVATE_KEY_B64 = "MIGHAgEAMBMGByqGSM49AgEGCC"
            + "qGSM49AwEHBG0wawIBAQQg6HaC8U6Wv+ATL/1NZh5xF4v9kdUMWPdnJGNhYf0/862hRANCAAR4yBAG"
            + "GG5wFRqCMvrXWn1FZbPwrwTvW0ZYdiRxqhXAOrfCmLHgQkMkCoqFcOzeyzJvKi9+XpX7VMq/Q/XKd47j";

    public static final String EC_CA_PUBLIC_KEY_B64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0"
            + "DAQcDQgAEeMgQBhhucBUagjL611p9RWWz8K8E71tGWHYkcaoVwDq3wpix4EJDJAqKhXDs3ssybyovf"
            + "l6V+1TKv0P1yneO4w==";

    public static final String U2F_PRIVATE_KEY_B64 = "MIGHAgEAMBMGByqGSM49AgEGC"
            + "CqGSM49AwEHBG0wawIBAQQgr3MJxLuXuwVLVEZlz7h93odLmaZOHUxBwHeigLyFMAehRANCAAQCuZo"
            + "wPdLorv+D71HiDcgK8NvOosFX+MndmjyDHOoMU1sTx9JITYCZgLDLpfVSmLjEoJ4P2j45EMlWA6+WY"
            + "NKb";

    public static final String U2F_PUBLIC_KEY_B64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj"
            + "0DAQcDQgAEArmaMD3S6K7/g+9R4g3ICvDbzqLBV/jJ3Zo8gxzqDFNbE8fSSE2AmYCwy6X1Upi4xKCe"
            + "D9o+ORDJVgOvlmDSmw==";

    public static final String U2F_CERT_B64 = "MIIDDjCB9wIJAMESpCKbzurNMA0GCSqG"
            + "SIb3DQEBCwUAMC4xCzAJBgNVBAYTAlVTMQwwCgYDVQQKDANJQk0xETAPBgNVBAMMCEZJRE9URVNUMB"
            + "4XDTE4MTEyOTA1NTAyNFoXDTQ2MDQxNTA1NTAyNFowMDELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0lC"
            + "TTETMBEGA1UEAwwKVTJGLVNJR05FUjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAK5mjA90uiu/4"
            + "PvUeINyArw286iwVf4yd2aPIMc6gxTWxPH0khNgJmAsMul9VKYuMSgng/aPjkQyVYDr5Zg0pswDQYJ"
            + "KoZIhvcNAQELBQADggIBABPCZG9yI+utyhhN9b/vIM/6UQY+wtZVVkEWUQ/WKQz+gXFX08A/QD03hd"
            + "Xq6pHPvlfnq5WFOrVdRbgTzzJpITgOLxfIpkIGkmATrPRK/5V4S86k7yMLSa3VTkhfZOYZ0ndd/1lV"
            + "vCHiMtfAV6878sVQ1/INafd61m4Pz4JYkMa6yKM1PK2YCYlhmORG4kdgMklDqd3/C04S0EhnNZF7Pk"
            + "A7gU1NirJChC+S6c5UCFirRv94CgDCvPLGOpdmV/SnYFQhCFugJbbyS2tH6Ko9iTPt7UH1HcAAGN6c"
            + "nJwxHi14laVoByAWH3GZpy6JG1nXVEtTeaLkQ56gOTv5tIBIMPySXqFXLw4D7BKp6UCbo1Pjjl1Glv"
            + "FAs1sH7AsFM8zRyq9N7q7M6ebt63XCkiVrqr94IDGdVPA61xFasV+xqyZTiiV/gLsCKRJd0kM+Kg1G"
            + "5I4JP4yWsSW9dEj3rqZ9x1So4amAXsLUCARGxZLKaryPlp7WGrb/G89agnUys8Tl42x96vOpAvr93I"
            + "xFw/uLEYEH9NvtoxXIMR4T6g5YtFfmUuWqt9keYfxepAj+QqEAyQh8iJbDt55GAEAzoziulwX74EwN"
            + "J6Hy8/TXnjeeixYcrlIk2H9lQ6ODSuV8KzVcNzanSfFDNcFb3DN2ZwMVCFJ+oVBPfxEcNQ68iG2dyu"
            + "zU";

    public static final String RSA_PRIVATE_KEY_B64 = "MIIEvQIBADANBgkqhkiG9w0BA"
            + "QEFAASCBKcwggSjAgEAAoIBAQCxykzAUprTPMm0KdgJACTdiFgzLMlMRTDJlgt+4Y1UjmpfIGIM4AU"
            + "idXk5iYsQfA5A1y5y9ylSOJnWCk5yv89vb7QktID6FFJ14xhETKg5U+uO7lTxA3u4i6J2uoeT+Fpz7"
            + "XrcEYBj+Og0RukH7gDMi9nyOl3p6ROM4enFFZYxRg6E6h6csd3GPGTVI6ZrvFveZMtcFfCtJrDgds/"
            + "qn2rAK+0BHSkwGA1vJdW8A4+IaE78YRGWjtk9a4WeQKyE3gz4v600/uZnrcGwQFAU6IoL9h59r+iGe"
            + "yxmr8DobtvObiwcQWChmI02uNU8mGRT3m+pN57LDzsvqnRouXkM6b2fAgMBAAECggEAXvcN9BSrenW"
            + "Xz9IiAPzAtEwlwIAFreWvX53z2fwkf6vqiZFEjlgCphtVezRKwa1h96R4vRPkUHTHRxsOOCDYbk+eS"
            + "5TW571/JlT9G05O9QAsbJZFbM9NgI+lYgHUdWdM+Ws6Gt6GU+AaOAJAaunoJ1n0OnyOuWiz9qadNZa"
            + "IORyr6AKLdB0XspQzCU4mc4173ACbuoRQQXyEIgVgIRU3feNfFLdbdNhJr43sAXurVl4eZPKlWEv77"
            + "tWhg7J01WueydQbWyOddvolJYKtGNmS82X9q77Wjn4Bw+q2HE7iAqG2uLDc3mggzFdF80Bhyb6BpN+"
            + "KVjwscyRHEtcczSo0wQKBgQDnuDBqXnH1h/8NNr5PE2yr89iMu8xAHDm4FYdhVROi/oDt0iT49++8T"
            + "LajB8wpny8xPfqI7Fhd7f5ambr/AaKf2f0hbM4dlFaurTdVGvD+mbFI5PowkJrxW1S4yFMvi7f4+GS"
            + "qNoP6ceSVLk96sV3hBXWLLJDfKcjnCGOO0FxCsQKBgQDEa3kxQw7AGNOvtxNznovN+f1SGY1fnMCkn"
            + "aRXNVcuRvLvcffhRDJU97qoOo8mAm2EC5bbMWCPJt8d/aIuGxsZ4yM3NHmPMcxQ3jU8AeOvGPwIWdQ"
            + "je0avMMP8+RBZmP4t6mY+ottcqeMqqy0Z06TC2/jXp2WqaLf7wEQ/04P5TwKBgGZwok7UFBNVHSeNV"
            + "RMGZluagNiuyXxqPgYo1mHsR7MeSodZCOlcSwr26yMl9ldMPYPKf7D6s5JK/dC199p2sZtztpmJTZH"
            + "8G1o7z6N7NqGH9r1gJU9FDoq3MrxCK6xwW1PhFDe/xBb7NO/SumZmdTdev3lYqW9PPLcOmVzwtmjxA"
            + "oGAOv9hHqfatV5/rwbZg9/6dDsDmPZt3Wsy/f8PztYJwq+y5rMf1nzqdVUXrtIwDyWpiYEFpf8V1sn"
            + "BOLvnS9v+bu8ns7xCSv2VNjEYYlba8cwaX9PDgYjUuWh3ZfPVsmPe7SG75lJ6e0HYJwfVey10DseN3"
            + "hC828uqf6bHmThKKscCgYEAwG2tXQbhf0uzcVoztL4t2inC6EQK3K5P2mgd6uw9Fw16Xr1EmGKGIN/"
            + "C7H1A4aIcUs3LRTBAJS+yqZ15YOWVigctRzBQBJb0/LUsTTpkkTsvu3ygTrQM+ZxGMSGbCyORaA6wJ"
            + "U/GuveFMBUH3rYRJBBaEl50O8f5jcJLEa/zVz4=";

    public static final String RSA_PUBLIC_KEY_B64 = "MIIBIjANBgkqhkiG9w0BAQEFA"
            + "AOCAQ8AMIIBCgKCAQEAscpMwFKa0zzJtCnYCQAk3YhYMyzJTEUwyZYLfuGNVI5qXyBiDOAFInV5OYm"
            + "LEHwOQNcucvcpUjiZ1gpOcr/Pb2+0JLSA+hRSdeMYREyoOVPrju5U8QN7uIuidrqHk/hac+163BGAY"
            + "/joNEbpB+4AzIvZ8jpd6ekTjOHpxRWWMUYOhOoenLHdxjxk1SOma7xb3mTLXBXwrSaw4HbP6p9qwCv"
            + "tAR0pMBgNbyXVvAOPiGhO/GERlo7ZPWuFnkCshN4M+L+tNP7mZ63BsEBQFOiKC/Yefa/ohnssZq/A6"
            + "G7bzm4sHEFgoZiNNrjVPJhkU95vqTeeyw87L6p0aLl5DOm9nwIDAQAB";
    
    
    public static final String RSA_CA_PRIVATE_KEY_B64 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwg"
            + "gSkAgEAAoIBAQCv1LBZz7fuCOCWXnQPUUgFLzJ1n5KnghhV64zh9N27oLlvtsd0GHReMMiQmmLJm1Zm"
            + "l1P4Fr4OK/RYNcQ3dg8hibS5STLxqnkaO41TOeDopo+LhK+RU8OlDVJC78UrGM65GHyL96mP0xICd01"
            + "Txt3K8d4Q+upNb44OUueIgJM7zDzbGwoZstHiP42/RDgWDzBMk2rmIOc68xU+AouYzoTfS6Lm5EZ/6M"
            + "2TKLVq22WyHwJ6RfZIyCeBSZH7VIlZaRbewBGqfB3IrNazi9KCrIJFVWFTOXFwapTlyMXM67czZy/73"
            + "rc60NZ8Gxd4wUew36C4JNigzsWM0bH4Lp4kQEvPAgMBAAECggEBAJ+ExU1lvwesdBzXqlGvOzjA3fWK"
            + "hOGFjJB+t/zTS0sLANFSMNepzAEcHwnZluAzForSpbKA54Ix7GcOuGpcqFOT/CrRNu+66k2bU5b6/on"
            + "zem1oPmQJa4jVchkaMHXt9rZEedH+KY47Pq6QD85+r/+LuR0Mlv8TwvxJyJa1l136ZMczcfaqIb4spR"
            + "GV/X5bu8YvWnsTc1hrCfA9z4fwigU6ph/hMpAYvqACVqALqZYJvzcZyAgifb6Rm74NDVut07LdtdfJU"
            + "d0hwySnc8U16z0df6tTi3ZZZuvnV0+WT58t/75wCwhUHy1LlLUzb1KSONKsUox8Y9BLhZ6sdd0tQJkC"
            + "gYEA7JWg5qQ6KqB9TXRMLuqHNzALcxZsJ/WHXmXYSpcOEALXCcTDypXpL4ax1R/7qHV0eiE0u8SitbZ"
            + "+1SqTBQv/FvvFVMGUdWY/SOh4OPS9YJaPFmNCSZcLoH1hrZO9slYLwT9rw9/7UwB4hN0RysJVKR/bw5"
            + "cTVBrl8k37I3e8UD0CgYEAvkKx2BWArWMDimwDrYtwKZFAgSr0ovmhoLmjoo+F5mojViGOohUMmINAq"
            + "3glfxCfVSMrXhTB3mAqbczJeeWXb23/ebJcRv5RvQHNioH4V/w2Z1naWy+EwuVir0qFKgL1usNbLnYA"
            + "fYFDeEjRlQJFcR6hE0/xxTQuVNQOSOpOIPsCgYEAzsyEFtda2MPsg3Wy2he7FexzNahV5h/isgsIIzs"
            + "i2bAB09Ig6sZbTGXKsGcCjWAN7mt0MuVQ7NGW0DIkzPaNhcOR2+JSKMS1cL9zxyV3HCS+8mzVFopnaW"
            + "Pvq9BGssowAD21r0Pr5cO1lT3APaHc2tO0P6WhCZVxhnnPmlMhUmkCgYBtkxu5xyiEszGm1u6HVHcUe"
            + "YMc4RBjjEF5v3BufxouyZHwWQM8dcL7Uxw7pMZzl68r6UVgubOtztSgyACBI6lDk6Y/AGoEuRN6Nz+Z"
            + "NaFBixAKFcWcHpHnbRSYv+JRf8Ll/PzWlT9TCM9Cxy1tFBHKREmgRbqISLUmRbq0Y7z7YQKBgH2iyYj"
            + "ufsGIi9y0qnnOgjZxTHnwpXSdcxPOS3vbc3tW1RXYLL3d1YmReglUBOTlwY1QnTjn+caPfc6P33cxew"
            + "t+9LWSxsY+z6kz/wtieBJndr3ISHJMqe5JYU9ymnSCwJtgzhoXNDj4SwGIPrTn6KaBpb2mpmPSuaL0d"
            + "YuUK1SX";

    public static final String RSA_CA_PUBLIC_KEY_B64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCg"
            + "KCAQEAr9SwWc+37gjgll50D1FIBS8ydZ+Sp4IYVeuM4fTdu6C5b7bHdBh0XjDIkJpiyZtWZpdT+Ba+D"
            + "iv0WDXEN3YPIYm0uUky8ap5GjuNUzng6KaPi4SvkVPDpQ1SQu/FKxjOuRh8i/epj9MSAndNU8bdyvHe"
            + "EPrqTW+ODlLniICTO8w82xsKGbLR4j+Nv0Q4Fg8wTJNq5iDnOvMVPgKLmM6E30ui5uRGf+jNkyi1att"
            + "lsh8CekX2SMgngUmR+1SJWWkW3sARqnwdyKzWs4vSgqyCRVVhUzlxcGqU5cjFzOu3M2cv+963OtDWfB"
            + "sXeMFHsN+guCTYoM7FjNGx+C6eJEBLzwIDAQAB";


    public static final ASN1ObjectIdentifier TCG_KP_AIK_CERTIFICATE_ATTRIBUTE = new ASN1ObjectIdentifier(
            "2.23.133.8.3");

    public static final ASN1ObjectIdentifier AAGUID_OID = new ASN1ObjectIdentifier(
            "1.3.6.1.4.1.45724.1.1.4");

    private static byte[] readPEMFile(String fileName) throws IOException {
        StringBuilder sb = null;
        try { // try read file from string
            InputStream inStream = new FileInputStream(fileName);
            BufferedReader br = new BufferedReader(new InputStreamReader(inStream));
            sb = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.contains("BEGIN")
                            && (line.contains("KEY") || line.contains("CERTIFICATE"))) {
                        inKey = true;
                    }
                    continue;
                } else {
                    if (line.contains("END")
                            && (line.contains("KEY") || line.contains("CERTIFICATE"))) {
                        inKey = false;
                        break;
                    }
                    sb.append(line);
                }
            }
            br.close();
            inStream.close();
        } catch (IOException ioe) { // if we fail use the literal string
            sb = new StringBuilder(fileName);
        }
        byte[] rawKey = DatatypeConverter.parseBase64Binary(sb.toString());
        return rawKey;
    }

    public static Certificate readCert(String fileName, String alg)
            throws FileNotFoundException, CertificateException, IOException,
            InvalidKeySpecException {
        InputStream inStream = null;
        try {
            inStream = new FileInputStream(fileName);
        } catch (IOException ioe) {
            inStream = new ByteArrayInputStream(fileName.getBytes());
        }
        CertificateFactory certFactory = CertificateFactory.getInstance(alg);
        Certificate cert = certFactory.generateCertificate(inStream);
        inStream.close();
        return cert;
    }

    public static PublicKey readPublic(String fileName, String alg)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] rawKey = readPEMFile(fileName);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(rawKey);
        KeyFactory kf = KeyFactory.getInstance(alg);
        return kf.generatePublic(spec);
    }

    public static PrivateKey readPrivate(String fileName, String alg)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] rawKey = readPEMFile(fileName);
        KeyFactory kf = KeyFactory.getInstance(alg);
        PrivateKey pk = (PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(rawKey));
        return pk;
    }

    public static PrivateKey readPrivate()
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] rawKey = readPEMFile(EC_PRIVATE_KEY_B64);
        KeyFactory kf = KeyFactory.getInstance("EC");
        PrivateKey pk = (PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(rawKey));
        return pk;
    }

    public static PrivateKey readPrivate(byte[] raw, String alg)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance(alg);
        PrivateKey pk = (PrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(raw));
        return pk;
    }

    private static class FieldP {
        final static BigInteger _2 = BigInteger.valueOf(2);
        final static BigInteger _3 = BigInteger.valueOf(3);
    }

    private static ECPoint doublePoint(final BigInteger p, final BigInteger a,
            final ECPoint R) {
        if (R.equals(ECPoint.POINT_INFINITY)) {
            return R;
        }
        BigInteger slope = (R.getAffineX().pow(2)).multiply(FieldP._3);
        slope = slope.add(a);
        slope = slope.multiply((R.getAffineY().multiply(FieldP._2)).modInverse(p));
        final BigInteger Xout = slope.pow(2).subtract(R.getAffineX().multiply(FieldP._2))
                .mod(p);
        final BigInteger Yout = (R.getAffineY().negate())
                .add(slope.multiply(R.getAffineX().subtract(Xout))).mod(p);
        return new ECPoint(Xout, Yout);
    }

    private static ECPoint addPoint(final BigInteger p, final BigInteger a, final ECPoint r,
            final ECPoint g) {
        if (r.equals(ECPoint.POINT_INFINITY)) {
            return g;
        }
        if (g.equals(ECPoint.POINT_INFINITY)) {
            return r;
        }
        if (r == g || r.equals(g)) {
            return doublePoint(p, a, r);
        }
        final BigInteger gX = g.getAffineX();
        final BigInteger sY = g.getAffineY();
        final BigInteger rX = r.getAffineX();
        final BigInteger rY = r.getAffineY();
        final BigInteger slope = (rY.subtract(sY)).multiply(rX.subtract(gX).modInverse(p))
                .mod(p);
        final BigInteger Xout = (slope.modPow(FieldP._2, p).subtract(rX)).subtract(gX).mod(p);
        BigInteger Yout = sY.negate().mod(p);
        Yout = Yout.add(slope.multiply(gX.subtract(Xout))).mod(p);
        return new ECPoint(Xout, Yout);
    }

    public static ECPoint scalmult(final EllipticCurve curve, final ECPoint g,
            final BigInteger kin) {
        final ECField field = curve.getField();
        if (!(field instanceof ECFieldFp)) {
            throw new UnsupportedOperationException(field.getClass().getCanonicalName());
        }
        final BigInteger p = ((ECFieldFp) field).getP();
        final BigInteger a = curve.getA();
        ECPoint R = ECPoint.POINT_INFINITY;
        BigInteger k = kin.mod(p);
        final int length = k.bitLength();
        final byte[] binarray = new byte[length];
        for (int i = 0; i <= length - 1; i++) {
            binarray[i] = k.mod(FieldP._2).byteValue();
            k = k.shiftRight(1);
        }
        for (int i = length - 1; i >= 0; i--) {
            R = doublePoint(p, a, R);
            if (binarray[i] == 1) {
                R = addPoint(p, a, R, g);
            }
        }
        return R;
    }

    public static ECPublicKey getPubKey(final ECPrivateKey pk)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECParameterSpec spec = pk.getParams();
        ECPoint w = scalmult(spec.getCurve(), pk.getParams().getGenerator(), pk.getS());
        KeyFactory kf = KeyFactory.getInstance("EC");
        return (ECPublicKey) kf.generatePublic(new ECPublicKeySpec(w, spec));
    }

    public static RSAPublicKey getPubKey(final RSAPrivateCrtKey pk)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(pk.getModulus(), pk.getPublicExponent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }

    public static KeyPair generateKeyPair(String alg, int keySize)
            throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
        kpg.initialize(keySize);
        return kpg.genKeyPair();
    }

    public static KeyPair getCAKeyPair(String alg) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        if (alg == "EC") {
            privateKey = CertUtils.readPrivate(EC_CA_PRIVATE_KEY_B64, alg);
            publicKey = CertUtils.readPublic(EC_CA_PUBLIC_KEY_B64, alg);
        }
        else if (alg == "RSA") {
            privateKey = CertUtils.readPrivate(RSA_CA_PRIVATE_KEY_B64, alg);
            publicKey = CertUtils.readPublic(RSA_CA_PUBLIC_KEY_B64, alg);
        }
        else {
            throw new NoSuchAlgorithmException(String.format("Invalid alg:  %s", alg));
        }
        return new KeyPair(publicKey, privateKey);      
    }
    
    public static KeyPair getKeyPair(String alg) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        if (alg == "EC") {
            privateKey = CertUtils.readPrivate(EC_PRIVATE_KEY_B64, alg);
            publicKey = CertUtils.readPublic(EC_PUBLIC_KEY_B64, alg);
        }
        else if (alg == "RSA") {
            privateKey = CertUtils.readPrivate(RSA_PRIVATE_KEY_B64, alg);
            publicKey = CertUtils.readPublic(RSA_PUBLIC_KEY_B64, alg);
        }
        else if (alg == "U2F") {
            privateKey = CertUtils.readPrivate(U2F_PRIVATE_KEY_B64, "EC");
            publicKey = CertUtils.readPublic(U2F_PUBLIC_KEY_B64, "EC");
        }
        else {
            throw new NoSuchAlgorithmException(String.format("Invalid alg:  %s", alg));
        }
        return new KeyPair(publicKey, privateKey);
    }

    public static PrivateKey generatePrivate(String alg, int keySize)
            throws NoSuchAlgorithmException {
        return generateKeyPair(alg, keySize).getPrivate();
    }

    /**
     * 
     * @param X509Certificate trust chain certificate
     * @param dn              Subject
     * @param pubKey          Public Key to sign certificate
     * @param expiry          Expiry of certificate
     * @return X509v3CertificateBuilder certificate builder with provided params,
     *         can add extensions as required
     */
    private static X509v3CertificateBuilder certificateBuilder(X509Certificate caCert,
            String dn, PublicKey pubKey, int expiry) {
        Calendar valid = Calendar.getInstance();
        valid.add(Calendar.DAY_OF_YEAR, expiry);
        X500Name subject = (dn == null) ? new X500Name(new RDN[0]) : new X500Name(dn);
        X509v3CertificateBuilder certBuilder = null;
        if (caCert == null) {
            certBuilder = new JcaX509v3CertificateBuilder(subject,
                    BigInteger.valueOf(System.currentTimeMillis()),
                    new Date(System.currentTimeMillis()), valid.getTime(), subject, pubKey);
        } else {
            certBuilder = new JcaX509v3CertificateBuilder(caCert,
                    BigInteger.valueOf(System.currentTimeMillis()),
                    new Date(System.currentTimeMillis()), valid.getTime(), subject, pubKey);
        }
        return certBuilder;
    }

    private static X509v3CertificateBuilder certificateBuilder(String dn, PublicKey pubKey,
            int expiry) {
        return certificateBuilder(null, dn, pubKey, expiry);
    }

    public static X509Certificate generatePackedBasicCertificate(String dn, KeyPair keyPair,
            int days, String aaguid)
            throws IOException, OperatorCreationException, CertificateException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate result = null;

        X509v3CertificateBuilder certBuilder = certificateBuilder(dn, keyPair.getPublic(),
                days);
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4");
        // value must be a double encoded octet stream
        ASN1OctetString value = new DEROctetString(new byte[16]);
        certBuilder.addExtension(oid, false, value);
        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC").build(keyPair.getPrivate())));

        return result;
    }

    public static X509Certificate gereatePackedAttCACertificate(X509Certificate caCert,
            String dn, KeyPair keyPair, int days, String aaguid, KeyPair signKeyPair)
            throws IOException, OperatorCreationException, CertificateException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate result = null;

        X509v3CertificateBuilder certBuilder = certificateBuilder(caCert, dn,
                keyPair.getPublic(), days);

        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4");
        // value must be a double encoded octet stream
        ASN1OctetString value = new DEROctetString(new byte[16]);
        certBuilder.addExtension(oid, false, value);
        result = new JcaX509CertificateConverter().getCertificate(certBuilder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(signKeyPair.getPrivate())));

        return result;
    }

    public static X509Certificate generateU2FCertificate(X509Certificate caCert, String dn,
            KeyPair keyPair, int days) throws CertificateException, OperatorCreationException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate result = null;

        X509v3CertificateBuilder certBuilder = certificateBuilder(caCert, dn,
                keyPair.getPublic(), days);

        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider("BC").build(keyPair.getPrivate())));

        return result;
    }

    public static X509Certificate generateU2FSignedCertificate(X509Certificate caCert,
            String dn, KeyPair keyPair, int days, KeyPair caKeyPair)
            throws CertificateException, OperatorCreationException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate result = null;

        X509v3CertificateBuilder certBuilder = certificateBuilder(caCert, dn,
                keyPair.getPublic(), days);

        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider("BC").build(caKeyPair.getPrivate())));

        return result;
    }

    public static X509Certificate generateCaCert(String dn, KeyPair keyPair, int days,
            boolean addSki) throws Exception {
        PublicKey pubKey = keyPair.getPublic();
        if (pubKey instanceof RSAPublicKey) {
            return generateRsaCaCert(dn, keyPair, days, addSki);
        } else if (pubKey instanceof ECPublicKey) {
            return generateEcCaCert(dn, keyPair, days, addSki);
        } else {
            throw new Exception("Invalid keypair found");
        }
    }

    private static X509Certificate generateRsaCaCert(String dn, KeyPair keyPair, int days,
            boolean addSki) throws CertificateEncodingException, CertIOException,
            OperatorCreationException, CertificateException, NoSuchAlgorithmException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate result = null;

        X509v3CertificateBuilder certBuilder = certificateBuilder(dn, keyPair.getPublic(),
                days);
        // usage restrictions
        certBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(
                KeyUsage.cRLSign | KeyUsage.keyCertSign | KeyUsage.digitalSignature));
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        if (addSki) {
            SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(keyPair.getPublic());
            System.err.println("ski: " + new Base64String(ski.getKeyIdentifier()).toString());
            certBuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);
        }
        certBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));
        // build certificate
        result = new JcaX509CertificateConverter().getCertificate(certBuilder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())));
        return result;
    }

    private static X509Certificate generateEcCaCert(String dn, KeyPair keyPair, int days,
            boolean addSki) throws CertificateEncodingException, CertIOException,
            OperatorCreationException, CertificateException, NoSuchAlgorithmException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509Certificate result = null;

        X509v3CertificateBuilder certBuilder = certificateBuilder(dn, keyPair.getPublic(),
                days);
        // usage restrictions
        certBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyCertSign));
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        if (addSki) {
            SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(keyPair.getPublic());
            System.err.println("ski: " + new Base64String(ski.getKeyIdentifier()).toString());
            certBuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);
        }
        certBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));
        // build certificate
        result = new JcaX509CertificateConverter().getCertificate(certBuilder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
        return result;
    }

    private static X509Certificate generateTPMCert(X509Certificate caCert, String dn, int days,
            KeyPair keyPair, boolean aikCert, String altName, KeyPair signKeyPair,
            boolean keyUsageCritical, int keyUsage, byte[] aaguid)
            throws CertIOException, OperatorCreationException, CertificateException {
        X509Certificate result = null;
        X509v3CertificateBuilder certBuilder = certificateBuilder(caCert, dn,
                keyPair.getPublic(), days);

        certBuilder.addExtension(Extension.keyUsage, keyUsageCritical, new KeyUsage(keyUsage));
        certBuilder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId
                        .getInstance(CertUtils.TCG_KP_AIK_CERTIFICATE_ATTRIBUTE) }));
        certBuilder.addExtension(Extension.basicConstraints, false,
                new BasicConstraints(!aikCert));
        if (aikCert && altName != null) {
            List<GeneralName> altNames = new ArrayList<GeneralName>();
            altNames.add(new GeneralName(GeneralName.directoryName, altName));
            GeneralNames subjectAltNames = GeneralNames.getInstance(
                    new DERSequence((GeneralName[]) altNames.toArray(new GeneralName[] {})));
            certBuilder.addExtension(Extension.subjectAlternativeName, true, subjectAltNames);
        }
        if(aaguid != null) {
            certBuilder.addExtension(AAGUID_OID, false,
                    aaguid);
        }

        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC").build(signKeyPair.getPrivate())));
        return result;
    }

    public static X509Certificate generateIntermediateCACert(X509Certificate caCert, String dn,
            int days, KeyPair keyPair, KeyPair caKeyPair)
            throws CertIOException, OperatorCreationException, CertificateException {
        return generateTPMCert(caCert, dn, days, keyPair, false, null, caKeyPair, false,
                (KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign), null);
    }

    public static X509Certificate generateAIKCert(X509Certificate caCert, int days,
            KeyPair keyPair, String altNames, KeyPair caKeyPair)
            throws CertIOException, OperatorCreationException, CertificateException {
        return generateTPMCert(caCert, null, days, keyPair, true, altNames, caKeyPair, true,
                KeyUsage.digitalSignature, null);
    }
    
    public static X509Certificate generateAIKCert(X509Certificate caCert, int days,
            KeyPair keyPair, String altNames, KeyPair caKeyPair, byte[] aaguid)
            throws CertIOException, OperatorCreationException, CertificateException {
        return generateTPMCert(caCert, null, days, keyPair, true, altNames, caKeyPair, true,
                KeyUsage.digitalSignature, aaguid);
    }

    public static X509Certificate generateBadSNAIKCert(X509Certificate caCert, int days,
            KeyPair keyPair, String altNames, KeyPair caKeyPair)
            throws CertIOException, OperatorCreationException, CertificateException {
        // bad AIK cert has subjectName not empty
        return generateTPMCert(caCert, "CN=bad", days, keyPair, true, altNames, caKeyPair, true,
                KeyUsage.digitalSignature, null);
    }

    public static X509Certificate generateBadVersionAIKCertificate(X509Certificate caCert,
            int days, KeyPair keyPair, String altNames, KeyPair caKeyPair)
            throws CertIOException, OperatorCreationException, CertificateException {
        // bad AIK cert has subjectName not empty
        X509Certificate result = null;
        Calendar valid = Calendar.getInstance();
        valid.add(Calendar.DAY_OF_YEAR, days);
        X500Name subject = new X500Name("CN=invalid");
        X509v1CertificateBuilder certBuilder = new JcaX509v1CertificateBuilder(subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(System.currentTimeMillis()), valid.getTime(), subject,
                keyPair.getPublic());

        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC").build(caKeyPair.getPrivate())));
        return result;
    }

    public static X509Certificate generateMissingAIKCertificateExtension(X509Certificate caCert,
            int days, KeyPair keyPair, String altName, KeyPair caKeyPair)
            throws CertIOException, OperatorCreationException, CertificateException {
        X509Certificate result = null;
        X509v3CertificateBuilder certBuilder = certificateBuilder(caCert, null,
                keyPair.getPublic(), days);

        certBuilder.addExtension(Extension.keyUsage, false,
                new KeyUsage(KeyUsage.digitalSignature));
        certBuilder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[0]));
        List<GeneralName> altNames = new ArrayList<GeneralName>();
        altNames.add(new GeneralName(GeneralName.directoryName, altName));
        GeneralNames subjectAltNames = GeneralNames.getInstance(
                new DERSequence((GeneralName[]) altNames.toArray(new GeneralName[] {})));
        certBuilder.addExtension(Extension.subjectAlternativeName, true, subjectAltNames);

        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC").build(caKeyPair.getPrivate())));
        return result;
    }

    public static X509Certificate generateAKICertWithBasicConstraints(X509Certificate caCert,
            int days, KeyPair keyPair, String altName, KeyPair caKeyPair)
            throws CertIOException, OperatorCreationException, CertificateException {
        X509Certificate result = null;
        X509v3CertificateBuilder certBuilder = certificateBuilder(caCert, null,
                keyPair.getPublic(), days);

        certBuilder.addExtension(Extension.keyUsage, false,
                new KeyUsage(KeyUsage.digitalSignature));
        certBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(
                KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
        certBuilder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[] { KeyPurposeId
                        .getInstance(CertUtils.TCG_KP_AIK_CERTIFICATE_ATTRIBUTE) }));
        List<GeneralName> altNames = new ArrayList<GeneralName>();
        altNames.add(new GeneralName(GeneralName.directoryName, altName));
        GeneralNames subjectAltNames = GeneralNames.getInstance(
                new DERSequence((GeneralName[]) altNames.toArray(new GeneralName[] {})));
        certBuilder.addExtension(Extension.subjectAlternativeName, true, subjectAltNames);

        result = new JcaX509CertificateConverter()
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC").build(caKeyPair.getPrivate())));
        return result;
    }

    public static X509Certificate generateAKICertWithBadAAGUID(X509Certificate caCert, int days,
            KeyPair keyPair, String altNames, KeyPair caKeyPair)
            throws CertIOException, OperatorCreationException, CertificateException {
        return generateTPMCert(caCert, null, days, keyPair, true, altNames, caKeyPair, true,
                KeyUsage.digitalSignature, RandomUtil.generateBytes(16));
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: CertUtils pemfile");
            System.exit(1);
        }
        String pemFile = args[0];
        try {
            X509Certificate cert = (X509Certificate) CertUtils.readCert(pemFile, "X.509");
            PublicKey pk = cert.getPublicKey();
            System.out.println("X509 Public Key:");
            System.out.println(pk.getAlgorithm() + " " + pk.getFormat());
            System.out.println(Base64.getEncoder().encodeToString(pk.getEncoded()));
            System.exit(0);
        } catch (Exception e) {
            System.out.println("Failed to get X509 Public key");
//            e.printStackTrace();
        }

        try {
            ECPublicKey cert = (ECPublicKey) CertUtils.readPublic(pemFile, "EC");
            System.out.println("EC Public Key:");
            ECPoint point = cert.getW();
            String x = point.getAffineX().toString(16);
            String y = point.getAffineY().toString(16);
            System.out.println("X = " + x + ", Y = " + y);
            System.exit(0);
        } catch (Exception e) {
            System.out.println("Failed to get EC Public key");
//            e.printStackTrace();
        }

        try {
            PrivateKey pk = CertUtils.readPrivate(pemFile, "RSA");
            System.out.println("RSA Private Key:");
            System.out.println(pk.getAlgorithm() + " " + pk.getFormat());
            System.out.println(Base64.getEncoder().encodeToString(pk.getEncoded()));
            System.exit(0);
        } catch (Exception e) {
            System.out.println("Failed to get RSA private key");
//            e.printStackTrace();
        }

        try {
            PrivateKey pk = CertUtils.readPrivate(pemFile, "EC");
            System.out.println("EC Private Key:");
            System.out.println(pk.getAlgorithm() + " " + pk.getFormat());
            System.out.println(Base64.getEncoder().encodeToString(pk.getEncoded()));
            System.exit(0);
        } catch (Exception e) {
            System.out.println("Failed to get EC private key");
            e.printStackTrace();
        }
    }
}
