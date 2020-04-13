/**
 *Copyrite notice
 */

/*IBM Confidential
* OCO Source Materials
* 5725-V89 5725-V90
*
* Copyright IBM Corp. 2019
*
* The source code for this program is not published or otherwise divested of its trade secrets,
* irrespective of what has been deposited with the U.S. Copyright Office.
*/
package com.isfs.util.authenticators;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

import com.ibm.iam.isfs.v2.exception.Fido2Exception;
import com.ibm.iam.isfs.v2.impl.data.DataMapper;
import com.isfs.util.CertUtils;
import com.isfs.util.KeyFactory;

@SuppressWarnings("unchecked")
public class Fido2Authenticator implements java.io.Serializable {

    /**
     * Don't know what this does
     */
    private static final long serialVersionUID = -7830063672721389698L;

    private KeyPair keyPair;

    private long counter = 0;

    private static Set<String> validAuthenticatorExtensions = new HashSet<String>(
            Arrays.asList("txAuthSimple", "txAuthGeneric"));

    // Vendor ID for IBM TMP chip
    protected static final byte[] TPM_VENDOR_ID_CONFORMANCE = new BigInteger("fffff1d0", 16)
            .toByteArray();

    // TODO change aaguid from zero's
    //protected byte[] TEST_AAGUID = new byte[] { 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
    //        0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F };
    protected byte[] TEST_AAGUID = new byte[16];
    // Subject alternative names OID
    protected static final String TPM_MANUFACTURER = "2.23.133.2.1";
    protected static final String TPM_VENDOR = "2.23.133.2.2";
    protected static final String TPM_FW_VERSION = "2.23.133.2.3";

    public Fido2Authenticator() {
        try {
            this.keyPair = KeyFactory.getKeyPair("EC");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Fido2Authenticator(String alg) throws Exception {
        this.keyPair = KeyFactory.getKeyPair(alg);
    }
    
    public Fido2Authenticator(String alg, int keySize) throws NoSuchAlgorithmException {
        this.keyPair = CertUtils.generateKeyPair(alg, keySize);
    }

    public KeyPair getKeyPair() {
        return this.keyPair;
    }

    public Fido2Authenticator setKeyPair(KeyPair kp) {
        this.keyPair = kp;
        return this;
    }

    public long getCounter() {
        return counter;
    }

    public void setCounter(long c) {
        counter = c;
    }

    public final PublicKey getPubKey() {
        return this.keyPair.getPublic();
    }

    public final PrivateKey getPrivKey() {
        return this.keyPair.getPrivate();
    }

    private byte[] ECBigIntegerToByteArray(BigInteger point) {
        byte[] result = point.toByteArray();
        if (result.length == 33) { // Remove leading zero, added if coordinate is negative
            result = Arrays.copyOfRange(result, 1, result.length);
        }
        return result;
    }

    public String credentialCreate(String jsonOptions) throws Exception, Fido2Exception {
        return credentialCreate(jsonOptions, "none", this.getKeyPair());
    }

    public String credentialCreate(String jsonOptions, String attestation)
            throws Exception, Fido2Exception {
        return credentialCreate(jsonOptions, attestation, this.getKeyPair());
    }

    public String credentialCreate(String jsonOptions, String attestation, KeyPair kp)
            throws Exception, Fido2Exception {
        JsonReader jr = Json.createReader(new StringReader(jsonOptions));
        JsonObject jo = jr.readObject();
        Map<String, Object> options = DataMapper.jsonToMap(jo);
        Map<String, Object> result = credentialCreate(options, attestation, kp, null, null);
        return DataMapper.objectToJson(result).toString();
    }

    public String credentialCreate(String jsonOptions, String attestation, KeyPair kp,
            KeyPair caKeyPair, X509Certificate akiCert) throws Exception, Fido2Exception {
        JsonReader jr = Json.createReader(new StringReader(jsonOptions));
        JsonObject jo = jr.readObject();
        Map<String, Object> options = DataMapper.jsonToMap(jo);
        Map<String, Object> result = credentialCreate(options, attestation, kp, caKeyPair,
                akiCert);
        return DataMapper.objectToJson(result).toString();
    }

    public Map<String, Object> credentialCreate(Map<String, Object> options, String attestation,
            KeyPair kp, KeyPair caKeyPair, X509Certificate akiCert)
            throws Exception, Fido2Exception {
        Map<String, Map<String, Object>> cco = this
                .attestationOptionsResponeToCredentialCreationOptions(options);
        return processCredentialCreationOptions(cco, attestation, kp, caKeyPair, akiCert);
    }

    public String credentialRequest(String jsonOptions) throws Exception, Fido2Exception {
        return credentialRequest(jsonOptions, this.getKeyPair());
    }

    public String credentialRequest(String jsonOptions, KeyPair kp)
            throws Exception, Fido2Exception {
        JsonReader jr = Json.createReader(new StringReader(jsonOptions));
        JsonObject jo = jr.readObject();
        Map<String, Object> options = DataMapper.jsonToMap(jo);
        Map<String, Object> result = credentialRequest(options, kp);
        return DataMapper.objectToJson(result).toString();
    }

    public Map<String, Object> credentialRequest(Map<String, Object> options, KeyPair kp)
            throws Exception, Fido2Exception {
        Map<String, Object> cro = assertionOptionsResponseToCredentialRequestOptions(options);
        return processCredentialRequestOptions(cro, kp);
    }

    public byte[] buildAuthenticatorData(JsonObject clientDataJSON,
            Map<String, Object> publicKey, String attestation, Map<String, Object> extensions,
            Map<String, Object> extensionResults, KeyPair kp) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // Lets work out if we need to set authenticator extension data
        Map<String, Object> authenticatorExtensions = null;
        if (extensionResults != null) {
            // this object may or may not contain keys of extensions which must be set by
            // the authenticator
            for (String key : extensionResults.keySet()) {
                if (validAuthenticatorExtensions.contains(key)) {
                    if (authenticatorExtensions == null) {
                        authenticatorExtensions = new HashMap<String, Object>();
                    }
                    authenticatorExtensions.put(key, extensionResults.get(key));
                }
            }
        }

        // Construct Attestation Object https://w3c.github.io/webauthn/#sctn-attestation
        ByteArrayOutputStream authDataBytes = new ByteArrayOutputStream();

        // If this key is present we are doing attestation, otherwise do an assertion
        boolean performAttestation = publicKey.containsKey("attestation");

        // I've arbitrarily decided to make the credential ID the sha256 bytes of the
        // public key
        byte[] credIdBytes = digest.digest(kp.getPublic().getEncoded());

        String rpId = null;
        if (performAttestation) {
            rpId = (String) ((Map<String, Object>) publicKey.get("rp")).get("id");
        } else {
            if (extensions != null && extensions.get("appid") != null) {
                rpId = (String) extensions.get("appid");
            } else {
                rpId = (String) publicKey.get("rpId");
            }
        }
        byte[] rpIdHash = digest.digest(rpId.getBytes());
        authDataBytes.write(rpIdHash);

        int flags = 0x01; // UP
        if (performAttestation) {
            flags |= 0x40; // AT
        }
        if (attestation != null && !attestation.equalsIgnoreCase("fido-u2f")) {
            flags |= 0x04; // UV
        }
        if (authenticatorExtensions != null) {
            flags |= 0x80; // ED
        }
        // Flags
        authDataBytes.write(flags);
        // Signature counter
        authDataBytes.write(getCounterBytes());
        if (performAttestation) {
            byte[] attestedCredData = processAttestedCredentialData(kp.getPublic(),
                    credIdBytes);
            authDataBytes.write(attestedCredData);
        }
        if (authenticatorExtensions != null) { // If we have extensions write to the end of
                                               // authenticator data
            // ED flag set previously
            authDataBytes.write(DataMapper.objectToCbor(authenticatorExtensions));
        }
        byte[] authData = authDataBytes.toByteArray();

        return authData;
    }

    public JsonObject buildClientDataJson(Map<String, Object> publicKey) {
        String rp = (String) publicKey.get("rpId");
        String type = "webauthn.get";
        if (rp == null) {
            rp = (String) ((Map<String, Object>) publicKey.get("rp")).get("id");
            type = "webauthn.create";
        }
        JsonObject clientDataJSON = Json.createObjectBuilder().add("origin", "https://" + rp)
                .add("challenge",
                        new String(Base64.getUrlEncoder()
                                .encode((byte[]) publicKey.get("challenge"))))
                .add("type", type).build();
        return clientDataJSON;
    }

    public static byte[] signData(byte[] toSign, PrivateKey key, String alg)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance(alg);
        signer.initSign(key);
        signer.update(toSign);
        byte[] result = signer.sign();
        return result;
    }

    /**
     * process CCO options (if present) and returns the results
     * 
     * @param extensions
     * @return Map of extensions results OR null if no extensions to process
     * @throws NoSuchAlgorithmException
     */
    public Map<String, Object> processExtensions(Map<String, Object> extensions, String type)
            throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        Map<String, Object> extensionResults = null;
        // process registration extensions
        if (extensions != null) {
            // process attestation and assertion extensions
            extensionResults = new HashMap<String, Object>();

            if (type.equals("attestation")) {
                // process attestation extensions
                if (extensions.get("authnSel") != null) {
                    boolean authnSel = true;
                    // byte[][] aaguidList = (byte[][]) extensions.get("authnSel");
                    // System.out.println(Arrays.toString(aaguidList));
                    /*
                     * for(byte[] aaguidString: aaguidList) { byte[] aaguid = aaguidString;
                     * System.out.println(Arrays.toString(aaguid)); if(Arrays.equals(aaguid, new
                     * byte[16])) { authnSel = true; } }
                     */

                    extensionResults.put("authnSel", authnSel);
                }

                if (extensions.get("exts") != null
                        && ((boolean) extensions.get("exts")) == true) {
                    String[] exts = new String[] { "appid", "txAuthSimple" };
                    extensionResults.put("exts", exts);
                }
            }
            if (type.equals("assertion")) {
                // process assertion extensions
                if (extensions.get("txAuthSimple") != null) {
                    extensionResults.put("txAuthSimple",
                            (String) extensions.get("txAuthSimple"));
                    // System.err.println("txAuthSimple = " + (String)
                    // extensions.get("txAuthSimple"));
                }
                if (extensions.get("txAuthGeneric") != null) {
                    Map<String, Object> txAuthGeneric = (Map<String, Object>) extensions
                            .get("txAuthGeneric");
                    extensionResults.put("txAuthGeneric",
                            digest.digest(((String) txAuthGeneric.get("content")).getBytes()));
                    // System.err.println("txAuthGeneric = " + Arrays.toString(
                    // ((String) txAuthGeneric.get("content")).getBytes() ));
                }
                if (extensions.get("appid") != null) {
                    extensionResults.put("appid", true);

                }
            }
        }
        return extensionResults;
    }

    /*
     * Credentail Create helpers
     */

    public Map<String, Map<String, Object>> attestationOptionsResponeToCredentialCreationOptions(
            Map<String, Object> options) {
        // Public Key Credential Create Option
        // https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions
        Map<String, Object> pkcco = new HashMap<String, Object>();
        pkcco.put("rp", options.get("rp"));
        Map<String, Object> user = new HashMap<String, Object>();
        user.put("id", Base64.getUrlDecoder()
                .decode((String) ((Map<String, Object>) options.get("user")).get("id")));
        pkcco.put("user", user);
        pkcco.put("challenge",
                Base64.getUrlDecoder().decode((String) options.get("challenge")));
        pkcco.put("pubKeyCredParams", options.get("pubKeyCredParams"));

        if (options.get("timeout") != null) {
            if (options.get("timeout") instanceof String) {
                pkcco.put("timeout", Long.valueOf((String) options.get("timeout")));
            } else
                pkcco.put("timeout", Long.valueOf((Integer) options.get("timeout")));
        }
        if (options.get("excludeCredentials") != null) {
            pkcco.put("excludeCredentials", options.get("excludeCredentials"));
        }
        if (options.get("authenticatorSelector") != null) {
            pkcco.put("authenticatorSelector", options.get("authenticatorSelector"));
        }
        if (options.get("attestation") != null) {
            pkcco.put("attestation", options.get("attestation"));
        }
        if (options.get("extensions") != null) {
            pkcco.put("extensions", options.get("extensions"));
        }

        // Credential Create Option
        // https://w3c.github.io/webauthn/#credentialcreationoptions-extension
        Map<String, Map<String, Object>> cco = new HashMap<String, Map<String, Object>>();
        cco.put("publicKey", pkcco);

        return cco;
    }

    public byte[] processAttestedCredentialData(PublicKey pubKey, byte[] credIdBytes)
            throws IOException, NoSuchAlgorithmException, Fido2Exception {

        ByteArrayOutputStream attestedCredDataBytes = new ByteArrayOutputStream();
        attestedCredDataBytes.write(TEST_AAGUID);
        byte[] length = ByteBuffer.allocate(2).putShort((short) credIdBytes.length).array();
        attestedCredDataBytes.write(length[0]);
        attestedCredDataBytes.write(length[1]);
        attestedCredDataBytes.write(credIdBytes);

        // COSE Dict of key parameters
        Map<String, Object> credPublicKeyCOSE = new HashMap<String, Object>();
        if (pubKey instanceof ECPublicKey) {
            ECPoint point = ((ECPublicKey) pubKey).getW();
            credPublicKeyCOSE.put("1", 2); // kty
            credPublicKeyCOSE.put("3", -7); // alg
            credPublicKeyCOSE.put("-1", 1); // crv
            credPublicKeyCOSE.put("-2", ECBigIntegerToByteArray(point.getAffineX())); // x
                                                                                      // coordinate
            credPublicKeyCOSE.put("-3", ECBigIntegerToByteArray(point.getAffineY())); // y
                                                                                      // coordinate
        } else if (pubKey instanceof RSAPublicKey) {
            credPublicKeyCOSE.put("1", 3); // kty
            credPublicKeyCOSE.put("3", -257); // alg
            credPublicKeyCOSE.put("-1", ((RSAPublicKey) pubKey).getModulus()); // modulus
            credPublicKeyCOSE.put("-2", ((RSAPublicKey) pubKey).getPublicExponent()); // exponent
        }
        attestedCredDataBytes.write(DataMapper.objectToCbor(credPublicKeyCOSE));
        return attestedCredDataBytes.toByteArray();
    }

    public Map<String, Object> processAttestationStatement(String attestation,
            byte[] clientDataHash, byte[] authData, byte[] credIdBytes, KeyPair kp,
            KeyPair caKeyPair, X509Certificate akiCert) throws Exception {
        Map<String, Object> attStmt = null;
        if (attestation == null || attestation.equalsIgnoreCase("none")) {
            attStmt = new HashMap<String, Object>();
        } else if (attestation.equalsIgnoreCase("fido-u2f")) {
            attStmt = buildFIDOU2FAttestationStatement(clientDataHash, authData, credIdBytes,
                    kp, akiCert);
        } else if (attestation.equalsIgnoreCase("packed")) {
            attStmt = buildPackedAttestationStatement(clientDataHash, authData, credIdBytes,
                    null, caKeyPair, akiCert);
        } else if (attestation.equalsIgnoreCase("packed-self")) {
            attStmt = buildPackedAttestationStatement(clientDataHash, authData, credIdBytes, kp,
                    null, null);
        } else if (attestation.equalsIgnoreCase("tpm")) {
            attStmt = buildTPMAttestationStatement(clientDataHash, authData, credIdBytes,
                    akiCert, caKeyPair, kp);
        } else {
            throw new Exception("Invalid attestation type specified: " + attestation);
        }
        return attStmt;
    }

    public Map<String, Object> processCredentialCreationOptions(
            Map<String, Map<String, Object>> cco, String attestation, KeyPair kp,
            KeyPair caKeyPair, X509Certificate akiCert)
            throws NoSuchAlgorithmException, IOException, Exception, Fido2Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        Map<String, Object> publicKey = (Map<String, Object>) cco.get("publicKey");
        Map<String, Object> extensions = null;
        if (publicKey.get("extensions") != null) {
            extensions = DataMapper.cborToObject((byte[]) publicKey.get("extensions"),
                    HashMap.class);
        }
        Map<String, Object> extensionResults = processExtensions(extensions, "attestation");

        JsonObject clientDataJSON = buildClientDataJson(publicKey);
        byte[] clientDataBytes = clientDataJSON.toString().getBytes();
        byte[] clientDataHash = digest.digest(clientDataBytes);
        String clientDataString = Base64.getUrlEncoder().encodeToString(clientDataBytes);

        byte[] credIdBytes = digest.digest(kp.getPublic().getEncoded());
        String credIdString = new String(Base64.getUrlEncoder().encode(credIdBytes));

        byte[] authData = buildAuthenticatorData(clientDataJSON, publicKey, attestation,
                extensions, extensionResults, kp);
        Map<String, Object> attStmt = processAttestationStatement(attestation, clientDataHash,
                authData, credIdBytes, kp, caKeyPair, akiCert);
        Map<String, Object> attestationObject = new HashMap<String, Object>();
        attestationObject.put("authData", authData);
        attestationObject.put("fmt",
                attestation.equalsIgnoreCase("packed-self") ? "packed" : attestation);
        attestationObject.put("attStmt", attStmt);

        // Server Authentication Attestation Response
        // https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#example-authenticator-attestation-response
        Map<String, String> saar = new HashMap<String, String>();
        saar.put("clientDataJSON", clientDataString);
        // add the base64 URL of the CBOR encoding of the attestationObject to the
        // response
        saar.put("attestationObject", new String(
                Base64.getUrlEncoder().encode(DataMapper.objectToCbor(attestationObject))));

        // Server Public Key Creadential
        // https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredential
        Map<String, Object> spkc = new HashMap<String, Object>();
        spkc.put("id", credIdString);
        spkc.put("rawId", spkc.get("id"));
        spkc.put("response", saar);
        spkc.put("type", "public-key");
        // TODO extensions
        spkc.put("getClientExtensionResults", DataMapper.objectToCbor(extensionResults));
        return spkc;
    }

    public byte[] buildRsaPubArea(KeyPair aikKeyPair) throws IOException {
        // build pubArea
        ByteArrayOutputStream pubAreaByteStream = new ByteArrayOutputStream();
        pubAreaByteStream.write(new byte[] { 0, 1 }); // type TMP_ALG_ID = TMP_ALG_RSA
        pubAreaByteStream.write(new byte[] { 0, 11 }); // name_alg (used to generate
                                                       // attested_name in certInfo) =
                                                       // TMP_ALG_SHA256
        pubAreaByteStream.write(new byte[4]); // TPMA_OBJECT bits
        pubAreaByteStream.write(new byte[2]); // authPolicy, set length = 0 and ignore
        // RSA key params
        pubAreaByteStream.write(new byte[] { 0, 1 }); // symetric = TMP_ALG_NULL
        pubAreaByteStream.write(new byte[] { 1, 4 }); // scheme = TMP_ALG_RSASSA (PKCS1-v1.5)
        pubAreaByteStream.write(new byte[] { 4, 0 }); // key size = 1024
        pubAreaByteStream.write(new byte[4]); // exponent
        byte[] unique = ((RSAPublicKey) aikKeyPair.getPublic()).getModulus().toByteArray();
        byte[] uniqueLength = ByteBuffer.allocate(2).putShort((short) unique.length).array();
        pubAreaByteStream.write(uniqueLength[0]);
        pubAreaByteStream.write(uniqueLength[1]);
        pubAreaByteStream.write(unique); // unique (n - coefficient)

        byte[] pubArea = pubAreaByteStream.toByteArray();
        return pubArea;
    }

    public byte[] buildRsaCertInfo(byte[] attsToSign, byte[] pubInfo)
            throws IOException, NoSuchAlgorithmException {
        // build certInfo
        ByteArrayOutputStream certInfoByteStream = new ByteArrayOutputStream();
        certInfoByteStream.write(new byte[] { (byte) 0xFF, 0x54, 0x43, 0x47 }); // magic, 4 byte
                                                                                // constant
                                                                                // specifying
                                                                                // TPM_GENERATED
        certInfoByteStream.write(new byte[] { (byte) 0x80, 0x17 }); // attestation type, 2 byte
                                                                    // TPM_ST_ATTEST_CERTIFY
        certInfoByteStream.write(new byte[2]); // qualified signer length, 0 = Ignore
        // calculate hash of attsToBeSigned
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] sigHash = digest.digest(attsToSign);
        int[] sigHashLength = { (sigHash.length - (sigHash.length & 0xFF)) / 256,
                sigHash.length & 0xFF };
        certInfoByteStream.write(sigHashLength[0]); // write sigHash to certInfo
        certInfoByteStream.write(sigHashLength[1]); // goes in extraData field
        certInfoByteStream.write(sigHash);
        // write clock Info, arbitrarily set to zero
        certInfoByteStream.write(new byte[17]); // uint64 clock, uint32 resetCount, uint32
                                                // restartCount, safe
        System.out.println("Vendor Id = " + Arrays.toString(TPM_VENDOR_ID_CONFORMANCE));
        certInfoByteStream.write((new byte[8 - TPM_VENDOR_ID_CONFORMANCE.length])); // pad with
                                                                                    // correct
                                                                                    // number of
                                                                                    // 0 bytes
        certInfoByteStream.write(TPM_VENDOR_ID_CONFORMANCE); // write Vendor ID, must pad to 8
                                                             // bytes
        // hash of pubInfo = attestedName
        ByteArrayOutputStream attestedNameByteStream = new ByteArrayOutputStream();
        attestedNameByteStream.write(new byte[] { 0x00, 0x0B }); // name_alg from pubInfo field
        byte[] pubInfoHash = digest.digest(pubInfo);
        attestedNameByteStream.write(pubInfoHash);
        byte[] attestedName = attestedNameByteStream.toByteArray();
        byte[] attestedNameLength = ByteBuffer.allocate(2).putShort((short) attestedName.length)
                .array();
        certInfoByteStream.write(attestedNameLength[0]);
        certInfoByteStream.write(attestedNameLength[1]);
        certInfoByteStream.write(attestedName);
        // attested qualified name, can ignore
        certInfoByteStream.write(new byte[] { 0x00, 0x00 }); // length = 0 === ignore
        byte[] certInfo = certInfoByteStream.toByteArray();

        return certInfo;

    }

    public Map<String, Object> buildTPMAttestationStatement(byte[] clientDataHash,
            byte[] authData, byte[] credId, X509Certificate caCert, KeyPair caKeyPair,
            KeyPair aikKeyPair) throws Exception {
        Map<String, Object> result = new HashMap<String, Object>();
        if (aikKeyPair.getPublic() instanceof ECPublicKey) {
            throw new RuntimeException(
                    "Unsupported key type" + aikKeyPair.getPublic().getClass().getName());
        }

        KeyPair intermediateKeyPair = CertUtils.generateKeyPair("RSA", 2048);
        X509Certificate intermediateCert = CertUtils.generateIntermediateCACert(caCert,
                "CN=intermediateCA", 365, intermediateKeyPair, caKeyPair);
        String altNames = Fido2Authenticator.TPM_VENDOR + "=IBMTPM+"
                + Fido2Authenticator.TPM_MANUFACTURER + "=id:"
                + new BigInteger(Fido2Authenticator.TPM_VENDOR_ID_CONFORMANCE).toString(16)
                + "+" + Fido2Authenticator.TPM_FW_VERSION + "=id:1";
        X509Certificate aikCert = CertUtils.generateAIKCert(intermediateCert, 365, aikKeyPair,
                altNames, intermediateKeyPair);
        result.put("ver", "2.0");
        result.put("alg", -257); // SHA256 with RSA
        result.put("x5c", new byte[][] { aikCert.getEncoded(), intermediateCert.getEncoded(),
                caCert.getEncoded() });

        // build attsToSign
        ByteArrayOutputStream sigByteStream = new ByteArrayOutputStream();
        sigByteStream.write(authData);
        sigByteStream.write(clientDataHash);
        byte[] attsToSign = sigByteStream.toByteArray();

        byte[] pubInfo = buildRsaPubArea(aikKeyPair);
        result.put("pubArea", pubInfo);

        byte[] certInfo = buildRsaCertInfo(attsToSign, pubInfo);
        result.put("certInfo", certInfo);

        // add sig of certInfo
        byte[] sig = signData(certInfo, aikKeyPair.getPrivate(), "SHA256withRSA");
        result.put("sig", sig);

        return result;
    }

    public Map<String, Object> buildFIDOU2FAttestationStatement(byte[] clientDataHash,
            byte[] authData, byte[] credId, KeyPair caKeyPair, X509Certificate caCert)
            throws Exception {
        Map<String, Object> result = new HashMap<String, Object>();

        ECPoint point = ((ECPublicKey) caKeyPair.getPublic()).getW();
        ByteArrayOutputStream pubKeyU2FStream = new ByteArrayOutputStream();
        pubKeyU2FStream.write(0x04);
        pubKeyU2FStream.write(ECBigIntegerToByteArray(point.getAffineX())); // x coordinate
        pubKeyU2FStream.write(ECBigIntegerToByteArray(point.getAffineY())); // y coordinate
        byte[] pubKeyU2F = pubKeyU2FStream.toByteArray();
        result.put("x5c", new byte[][] { caCert.getEncoded() });

        byte[] rpidHashBytes = Arrays.copyOfRange(authData, 0, 32);

        ByteArrayOutputStream sigByteStream = new ByteArrayOutputStream();
        sigByteStream.write(0x00);
        sigByteStream.write(rpidHashBytes);
        sigByteStream.write(clientDataHash);
        sigByteStream.write(credId);
        sigByteStream.write(pubKeyU2F);
        byte[] signature = signData(sigByteStream.toByteArray(), caKeyPair.getPrivate(),
                "SHA256withECDSA");
        result.put("sig", signature);

        return result;
    }

    public Map<String, Object> buildPackedAttestationStatement(byte[] clientDataHash,
            byte[] authData, byte[] credId, KeyPair attestnKeyPair, KeyPair caKeyPair,
            X509Certificate akiCert) throws Exception {
        Map<String, Object> result = new HashMap<String, Object>();
        String alg = "";

        if (attestnKeyPair != null) {
            // we are doing self
            if (attestnKeyPair.getPrivate() instanceof ECPrivateKey) {
                alg = "SHA256withECDSA";
                result.put("alg", -7);
            } else if (attestnKeyPair.getPrivate() instanceof RSAPrivateKey) {
                alg = "SHA256withRSA";
                result.put("alg", -257);
            } else {
                throw new Exception("Unsuported Key Type");
            }
        } else {
            attestnKeyPair = getKeyPair();
            if (attestnKeyPair.getPrivate() instanceof ECPrivateKey) {
                throw new Exception("Not yet implemented");
            } else if (attestnKeyPair.getPrivate() instanceof RSAPrivateKey) {
                if (akiCert == null) {
                    // we are doing basic
                    byte[] attestnCert = CertUtils.generatePackedBasicCertificate(
                            "C=AU,O=IBM,OU=Authenticator Attestation,CN=packedBasic",
                            attestnKeyPair, 365, new BigInteger(TEST_AAGUID).toString(16))
                            .getEncoded();
                    result.put("x5c", new byte[][] { attestnCert });
                    alg = "SHA256withRSA";
                    result.put("alg", -257);
                } else {
                    // we are doint attCA
                    byte[] caCert = akiCert.getEncoded();
                    byte[] attestnCert = CertUtils
                            .gereatePackedAttCACertificate(akiCert,
                                    "C=AU,O=IBM,OU=Authenticator Attestation,CN=packedAttCA",
                                    attestnKeyPair, 365,
                                    new BigInteger(TEST_AAGUID).toString(16), caKeyPair)
                            .getEncoded();
                    result.put("x5c", new byte[][] { attestnCert, caCert });
                    alg = "SHA256withRSA";
                    result.put("alg", -257);
                }
            } else {
                throw new Exception("Unsuported Key Type");
            }
        }
        ByteArrayOutputStream sigByteStream = new ByteArrayOutputStream();
        sigByteStream.write(authData);
        sigByteStream.write(clientDataHash);
        byte[] signature = signData(sigByteStream.toByteArray(), attestnKeyPair.getPrivate(),
                alg);
        result.put("sig", signature);
        return result;
    }

    /*
     * Credential request helpers
     */
    public static Map<String, Object> assertionOptionsResponseToCredentialRequestOptions(
            Map<String, Object> options) {
        // Credential Request Options
        Map<String, Object> cro = new HashMap<String, Object>();
        // https://w3c.github.io/webauthn/#dictdef-publickeycredentialrequestoptions
        Map<String, Object> pkcro = new HashMap<String, Object>();

        pkcro.put("challenge",
                Base64.getUrlDecoder().decode((String) options.get("challenge")));
        if (options.get("timeout") != null) {
            if (options.get("timeout") instanceof String) {
                pkcro.put("timeout", Long.valueOf((String) options.get("timeout")));
            } else
                pkcro.put("timeout", Long.valueOf((Integer) options.get("timeout")));
        }
        if (options.get("rpId") != null) {
            pkcro.put("rpId", options.get("rpId"));
        }
        if (options.get("allowedCredentials") != null) {
            Map<String, Object>[] allowedCreds = (Map<String, Object>[]) options
                    .get("allowedCredentials");
            pkcro.put("allowedCredentails",
                    (Map<String, Object>[]) new Map[(allowedCreds.length)]);
            int pos = 0;
            for (Map<String, Object> c : allowedCreds) {
                Map<String, Object> cred = new HashMap<String, Object>();
                cred.put("type", c.get("type"));
                cred.put("id", Base64.getUrlDecoder().decode((String) c.get("id")));
                if (c.get("transports") != null) {
                    cred.put("transports", c.get("transports"));
                }
                ((Map<String, Object>[]) pkcro.get("allowedCredentails"))[pos++] = cred;
            }

        }
        if (options.get("userVerification") != null) {
            pkcro.put("userVerification", options.get("userVerification"));
        }
        if (options.get("extensions") != null) {
            pkcro.put("extensions", options.get("extensions"));
        }
        cro.put("publicKey", pkcro);

        return cro;
    }

    public Map<String, Object> processCredentialRequestOptions(Map<String, Object> cro,
            KeyPair kp) throws Exception, Fido2Exception {
        Map<String, Object> spkc = new HashMap<String, Object>();
        Map<String, Object> saar = new HashMap<String, Object>();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        Map<String, Object> publicKey = (Map<String, Object>) cro.get("publicKey");
        Map<String, Object> extensions = null;

        if (publicKey.get("extensions") != null) {
            extensions = DataMapper.cborToObject((byte[]) publicKey.get("extensions"),
                    HashMap.class);
        }
        Map<String, Object> extensionResults = processExtensions(extensions, "assertion");

        JsonObject clientDataJSON = buildClientDataJson(publicKey);
        byte[] clientDataBytes = clientDataJSON.toString().getBytes();
        String clientDataString = Base64.getUrlEncoder().encodeToString(clientDataBytes);
        saar.put("clientDataJSON", clientDataString);

        // Construct Attestation Object https://w3c.github.io/webauthn/#sctn-attestation
        byte[] authData = buildAuthenticatorData(clientDataJSON, publicKey, null, extensions,
                extensionResults, kp);

        saar.put("authenticatorData", Base64.getUrlEncoder().encode(authData));

        // credential information
        byte[] clientDataHash = digest.digest(clientDataBytes);
        // I've arbitrarily decided to make the credential ID the sha256 bytes of the
        // public key
        byte[] credIdBytes = digest.digest(kp.getPublic().getEncoded());

        ByteArrayOutputStream sigByteStream = new ByteArrayOutputStream();
        sigByteStream.write(authData);
        sigByteStream.write(clientDataHash);
        String alg = ((kp.getPublic() instanceof ECPublicKey) ? "SHA256withECDSA"
                : "SHA256withRSA");
        byte[] signature = signData(sigByteStream.toByteArray(), kp.getPrivate(), alg);

        saar.put("signature", Base64.getUrlEncoder().encode(signature));
        saar.put("userHandle", "");

        spkc.put("id", Base64.getUrlEncoder().encodeToString(credIdBytes));
        spkc.put("rawId", spkc.get("id"));
        spkc.put("response", saar);
        // type (from Credential defined here:
        // https://w3c.github.io/webappsec-credential-management/#credential)
        spkc.put("type", "public-key");
        if (extensionResults != null) {
            spkc.put("getClientExtensionResults", DataMapper.objectToCbor(extensionResults));
        } else {
            spkc.put("getClientExtensionResults",
                    DataMapper.objectToCbor(new HashMap<String, Object>()));
        }

        return spkc;
    }

    /*
     * Every time we call this method, we expect to do an attestation or assertion,
     * therefore lets icnrease the counter
     */
    public byte[] getCounterBytes() {
        // we store as a long, but only use the least significant 4 bytes
        byte[] result = new byte[4];
        long x = counter;
        for (int i = 3; i >= 0; i--) {
            result[i] = (byte) (x & 0xFF);
            x >>= 8;
        }
        counter += 1;
        return result;
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            // System.out.println("Usage: Fido2Authenticator pemfile");
            System.exit(1);
        }
    }
}
