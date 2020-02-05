package com.isfs.util;

import java.security.KeyPair;


public class KeyFactory {
    
    private static KeyFactory _instance = null;
    
    private static KeyPair _rsa = null;

    private static KeyPair _ec = null;
    
    private static KeyPair _rsa_ca = null;
    
    private static KeyPair _ec_ca = null;
    
    private static KeyPair _u2f = null;
    
    private KeyFactory() { }

    
    public static KeyPair getKeyPair(String alg) throws Exception {
        if (alg == "RSA") {
            return getRSAKeyPair();
        }
        else if (alg == "EC") {
            return getECKeyPair();
        }
        else if (alg == "RSA-CA") {
            return getRSAcaKeyPair();
        }
        else if (alg == "EC-CA") {
            return getECcaKeyPair();
        }
        else if (alg == "U2F") {
            return getU2FKeyPair();
        }
        return null;
    }
    
    
    private static KeyPair getRSAKeyPair() throws Exception {
        if (_rsa == null) {
            synchronized(KeyFactory.class) {
                if (_rsa == null) {
                    _rsa = CertUtils.generateKeyPair("RSA", 2048);
                }
            }
        }
        return _rsa;
    }
  
    
    private static KeyPair getRSAcaKeyPair() throws Exception {
        if (_rsa_ca == null) {
            synchronized(KeyFactory.class) {
                if (_rsa_ca == null) {
                    _rsa_ca = CertUtils.generateKeyPair("RSA", 2048);
                }
            }
        }
        return _rsa_ca;
    }
    
    
    private static KeyPair getECKeyPair() throws Exception {
        if (_ec == null) {
            synchronized(KeyFactory.class) {
                if (_ec == null) {
                    _ec = CertUtils.generateKeyPair("EC", 256);
                }
            }
        }
        return _ec;
    }
    
    private static KeyPair getECcaKeyPair() throws Exception {
        if (_ec_ca == null) {
            synchronized(KeyFactory.class) {
                if (_ec_ca == null) {
                    _ec_ca = CertUtils.generateKeyPair("EC", 521);
                }
            }
        }
        return _ec_ca;
    }
    
    
    private static KeyPair getU2FKeyPair() throws Exception {
        if (_u2f == null) {
            synchronized(KeyPair.class) { 
                if(_u2f == null) {
                    _u2f = CertUtils.generateKeyPair("EC", 256);
                }
            }
        }
        return _u2f;
    }
}
