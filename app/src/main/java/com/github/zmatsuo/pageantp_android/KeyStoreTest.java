
package com.github.zmatsuo.pageantp_android;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.spongycastle.jce.X509Principal;
import org.spongycastle.x509.X509V3CertificateGenerator;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.security.auth.x500.X500Principal;

import static com.github.zmatsuo.pageantp_android.Sign.getFingerprintSHA256Base64;
import static com.github.zmatsuo.pageantp_android.Sign.getPublicKey;

public class KeyStoreTest {
    private Context mContext;
    
    final String KEY_STORE_ALIAS = "alias";
    String KEY_NAME = "test_key_name";
    int AUTHENTICATION_DURATION_SECONDS = 5*60;

    public X509Certificate generateCertificate(KeyPair keyPair) {
        Calendar now = Calendar.getInstance();
        Calendar expiry = now;
        expiry.add(Calendar.YEAR, 10);

        X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
        cert.setSerialNumber(BigInteger.valueOf(1));   //or generate a random number  
        cert.setSubjectDN(new X509Principal("CN=localhost"));  //see examples to add O,OU etc
        cert.setIssuerDN(new X509Principal("CN=localhost")); //same since it is self-signed  
        cert.setPublicKey(keyPair.getPublic());  
        cert.setNotBefore(now.getTime());
        cert.setNotAfter(expiry.getTime());
        cert.setSignatureAlgorithm("SHA1WithRSAEncryption");   
        PrivateKey signingKey = keyPair.getPrivate();
        X509Certificate _cert = null;
        try {
            _cert = cert.generate(signingKey, "BC");
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return _cert;
    }

    @TargetApi(23)
    private PrivateKey getPrivate_60() {
        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        try {
            keyStore.load(null);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        try {
            Enumeration<String> aliases = keyStore.aliases();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        boolean r = false;
        try {
            r = keyStore.containsAlias(KEY_STORE_ALIAS);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        // https://qiita.com/f_nishio/items/485490dea126dbbb5001

        if (r) {
            try {
                publicKey  = keyStore.getCertificate(KEY_STORE_ALIAS).getPublicKey();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
            try {
                privateKey = (PrivateKey)keyStore.getKey(KEY_STORE_ALIAS, null);
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (UnrecoverableKeyException e) {
                e.printStackTrace();
            }
            return privateKey;
        } else {
            KeyGenerator keyGenerator = null;
            try {
                keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            }

            // セキュリティ鍵を生成する
            try {
                keyGenerator.init(
                    new KeyGenParameterSpec.Builder(
                        KEY_NAME,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    //.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    // デバイス認証機能を必須化. デバイス認証機能がOFFの場合はセキュリティ例外が発生する
                    //.setUserAuthenticationRequired(true)
                    // セキュリティ鍵の有効期間を設定する
                    .setUserAuthenticationValidityDurationSeconds(AUTHENTICATION_DURATION_SECONDS)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }
            keyGenerator.generateKey();

            // try {
            //     publicKey  = keyStore.getCertificate(KEY_STORE_ALIAS).getPublicKey();
            // } catch (KeyStoreException e) {
            //     e.printStackTrace();
            // }

            try {
                privateKey = (PrivateKey)keyStore.getKey(KEY_STORE_ALIAS, null);
            } catch (UnrecoverableKeyException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }
        return privateKey;
    }

    // android 4.3
    // https://qiita.com/Koganes/items/e8253f13ecb534ca11a1
    // https://qiita.com/KazaKago/items/8b24f0a3f8744de35b4e
    // https://qiita.com/f_nishio/items/485490dea126dbbb5001
    private KeyPairGeneratorSpec createKeyPairGeneratorSpec() {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 100);

        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(mContext)
                .setAlias(KEY_STORE_ALIAS)
                .setSubject(new X500Principal(String.format("CN=%s", KEY_STORE_ALIAS)))
                .setSerialNumber(BigInteger.valueOf(1000000))
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .build();

        return spec;
    }

    private KeyPair createKeyPair() {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            kpg.initialize(createKeyPairGeneratorSpec());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return kpg.generateKeyPair();
    }

    private KeyPair getKeyPair(String fingerPrint) {
        String alias = fingerPrint;
        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        KeyStore keyStore = getKeyStore();
        KeyPair keyPair = null;
        try {
            if (keyStore.containsAlias(alias)) {
                // キーストアにあった場合
                publicKey  = keyStore.getCertificate(alias).getPublicKey();
                privateKey = (PrivateKey)keyStore.getKey(alias, null);
                keyPair = new KeyPair(publicKey, privateKey);
            } else {
                return null;
//                keyPair = createKeyPair();
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyPair;
    }
    private PrivateKey getPrivate_50(String fingerPrint) {
        KeyPair keyPair = getKeyPair(fingerPrint);
        return keyPair.getPrivate();
    }
    private PublicKey getPublic_50(String fingerPrint) {
        KeyPair keyPair = getKeyPair(fingerPrint);
        return keyPair.getPublic();
    }

    public void test() {
        PrivateKey privateKey = null;
        if(Build.VERSION.SDK_INT <= Build.VERSION_CODES.LOLLIPOP){
            // -5.0
            privateKey = getPrivate_50(KEY_STORE_ALIAS);
        } else {
            privateKey = getPrivate_60();
        }
        {
            String plainText = "hogehoge";
            byte[] data = plainText.getBytes();
            byte[] sign = null;

            try {
                // 署名(秘密鍵)
                Signature signer = Signature.getInstance("SHA1withRSA");
                signer.initSign(privateKey);
                signer.update(data);
                sign = signer.sign();
            } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            byte[] signedByte_ = sign;
        }
    }

    public void setContext(Context context) {
        mContext = context;
    }

    private KeyStore getKeyStore() {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        try {
            keyStore.load(null);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return keyStore;
    }

    public void importPrivateKey(PrivateKey privateKey) {
        //Certificate cert = getCertificate();
        X509Certificate cert;
        {
            PublicKey publicKey = getPublicKey(privateKey);
            KeyPair keyPair = new KeyPair(publicKey, privateKey);
            cert = generateCertificate(keyPair);
        }
        KeyStore keyStore = getKeyStore();
        try {
            String alias = getFingerprintSHA256Base64(privateKey);
            keyStore.setKeyEntry(alias, privateKey, null, new Certificate[] {cert});
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }


    // private PrivateKey getPrivateKeyFromKeyStore() {
    //     PrivateKey pk = getPrivate_50(KEY_STORE_ALIAS);
    //     return pk;
    // }

    private Enumeration<String> getAliases() {
        Enumeration<String> aliases = null;
        KeyStore keyStore = getKeyStore();
        int a = 0;
        try {
            aliases = keyStore.aliases();
            a = 1;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        a = 0;
        return aliases;
    }

    // public List<PrivateKey> getPrivateKeys() {
    //     List<PrivateKey> keys = new ArrayList<>();
    //     //PrivateKey privateKey = MainActivity.getPrivateKey();
    //     PrivateKey privateKey = getPrivateKeyFromKeyStore();
    //     if (privateKey != null) {
    //         keys.add(privateKey);
    //     }
    //     return keys;
    // }

    // public List<PublicKey> getPublicKeys2() {
    //     List<PublicKey> keys = new ArrayList<>();
    //     List<PrivateKey> privateKeys = getPrivateKeys();
    //     for (PrivateKey privateKey: privateKeys) {
    //         PublicKey publicKey = (PublicKey)Sign.getPublicKey(privateKey);
    //         keys.add(publicKey);
    //     }
    //     return keys;
    // }
    public List<PublicKey> getPublicKeys() {
        List<String> fingerprints = getFingerPrints();
        List<PublicKey> keys = new ArrayList<>();
        for (String fingerprint: fingerprints) {
            PublicKey publicKey = getPublic_50(fingerprint);
            keys.add(publicKey);
        }
        return keys;
    }

    public List<String> getFingerPrints() {
        List<String> fingerprints = new ArrayList<>();
        Enumeration<String> aliases = getAliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            fingerprints.add(alias);
        }
        return fingerprints;
    }

    public PrivateKey getPrivateKey(String fingerprint) {
        PrivateKey privateKey = getPrivate_50(fingerprint);
        return privateKey;
    }

    public PrivateKey getPrivateKey(PublicKey publicKey) {
        String fingerprint = getFingerprintSHA256Base64(publicKey);
        return getPrivateKey(fingerprint);
    }

    public boolean deleteKey(final String fingerprint) {
        KeyStore keyStore = getKeyStore();
        try {
            keyStore.deleteEntry(fingerprint);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return true;
    }

    ////////////////////////////////////////////////////////////
    void test3() {
        Enumeration<String> l = getAliases();
        int a = 0;
    }

    ////////////////////////////////////////////////////////////

    // android M Marshmallow 6.0-6.0.1 API 23-
    //  KeyPairGeneratorSpec -> KeyGenParameterSpec
    ////////////////////////////////////////////////////////////

    @TargetApi(23)
    private void test2()
    {
        /*
         * Generate a new EC key pair entry in the Android Keystore by
         * using the KeyPairGenerator API. The private key can only be
         * used for signing or verification and only with SHA-256 or
         * SHA-512 as the message digest.
         */
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        try {
            kpg.initialize(new KeyGenParameterSpec.Builder(
                               KEY_STORE_ALIAS,
                               KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                           .setDigests(KeyProperties.DIGEST_SHA256,
                                       KeyProperties.DIGEST_SHA512)
                           .build());
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        KeyPair kp = kpg.generateKeyPair();
    }

    ////////////////////////////////////////////////////////////
}
