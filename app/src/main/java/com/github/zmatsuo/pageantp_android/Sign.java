
package com.github.zmatsuo.pageantp_android;

import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.atomic.AtomicInteger;

public class Sign {
    final private static int SIZEOF_INT = 4;
    final private static String TAG = "Sign";

    public static PublicKey getPublicKey(final byte[] publicKeyBin) {
        PublicKey publicKey = null;
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(publicKeyBin);

            AtomicInteger position = new AtomicInteger();
            String algorithm = readString(byteBuffer, position);
            assert "ssh-rsa".equals(algorithm);
            BigInteger publicExponent = readMpint(byteBuffer, position);
            BigInteger modulus = readMpint(byteBuffer, position);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(keySpec);

            byte[] pubBytes = publicKey.getEncoded();
            
            PublicKey publickey2 = kf.generatePublic(keySpec);
            if (publicKey.equals(publickey2)){
                Log.d(TAG, "equal\n");
            }
		} catch (Exception e) {
            e.printStackTrace();
        }

        return publicKey;
    }

    /**
     *  sshで使う公開鍵のbase64部分を入力すると、公開鍵を取得できる
     *      ★更に publickKey.getEncoded()でssh-agentと同じ形式のbyte[]にすることができる
     *          byte[] pubBytes = publicKey.getEncoded();
     *
     */
    public static PublicKey getPublicKey(final String base64) {
        byte[] decoded = Base64.decode(base64, Base64.DEFAULT);
        return getPublicKey(decoded);
    }

    public static PublicKey getPublicKey(File file)
    {
        final byte[] keyBytes = Binutil.readAllBytes(file);

        PublicKey key = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec spec =
                    new X509EncodedKeySpec(keyBytes);
            key = kf.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return key;
    }
    
    public static RSAPrivateCrtKeySpec getRSAPrivateCrtKeySpec(final byte [] privateKey) {
        RSAPrivateCrtKeySpec privateKeySpec = null;
        try {
            privateKeySpec = PrivateKeyReader.getRSAKeySpecPKCS8(privateKey);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return privateKeySpec;
    }
    
    public static RSAPrivateCrtKeySpec getRSAPrivateCrtKeySpec(RSAPrivateKey privateKey) {
        return getRSAPrivateCrtKeySpec(privateKey.getEncoded());
    }
    
    public static RSAPublicKey getPublicKey(PrivateKey _privateKey) {
        String alg = _privateKey.getAlgorithm();
        byte [] b = _privateKey.getEncoded();
        RSAPrivateCrtKeySpec privateKeySpec = getRSAPrivateCrtKeySpec(b);

        RSAPrivateKey privateKey = (RSAPrivateKey)_privateKey;

        privateKeySpec = getRSAPrivateCrtKeySpec(privateKey);

        RSAPublicKeySpec publicKeySpec
            = new RSAPublicKeySpec(
                privateKeySpec.getModulus(),
                privateKeySpec.getPublicExponent());

        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        RSAPublicKey publicKey = null;
        try {
            publicKey = (RSAPublicKey)kf.generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }
    
    private static BigInteger readMpint(ByteBuffer buffer, AtomicInteger pos){
        byte[] bytes = readBytes(buffer, pos);
        if(bytes.length == 0){
            return BigInteger.ZERO;
        }
        return new BigInteger(bytes);
    }

    private static String readString(ByteBuffer buffer, AtomicInteger pos){
        byte[] bytes = readBytes(buffer, pos);
        if(bytes.length == 0){
            return "";
        }
        return new String(bytes, StandardCharsets.US_ASCII);
    }

    private static byte[] readBytes(ByteBuffer buffer, AtomicInteger pos){
        int len = buffer.getInt(pos.get());
        byte buff[] = new byte[len];
        for(int i = 0; i < len; i++) {
            buff[i] = buffer.get(i + pos.get() + SIZEOF_INT);
        }
        pos.set(pos.get() + SIZEOF_INT + len);
        return buff;
    }

    /**
     * file is der format  `openssl -outform der`
     */
    public static PrivateKey getPrivateKey(File file)
    {
        final byte[] keyBytes = Binutil.readAllBytes(file);

        PrivateKey key = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec spec =
                    new PKCS8EncodedKeySpec(keyBytes);
            key = kf.generatePrivate(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return key;
    }

    public static PrivateKey getPrivateKey(String privateKeyFile) {
        File path_private = new File(privateKeyFile);
        PrivateKey privateKey = getPrivateKey(path_private);
        return privateKey;
    }

    // 秘密鍵を表示
    public static String showPrivateKey(PrivateKey _privateKey)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("[private]\n");
        sb.append(_privateKey.getClass().getName()+"\n");
        String algorithm = _privateKey.getAlgorithm();
        sb.append(algorithm+"\n");
        if (algorithm.equals("RSA")) {
            RSAPrivateKey privateKey = (RSAPrivateKey) _privateKey;
            BigInteger modulus = privateKey.getModulus();
            //BigInteger publicExponent = privateKey.getPublicExponent();
            sb.append(String.format("Modulus: %X%n", modulus));
            //sb.append(String.format("public exponent: %X%n", publicExponent));

            byte[] privateKeyBytes = privateKey.getPrivateExponent().toByteArray();
            String privateKeyBase64 = Base64.encodeToString(privateKeyBytes, Base64.DEFAULT);
            sb.append(privateKeyBase64+"\n");
            String s;
            s = getFingerprintSHA256Base64(privateKey);
            sb.append("Fingerprint "+s+"\n");
        }
        return sb.toString();
    }

    // 公開鍵を表示
    static String showPublicKey(PublicKey _publicKey)
    {
        StringBuilder sb = new StringBuilder();

        sb.append("[public]\n");
        sb.append(_publicKey.getClass().getName()+"\n");
        String algorithm = _publicKey.getAlgorithm();
        sb.append(algorithm+"\n");
        if (algorithm.equals("RSA")) {
            RSAPublicKey publicKey = (RSAPublicKey)_publicKey;

            // Modulusを表示 (公開鍵と秘密鍵の両方に入っている)
            BigInteger modulus = publicKey.getModulus();
            BigInteger publicExponent = publicKey.getPublicExponent();

            sb.append(String.format("Modulus: %X%n", modulus));
            sb.append(String.format("private exponent: %X%n", publicExponent));

            // byte[] modulusBytes  = modulus.toByteArray();
            // String modulusBase64 = Base64.encodeToString(modulusBytes, Base64.DEFAULT);
            // System.out.println(modulusBase64);

            byte[] b = publicKey.getEncoded();
            sb.append(Binutil.dump(b,b.length));
        }
        return sb.toString();
    }

    public static byte[] sign_data(final PrivateKey privateKey, final byte[] data)
    {
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

        return sign;
    }

    // 検証(公開鍵)
    public static boolean verify(PublicKey publicKey, byte[] data, byte[] sign)
    {
        Signature verifier;
        boolean result = false;
        try {
            verifier = Signature.getInstance("SHA256withRSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        }
        try {
            verifier.initVerify(publicKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        try {
            verifier.update(data);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        try {
            result = verifier.verify(sign);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        System.out.println("verify=" + result);

        return result;
    }

    /**
     *  RFC4716 binary
     */
    public static byte[] getBin(PublicKey _publicKey) {
        RSAPublicKey publicKey = (RSAPublicKey)_publicKey;
        final byte[] exponentBytes  = publicKey.getPublicExponent().toByteArray();
        final byte[] modulusBytes  = publicKey.getModulus().toByteArray();
        final String sshRsh = "ssh-rsa";

        int length = 4*3 + sshRsh.length() + exponentBytes.length + modulusBytes.length;
        byte[] dest = new byte[length];
        int pos = 0;
        pos = Binutil.putBin(dest, pos, sshRsh);
        pos = Binutil.putBin(dest, pos, exponentBytes);
        pos = Binutil.putBin(dest, pos, modulusBytes);
        return dest;
    }

    public static byte[] getFingerprintSHA256(PublicKey publicKey) {
        byte[] blob = getBin(publicKey);
        MessageDigest sha1 = null;
        try {
            sha1 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
        return sha1.digest(blob);
    }

    public static byte[] getFingerprintSHA256(PrivateKey _privateKey) {
        RSAPrivateKey privateKey = (RSAPrivateKey)_privateKey;
        RSAPublicKey publicKey = getPublicKey(privateKey);
        return getFingerprintSHA256(publicKey);
    }

    public static String getFingerprintSHA256Base64(PublicKey publicKey) {
        byte[] b = getFingerprintSHA256(publicKey);
        return Base64.encodeToString(b, Base64.NO_PADDING|Base64.NO_WRAP);
    }

    public static String getFingerprintSHA256Base64(PrivateKey _privateKey) {
        RSAPrivateKey privateKey = (RSAPrivateKey)_privateKey;
        RSAPublicKey publicKey = getPublicKey(privateKey);
        return getFingerprintSHA256Base64(publicKey);
    }

    public static KeyPair generateKeyPair() {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        return keyPair;
    }
}
