import java.math.BigInteger;

// ConfigECDH256 and ConfigECDH512 -> OK
//class Config extends ConfigECDH256{}
class Config extends ConfigECDH512{}

class ConfigECDH256{
    String digest = "SHA-256";
    public static int key_size = 256;    
    public static int nn_cipher=32;
    boolean need_verification=false;
}

class ConfigECDH512{
    String digest = "SHA-512";
    public static int key_size = 521;    
    public static int nn_cipher=64;
    boolean can_verification=true;
}

class ECDH extends Config{    
    public static String cipher = "ecdh-sha2-nistp" + key_size;
    public static String groupCipher = "ssh-rsa,ecdsa-sha2-nistp" + key_size;    
    java.security.MessageDigest sha = null;        
    String _ecsp = "secp" + key_size + "r1";

    private byte[] K = null;
    private byte[] H = null;
    private byte[] K_S = null;
    private static final int SSH_MSG_KEX_ECDH_INIT = 30;
    private static final int SSH_MSG_KEX_ECDH_REPLY = 31;
    private int state;    
    byte[] V_S;
    byte[] V_C;
    byte[] I_S;
    byte[] I_C;
    byte[] Q_C;
    Buf buf=null;    
    java.security.interfaces.ECPrivateKey privateKey = null;
    java.security.interfaces.ECPublicKey publicKey = null;
    javax.crypto.KeyAgreement myKeyAgree = null;    
    public BigInteger two = BigInteger.ONE.add(BigInteger.ONE);
    public BigInteger three = two.add(BigInteger.ONE);

    ECDH(byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception{
        this.V_S = V_S;
        this.V_C = V_C;
        this.I_S = I_S;
        this.I_C = I_C;
        sha = java.security.MessageDigest.getInstance(digest);
        buf = new Buf();
        buf.reset_packet();
        buf.putByte((byte) SSH_MSG_KEX_ECDH_INIT);
        try{           
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
            java.security.spec.ECGenParameterSpec ecsp = new java.security.spec.ECGenParameterSpec(_ecsp);
            kpg.initialize(ecsp);
            java.security.KeyPair kp = kpg.genKeyPair();
            privateKey = (java.security.interfaces.ECPrivateKey) kp.getPrivate();
            publicKey = (java.security.interfaces.ECPublicKey) kp.getPublic();        
            java.security.spec.ECPoint w = publicKey.getW();
            byte[] r = w.getAffineX().toByteArray();
            byte[] s = w.getAffineY().toByteArray();
            Q_C = new byte[1 + r.length + s.length];
            Q_C[0] = 0x04;
            System.arraycopy(r, 0, Q_C, 1, r.length);
            System.arraycopy(s, 0, Q_C, 1 + r.length, s.length);            
            myKeyAgree = javax.crypto.KeyAgreement.getInstance("ECDH");
            myKeyAgree.init(privateKey);            
            buf.putValue(Q_C);
        } catch (Exception e) {
            throw new Exception("Error ECDH " + e.toString());
        }
        state = SSH_MSG_KEX_ECDH_REPLY;
    }

    public boolean next(Buf _buf) throws Exception {
        if ( state != SSH_MSG_KEX_ECDH_REPLY )
            return false;
        _buf.getInt();
        _buf.getByte();
        int j = _buf.getByte();
        if (j != 31) {
            System.err.println("type: must be 31 " + j);
            return false;
        }
        K_S = _buf.getValue();
        byte[] Q_S = _buf.getValue();
        int i = 0;
        while (Q_S[i] != 4)
            i++;
        i++;
        byte[] r_array = new byte[(Q_S.length - i) / 2];
        byte[] s_array = new byte[(Q_S.length - i) / 2];
        System.arraycopy(Q_S, i, r_array, 0, r_array.length);
        System.arraycopy(Q_S, i + r_array.length, s_array, 0, s_array.length);
        BigInteger x = new BigInteger(1, r_array);
        BigInteger y = new BigInteger(1, s_array);
        java.security.spec.ECPoint w = new java.security.spec.ECPoint(x, y);
        if ( w.equals(java.security.spec.ECPoint.POINT_INFINITY) )
            return false;
        java.security.spec.ECParameterSpec params = publicKey.getParams();
        java.security.spec.EllipticCurve curve = params.getCurve();
        BigInteger p = ((java.security.spec.ECFieldFp) curve.getField()).getP();
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC");
        java.security.spec.ECPoint point = new java.security.spec.ECPoint(new BigInteger(1, r_array), new BigInteger(1, s_array));
        java.security.spec.ECPublicKeySpec spec = new java.security.spec.ECPublicKeySpec(point, publicKey.getParams());
        java.security.PublicKey theirPublicKey = kf.generatePublic(spec);
        myKeyAgree.doPhase(theirPublicKey, true);
        K = myKeyAgree.generateSecret();
        while(K.length > 1 && K[0] == 0 && (K[1] & 0x80) == 0){
            byte[] tmp = new byte[K.length - 1];
            System.arraycopy(K, 1, tmp, 0, tmp.length);
            K=tmp;
        }            
        byte[] sig_of_H = _buf.getValue();
        buf.reset();
        buf.putValue(V_C);
        buf.putValue(V_S);
        buf.putValue(I_C);
        buf.putValue(I_S);
        buf.putValue(K_S);
        buf.putValue(Q_C);
        buf.putValue(Q_S);
        buf.putValue(K);
        byte[] a = buf.getValueAllLen();
        sha.update(a);
        H = sha.digest();
        state = 0;        
        i = 0;
        j = ((K_S[i++] << 24) & 0xff000000) | ((K_S[i++] << 16) & 0x00ff0000) |
            ((K_S[i++] << 8) & 0x0000ff00) | ((K_S[i++]) & 0x000000ff);        
        if (!new String(K_S, i, j, "UTF-8").equals("ssh-rsa"))
            throw new Exception("unknown alg");
        if ( can_verification ){            
            i += j;
            byte[] tmp;
            byte[] ee;
            j = ((K_S[i++] << 24) & 0xff000000) | ((K_S[i++] << 16) & 0x00ff0000) | ((K_S[i++] << 8) & 0x0000ff00) | ((K_S[i++]) & 0x000000ff);
            tmp = new byte[j];
            System.arraycopy(K_S, i, tmp, 0, j);
            i += j;
            ee = tmp;
            j = ((K_S[i++] << 24) & 0xff000000) | ((K_S[i++] << 16) & 0x00ff0000) | ((K_S[i++] << 8) & 0x0000ff00) | ((K_S[i++]) & 0x000000ff);
            tmp = new byte[j];
            System.arraycopy(K_S, i, tmp, 0, j);
            java.security.Signature signature = java.security.Signature.getInstance("SHA1withRSA");
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            java.security.spec.RSAPublicKeySpec rsaPubKeySpec = new java.security.spec.RSAPublicKeySpec(new BigInteger(tmp), new BigInteger(ee));
            java.security.PublicKey _publicKey = keyFactory.generatePublic(rsaPubKeySpec);
            signature.initVerify(_publicKey);
            signature.update(H);        
            Buf buf_RSA = new Buf(sig_of_H);
            if (new String(buf_RSA.getValue()).equals("ssh-rsa")) {
                byte[] tmp_RSA;
                int j_RSA = buf_RSA.getInt();
                int i_RSA = buf_RSA.get_get();
                tmp_RSA = new byte[j_RSA];
                System.arraycopy(sig_of_H, i_RSA, tmp_RSA, 0, j_RSA);
                sig_of_H = tmp_RSA;
            }
            return signature.verify(sig_of_H);  
        }
        return true;
    }
    byte[] getK() {
        return K;
    }
    byte[] getH() {
        return H;
    }
    java.security.MessageDigest getHash() {
        return sha;
    }
    public int getState() {
        return state;
    }
}  