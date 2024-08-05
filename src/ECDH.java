import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.KeyAgreement;


// ConfigECDH256 and ConfigECDH512 -> OK
//class Config extends ConfigECDH256{}
class Config extends ConfigECDH512{}


class ConfigECDH256{
    String digest = "SHA-256";
    public static int key_size = 256;    
    public static int nn_cipher=32;
    boolean skip_verify=true;
}

class ConfigECDH512{
    String digest = "SHA-512";
    public static int key_size = 521;    
    public static int nn_cipher=64;
    boolean skip_verify=false;
}

class ECDH extends Config{    
    public static String cipher = "ecdh-sha2-nistp" + key_size;
    public static String groupCipher = "ssh-rsa,ecdsa-sha2-nistp" + key_size;    
    java.security.MessageDigest sha = null;        
    String _ecsp = "secp" + key_size + "r1";

    static final int PROPOSAL_MAX = 10;
    protected byte[] K = null;
    protected byte[] H = null;
    protected byte[] K_S = null;
    protected final int RSA = 0;
    protected final int DSS = 1;
    protected final int ECDSA = 2;
    private static final int SSH_MSG_KEX_ECDH_INIT = 30;
    private static final int SSH_MSG_KEX_ECDH_REPLY = 31;
    private int state;
    byte[] Q_C;
    byte[] V_S;
    byte[] V_C;
    byte[] I_S;
    byte[] I_C;
    Buf buf=null;
    private DiffieHellmanECDH ecdh;
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
            ecdh = new DiffieHellmanECDH(_ecsp);
            Q_C = ecdh.Q_array;
            buf.putValue(Q_C);
        } catch (Exception e) {
            throw new Exception("Error ECDH " + e.toString());
        }
        state = SSH_MSG_KEX_ECDH_REPLY;
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
    // verificação opcional de segurança!
    protected boolean verify(byte[] K_S, byte[] sig_of_H) throws Exception {
        int i = 0;
        int j = ((K_S[i++] << 24) & 0xff000000) | ((K_S[i++] << 16) & 0x00ff0000) |
            ((K_S[i++] << 8) & 0x0000ff00) | ((K_S[i++]) & 0x000000ff);
        String alg = new String(K_S, i, j, "UTF-8");
        i += j;
        
        if ( skip_verify )
            return true;
        if (!alg.equals("ssh-rsa"))
            throw new Exception("unknown alg");
        byte[] tmp;
        byte[] ee;
        byte[] n;
        j = ((K_S[i++] << 24) & 0xff000000) | ((K_S[i++] << 16) & 0x00ff0000) | ((K_S[i++] << 8) & 0x0000ff00) | ((K_S[i++]) & 0x000000ff);
        tmp = new byte[j];
        System.arraycopy(K_S, i, tmp, 0, j);
        i += j;
        ee = tmp;
        j = ((K_S[i++] << 24) & 0xff000000) | ((K_S[i++] << 16) & 0x00ff0000) | ((K_S[i++] << 8) & 0x0000ff00) | ((K_S[i++]) & 0x000000ff);
        tmp = new byte[j];
        System.arraycopy(K_S, i, tmp, 0, j);
        n = tmp;

        Signature signature = Signature.getInstance("SHA1withRSA");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec rsaPubKeySpec = new RSAPublicKeySpec(new BigInteger(n), new BigInteger(ee));
        PublicKey _pubKey = keyFactory.generatePublic(rsaPubKeySpec);
        signature.initVerify(_pubKey);
        signature.update(H);
        byte[] tmp_RSA;
        Buf buf_RSA = new Buf(sig_of_H);
        if (new String(buf_RSA.getValue()).equals("ssh-rsa")) {
            int j_RSA = buf_RSA.getInt();
            int i_RSA = buf_RSA.get_get();
            tmp_RSA = new byte[j_RSA];
            System.arraycopy(sig_of_H, i_RSA, tmp_RSA, 0, j_RSA);
            sig_of_H = tmp_RSA;
        }
        return signature.verify(sig_of_H);
    }

    public boolean next(Buf _buf) throws Exception {
        if ( state == SSH_MSG_KEX_ECDH_REPLY ){
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
            ECPoint w = new ECPoint(x, y);
            if ( w.equals(ECPoint.POINT_INFINITY) )
                return false;
            ECParameterSpec params = ecdh.publicKey.getParams();
            EllipticCurve curve = params.getCurve();
            BigInteger p = ((ECFieldFp) curve.getField()).getP();
            BigInteger p_sub1 = p.subtract(BigInteger.ONE);
            if ( x.compareTo(p_sub1) > 0 || y.compareTo(p_sub1) > 0 )
                return false;
            BigInteger tmp3 = x.multiply(curve.getA()).add(curve.getB()).add(x.modPow(three, p)).mod(p);
            BigInteger tmp4 = y.modPow(two, p);
            if ( !tmp3.equals(tmp4) )
                return false;
            K = ecdh.getSecret(r_array, s_array);
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
            return verify(K_S, sig_of_H);
        }
        return false;
    }

    public int getState() {
        return state;
    }
}

class DiffieHellmanECDH {
    byte[] Q_array;
    java.security.interfaces.ECPrivateKey privateKey = null;
    java.security.interfaces.ECPublicKey publicKey = null;
    private KeyAgreement myKeyAgree = null;
    DiffieHellmanECDH(String ecsp) throws Exception {
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec _ecsp = new ECGenParameterSpec(ecsp);
        kpg.initialize(_ecsp);
        java.security.KeyPair kp = kpg.genKeyPair();
        privateKey = (java.security.interfaces.ECPrivateKey) kp.getPrivate();
        publicKey = (java.security.interfaces.ECPublicKey) kp.getPublic();        
        ECPoint w = publicKey.getW();
        byte[] r = w.getAffineX().toByteArray();
        byte[] s = w.getAffineY().toByteArray();
        Q_array = new byte[1 + r.length + s.length];
        Q_array[0] = 0x04;
        System.arraycopy(r, 0, Q_array, 1, r.length);
        System.arraycopy(s, 0, Q_array, 1 + r.length, s.length);            
        myKeyAgree = KeyAgreement.getInstance("ECDH");
        myKeyAgree.init(privateKey);
    }
    public byte[] getSecret(byte[] r, byte[] s) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        ECPoint point = new ECPoint(new BigInteger(1, r), new BigInteger(1, s));
        ECPublicKeySpec spec = new ECPublicKeySpec(point, publicKey.getParams());
        PublicKey theirPublicKey = kf.generatePublic(spec);
        myKeyAgree.doPhase(theirPublicKey, true);
        return myKeyAgree.generateSecret();
    }
}   