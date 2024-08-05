import java.math.BigInteger;
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

    ECDH(byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception{
        if ( guess(I_S, I_C) == null )
            throw new Exception("Algorithm negotiation fail");        
        this.V_S = V_S;
        this.V_C = V_C;
        this.I_S = I_S;
        this.I_C = I_C;
        sha = java.security.MessageDigest.getInstance(digest);
        buf = new Buf();
        buf.reset_packet();
        buf.putByte((byte) SSH_MSG_KEX_ECDH_INIT);
        try {
            ecdh = new DiffieHellmanECDH(_ecsp, key_size);
            Q_C = ecdh.getQ();
            buf.putValue(Q_C);
        } catch (Exception e) {
            throw new Exception("Error ECDH " + e.toString());
        }
        state = SSH_MSG_KEX_ECDH_REPLY;
    }
    protected String[] guess(byte[] I_S, byte[] I_C) {
        String[] guess = new String[PROPOSAL_MAX];
        Buf sb = new Buf(I_S);
        sb.set_get(17);
        Buf cb = new Buf(I_C);
        cb.set_get(17);
        for (int i = 0; i < PROPOSAL_MAX; i++) {
            byte[] sp = sb.getValue();
            byte[] cp = cb.getValue();
            int j = 0;
            int k = 0;
            label_break:
                while (j < cp.length) {
                    while (j < cp.length && cp[j] != ',')
                        j++;
                    if (k == j) return null;
                    String algorithm = byte2str(cp, k, j - k, "UTF-8");
                    int l = 0;
                    int m = 0;
                    while (l < sp.length){
                        while (l < sp.length && sp[l] != ',')
                            l++;
                        if (m == l)
                            return null;
                        if (algorithm.equals(byte2str(sp, m, l - m, "UTF-8"))) {
                            guess[i] = algorithm;
                            break label_break;
                        }
                        l++;
                        m = l;
                    }
                    j++;
                    k = j;
                }
            if (j == 0) {
                guess[i] = "";
            }else if (guess[i] == null) {
                return null;
            }
        }
        return guess;
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
    protected byte[] normalize(byte[] secret) {
        if (secret.length > 1 && secret[0] == 0 && (secret[1] & 0x80) == 0) {
            byte[] tmp = new byte[secret.length - 1];
            System.arraycopy(secret, 1, tmp, 0, tmp.length);
            return normalize(tmp);
        } else
            return secret;
    }
    // verificação opcional de segurança!
    protected boolean verify(byte[] K_S, byte[] sig_of_H) throws Exception {
        int i = 0;
        int j = ((K_S[i++] << 24) & 0xff000000) | ((K_S[i++] << 16) & 0x00ff0000) |
            ((K_S[i++] << 8) & 0x0000ff00) | ((K_S[i++]) & 0x000000ff);
        String alg = byte2str(K_S, i, j, "UTF-8");
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
        int j;
        if ( state == SSH_MSG_KEX_ECDH_REPLY ){
            _buf.getInt();
            _buf.getByte();
            j = _buf.getByte();
            if (j != 31) {
                System.err.println("type: must be 31 " + j);
                return false;
            }
            K_S = _buf.getValue();
            byte[] Q_S = _buf.getValue();
            byte[][] r_s = fromPoint(Q_S);
            if (!ecdh.validate(r_s[0], r_s[1]))
                return false;
            K = ecdh.getSecret(r_s[0], r_s[1]);
            K = normalize(K);
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

    static byte[][] fromPoint(byte[] point) {
        int i = 0;
        while (point[i] != 4)
            i++;
        i++;
        byte[][] tmp = new byte[2][];
        byte[] r_array = new byte[(point.length - i) / 2];
        byte[] s_array = new byte[(point.length - i) / 2];
        System.arraycopy(point, i, r_array, 0, r_array.length);
        System.arraycopy(point, i + r_array.length, s_array, 0, s_array.length);
        tmp[0] = r_array;
        tmp[1] = s_array;
        return tmp;
    }

    public int getState() {
        return state;
    }

    String byte2str(byte[] str, int s, int l, String encoding) {
        try {
            return new String(str, s, l, encoding);
        } catch (java.io.UnsupportedEncodingException e) {
            System.err.println(".Util UnsupportedEncodingException " + e);
            return new String(str, s, l);
        }
    }
}

class DiffieHellmanECDH {
    byte[] Q_array;
    java.security.interfaces.ECPublicKey publicKey;
    private KeyAgreement myKeyAgree;
    String _ecsp=null;
    DiffieHellmanECDH(String _ecsp, int size) throws Exception {
        this._ecsp=_ecsp;
        myKeyAgree = KeyAgreement.getInstance("ECDH");
        ECDSA kpair = new ECDSA(_ecsp);
        kpair.init(size);
        publicKey = kpair.getPublicKey();
        Q_array = toPoint(kpair.getR(), kpair.getS());
        myKeyAgree.init(kpair.getPrivateKey());
    }
    public byte[] getQ() throws Exception {
        return Q_array;
    }
    public byte[] getSecret(byte[] r, byte[] s) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        ECPoint w = new ECPoint(new BigInteger(1, r), new BigInteger(1, s));
        ECPublicKeySpec spec = new ECPublicKeySpec(w, publicKey.getParams());
        PublicKey theirPublicKey = kf.generatePublic(spec);
        myKeyAgree.doPhase(theirPublicKey, true);
        return myKeyAgree.generateSecret();
    }
    private BigInteger two = BigInteger.ONE.add(BigInteger.ONE);
    private BigInteger three = two.add(BigInteger.ONE);
    public boolean validate(byte[] r, byte[] s) throws Exception {
        BigInteger x = new BigInteger(1, r);
        BigInteger y = new BigInteger(1, s);
        ECPoint w = new ECPoint(x, y);
        if (w.equals(ECPoint.POINT_INFINITY))
            return false;
        ECParameterSpec params = publicKey.getParams();
        EllipticCurve curve = params.getCurve();
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        BigInteger p_sub1 = p.subtract(BigInteger.ONE);
        if (!(x.compareTo(p_sub1) <= 0 && y.compareTo(p_sub1) <= 0))
            return false;
        BigInteger tmp = x.multiply(curve.getA()).add(curve.getB()).add(x.modPow(three, p)).mod(p);
        BigInteger y_2 = y.modPow(two, p);
        if (!(y_2.equals(tmp)))
            return false;
        return true;
    }
    private byte[] toPoint(byte[] r_array, byte[] s_array) {
        byte[] tmp = new byte[1 + r_array.length + s_array.length];
        tmp[0] = 0x04;
        System.arraycopy(r_array, 0, tmp, 1, r_array.length);
        System.arraycopy(s_array, 0, tmp, 1 + r_array.length, s_array.length);
        return tmp;
    }        
}   

class ECDSA {
    byte[] r;
    byte[] s;
    java.security.interfaces.ECPublicKey pubKey;
    java.security.interfaces.ECPrivateKey prvKey;
    String _ecsp=null;
    public ECDSA(String _ecsp) {
        this._ecsp = _ecsp;
    }
    public void init(int key_size) throws Exception {
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecsp = new ECGenParameterSpec(_ecsp);
        kpg.initialize(ecsp);
        java.security.KeyPair kp = kpg.genKeyPair();
        prvKey = (java.security.interfaces.ECPrivateKey) kp.getPrivate();
        pubKey = (java.security.interfaces.ECPublicKey) kp.getPublic();
        ECPoint w = pubKey.getW();
        r = w.getAffineX().toByteArray();
        s = w.getAffineY().toByteArray();
    }
    public byte[] getR() {
        return r;
    }
    public byte[] getS() {
        return s;
    }
    java.security.interfaces.ECPublicKey getPublicKey() {
        return pubKey;
    }
    java.security.interfaces.ECPrivateKey getPrivateKey() {
        return prvKey;
    }
}