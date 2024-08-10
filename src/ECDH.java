
// ConfigECDH256 and ConfigECDH512 -> OK
//class Config extends ConfigECDH256{}
class Config extends ConfigECDH512{}

class ConfigECDH256{
    String digest = "SHA-256";
    public static int key_size = 256;    
    public static int nn_cipher=32;
    boolean can_verification=false;
}

class ConfigECDH512{
    String digest = "SHA-512";
    public static int key_size = 521;    
    public static int nn_cipher=64;
    boolean can_verification=true;
}

class ECDH extends Config{    
    java.security.MessageDigest sha = null;        
    String _ecsp = "secp" + key_size + "r1";

    private byte[] K = null;
    private byte[] H = null;
    private byte[] K_S = null;
    byte[] V_S;
    byte[] V_C;
    byte[] I_S;
    byte[] I_C;
    byte[] Q_C;    
    java.security.interfaces.ECPublicKey publicKey = null;
    javax.crypto.KeyAgreement myKeyAgree = null;    

    ECDH(byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception{
        this.V_S = V_S;
        this.V_C = V_C;
        this.I_S = I_S;
        this.I_C = I_C;
        sha = java.security.MessageDigest.getInstance(digest);
        try{     
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
            java.security.spec.ECGenParameterSpec ecsp = new java.security.spec.ECGenParameterSpec(_ecsp);
            kpg.initialize(ecsp);
            java.security.KeyPair kp = kpg.genKeyPair();
            java.security.PrivateKey privateKey = kp.getPrivate();
            publicKey = (java.security.interfaces.ECPublicKey) kp.getPublic();            
            java.security.spec.ECPoint w = publicKey.getW();            
            byte[] r = w.getAffineX().toByteArray();
            byte[] s = w.getAffineY().toByteArray();
            Q_C = new byte[1 + r.length + s.length];
            Q_C[0] = 4;
            System.arraycopy(r, 0, Q_C, 1, r.length);
            System.arraycopy(s, 0, Q_C, 1 + r.length, s.length);            
            myKeyAgree = javax.crypto.KeyAgreement.getInstance("ECDH");
            myKeyAgree.init(privateKey);            
        }catch(Exception e){
            throw new Exception("Error ECDH " + e.toString());
        }
    }

    public void next(Buf buf) throws Exception {
        buf.getInt();
        buf.getByte();
        buf.getByte();
        K_S = buf.getValue();
        byte[] Q_S = buf.getValue();
        byte[] r_array = new byte[(Q_S.length-1)/2];
        byte[] s_array = new byte[(Q_S.length-1)/2];
        System.arraycopy(Q_S, 1, r_array, 0, r_array.length);
        System.arraycopy(Q_S, 1 + r_array.length, s_array, 0, s_array.length);        
        java.security.spec.ECPoint point = new java.security.spec.ECPoint(new java.math.BigInteger( r_array), new java.math.BigInteger( s_array));        
        java.security.spec.ECPublicKeySpec spec = new java.security.spec.ECPublicKeySpec(point, publicKey.getParams());        
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC");
        java.security.PublicKey theirPublicKey = kf.generatePublic(spec);
        myKeyAgree.doPhase(theirPublicKey, true);
        K = myKeyAgree.generateSecret();
        while( K.length > 1 && K[0] == 0 && (K[1] & 0x80) == 0 ){
            byte[] tmp = new byte[K.length - 1];
            System.arraycopy(K, 1, tmp, 0, tmp.length);
            K=tmp;
        }            
        byte[] sig_of_H = buf.getValue();
        buf=new Buf();
        buf.putValue(V_C);
        buf.putValue(V_S);
        buf.putValue(I_C);
        buf.putValue(I_S);
        buf.putValue(K_S);
        buf.putValue(Q_C);
        buf.putValue(Q_S);
        buf.putValue(K);
        sha.update(buf.getValueAllLen());
        H = sha.digest();
        buf = new Buf(K_S);
        if (!new String(buf.getValue(), "UTF-8").equals("ssh-rsa"))
            throw new Exception("unknown alg");
        if ( can_verification ){            
            byte[] p2 = buf.getValue();
            byte[] p1 = buf.getValue();
            java.security.Signature signature = java.security.Signature.getInstance("SHA1withRSA");
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            java.security.spec.RSAPublicKeySpec rsaPubKeySpec = new java.security.spec.RSAPublicKeySpec(new java.math.BigInteger(p1), new java.math.BigInteger(p2));
            java.security.PublicKey _publicKey = keyFactory.generatePublic(rsaPubKeySpec);
            signature.initVerify(_publicKey);
            signature.update(H);        
            buf = new Buf(sig_of_H);
            if (!new String(buf.getValue()).equals("ssh-rsa"))
                throw new Exception("error ssh-rsa");
            if ( !signature.verify(buf.getValue()) )
                throw new Exception("signature.verify false");
        }
    }
    byte[] getK(){
        return K;
    }
    byte[] getH(){
        return H;
    }
    byte[] get_Q_C() {
        return Q_C;
    }
    java.security.MessageDigest getHash(){
        return sha;
    }
}  