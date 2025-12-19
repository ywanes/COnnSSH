class ECDH{    
    public byte[] K, H, Q_C;        
    private byte[] V_S, V_C, I_S, I_C;
    public java.security.MessageDigest sha = null;        
    private java.security.spec.ECParameterSpec params=null;
    private javax.crypto.KeyAgreement myKeyAgree = null;    

    public void init(byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception{
        this.V_S = V_S;
        this.V_C = V_C;
        this.I_S = I_S;
        this.I_C = I_C;        
        sha = java.security.MessageDigest.getInstance("SHA-256");
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        java.security.KeyPair kp = kpg.genKeyPair();
        java.security.PrivateKey privateKey = kp.getPrivate();
        java.security.interfaces.ECPublicKey publicKey = (java.security.interfaces.ECPublicKey) kp.getPublic();            
        params = publicKey.getParams();
        java.security.spec.ECPoint w = publicKey.getW();
        java.math.BigInteger x = w.getAffineX();
        java.math.BigInteger y = w.getAffineY();
        byte[] xBytes = toPaddedBytes(x, 32);
        byte[] yBytes = toPaddedBytes(y, 32);
        Q_C = new byte[1 + xBytes.length + yBytes.length];
        Q_C[0] = 4; // Formato não compactado
        System.arraycopy(xBytes, 0, Q_C, 1, xBytes.length);
        System.arraycopy(yBytes, 0, Q_C, 1 + xBytes.length, yBytes.length);
        myKeyAgree = javax.crypto.KeyAgreement.getInstance("ECDH");
        myKeyAgree.init(privateKey);            
    }

    private byte[] toPaddedBytes(java.math.BigInteger bi, int length) {
        byte[] bytes = bi.toByteArray();
        if (bytes.length == length) {
            return bytes;
        } else if (bytes.length > length) {
            if (bytes[0] == 0 && bytes.length == length + 1) {
                byte[] result = new byte[length];
                System.arraycopy(bytes, 1, result, 0, length);
                return result;
            }
        } else if (bytes.length < length) {
            byte[] result = new byte[length];
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
            return result;
        }
        return bytes;
    }
    
    public void next(Buf buf) throws Exception {
        buf.add_i_get(6);
        byte[] K_S = buf.getValue();
        byte[] Q_S = buf.getValue();
        if (Q_S[0] != 4)
            throw new Exception("Formato de ponto EC não suportado: " + Q_S[0]);
        int coordinateLength = 32;
        if (Q_S.length != 1 + coordinateLength * 2)
            coordinateLength = (Q_S.length - 1) / 2;
        byte[] xBytes = new byte[coordinateLength];
        byte[] yBytes = new byte[coordinateLength];
        System.arraycopy(Q_S, 1, xBytes, 0, coordinateLength);
        System.arraycopy(Q_S, 1 + coordinateLength, yBytes, 0, coordinateLength);
        java.math.BigInteger x = new java.math.BigInteger(1, xBytes);
        java.math.BigInteger y = new java.math.BigInteger(1, yBytes);
        myKeyAgree.doPhase(
            java.security.KeyFactory.getInstance("EC").generatePublic(
                new java.security.spec.ECPublicKeySpec(
                    new java.security.spec.ECPoint(x, y), 
                    params
                )
            ), 
            true
        );
        K = myKeyAgree.generateSecret();
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
    }    
}