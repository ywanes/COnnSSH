import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import java.security.spec.*;

public class ECDH521 {
  static final int PROPOSAL_ENC_ALGS_CTOS=2;
  static final int PROPOSAL_ENC_ALGS_STOC=3;
  static final int PROPOSAL_MAC_ALGS_CTOS=4;
  static final int PROPOSAL_MAC_ALGS_STOC=5;
  static final int PROPOSAL_COMP_ALGS_CTOS=6;
  static final int PROPOSAL_COMP_ALGS_STOC=7;
  static final int PROPOSAL_MAX=10;
  public static final int STATE_END=0;
  protected Session session=null;
  protected java.security.MessageDigest sha512=null;
  protected byte[] K=null;
  protected byte[] H=null;
  protected byte[] K_S=null;
  protected final int RSA=0;
  protected final int DSS=1;
  protected final int ECDSA=2;
  private int type=0;
  private String key_alg_name = "";
  private static final int SSH_MSG_KEX_ECDH_INIT = 30;
  private static final int SSH_MSG_KEX_ECDH_REPLY = 31;
  private int state;
  byte[] Q_C;
  byte[] V_S;
  byte[] V_C;
  byte[] I_S;
  byte[] I_C;
  private Buffer buf;
  private Packet packet;
  private KeyExchangeECDH ecdh;
  protected String sha_name="sha-512";
  protected int key_size=521;
  
  public void init(Session session, byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception{
    this.session=session;
    this.V_S=V_S;      
    this.V_C=V_C;      
    this.I_S=I_S;      
    this.I_C=I_C;      
    try{
      sha512=java.security.MessageDigest.getInstance("SHA-512");
    }catch(Exception e){
      AConfig.DebugPrintException("ex_89");  
      System.err.println(e);
    }
    buf=new Buffer();
    packet=new Packet(buf);
    packet.reset();
    buf.putByte((byte)SSH_MSG_KEX_ECDH_INIT);
    try{
      ecdh=new KeyExchangeECDH();
      ecdh.init(key_size);
      Q_C = ecdh.getQ();
      buf.putString(Q_C);
    }
    catch(Exception e){
      AConfig.DebugPrintException("ex_90");
      if(e instanceof Throwable)
        throw new ExceptionC(e.toString(), (Throwable)e);
      throw new ExceptionC(e.toString());
    }
    if(V_S==null)
      return;
    session.write(packet);
    state=SSH_MSG_KEX_ECDH_REPLY;
  }
  public String getKeyType() {
    if(type==DSS) return "DSA";
    if(type==RSA) return "RSA";
    return "ECDSA";
  }
  public String getKeyAlgorithName() {
    return key_alg_name;
  }
  protected static String[] guess(byte[]I_S, byte[]I_C){
    String[] guess=new String[PROPOSAL_MAX];
    Buffer sb=new Buffer(I_S); sb.setOffSet(17);
    Buffer cb=new Buffer(I_C); cb.setOffSet(17);
    for(int i=0; i<PROPOSAL_MAX; i++){
      byte[] sp=sb.getString();
      byte[] cp=cb.getString();
      int j=0;
      int k=0;
      label_break:
      while(j<cp.length){
	while(j<cp.length && cp[j]!=',')j++; 
	if(k==j) return null;
	String algorithm=byte2str(cp, k, j-k);
	int l=0;
	int m=0;
	while(l<sp.length){
	  while(l<sp.length && sp[l]!=',')l++; 
	  if(m==l) 
            return null;
	  if(algorithm.equals(byte2str(sp, m, l-m))){
	    guess[i]=algorithm;
	    break label_break;
	  }
	  l++;
	  m=l;
	}	
	j++;
	k=j;
      }
      if(j==0){
	guess[i]="";
      }
      else if(guess[i]==null){
	return null;
      }
    }
    return guess;
  }
  
  byte[] getK(){ return K; }
  byte[] getH(){ return H; }
  java.security.MessageDigest getHash(){ return sha512; }
  byte[] getHostKey(){ return K_S; }
  protected byte[] normalize(byte[] secret) {
    if(secret.length > 1 && secret[0] == 0 && (secret[1]&0x80) == 0) {
      byte[] tmp=new byte[secret.length-1];
      System.arraycopy(secret, 1, tmp, 0, tmp.length);
      return normalize(tmp);
    }else
      return secret;
  }
  // verificação opcional de segurança!
  protected boolean verify(String alg, byte[] K_S, int index, byte[] sig_of_H) throws Exception {
    int i,j;
    i=index;
    boolean result=false;
    if(alg.equals("ssh-rsa")){
      byte[] tmp;
      byte[] ee;
      byte[] n;
      type=RSA;
      key_alg_name=alg;
      j=((K_S[i++]<<24)&0xff000000)|((K_S[i++]<<16)&0x00ff0000)|((K_S[i++]<<8)&0x0000ff00)|((K_S[i++])&0x000000ff);
      tmp=new byte[j]; System.arraycopy(K_S, i, tmp, 0, j); i+=j;
      ee=tmp;
      j=((K_S[i++]<<24)&0xff000000)|((K_S[i++]<<16)&0x00ff0000)|((K_S[i++]<<8)&0x0000ff00)|((K_S[i++])&0x000000ff);
      tmp=new byte[j]; System.arraycopy(K_S, i, tmp, 0, j); 
      n=tmp;
      
      Signature signature=Signature.getInstance("SHA1withRSA");
      KeyFactory keyFactory=KeyFactory.getInstance("RSA");
      RSAPublicKeySpec rsaPubKeySpec = new RSAPublicKeySpec(new BigInteger(n),new BigInteger(ee));
      PublicKey pubKey2=keyFactory.generatePublic(rsaPubKeySpec);
      signature.initVerify(pubKey2);
      signature.update(H);
      int i_RSA=0;
      int j_RSA=0;
      byte[] tmp_RSA;
      Buffer buf_RSA=new Buffer(sig_of_H);
      if(new String(buf_RSA.getString()).equals("ssh-rsa")){
        j_RSA=buf_RSA.getInt();
        i_RSA=buf_RSA.getOffSet();
        tmp_RSA=new byte[j_RSA];
        System.arraycopy(sig_of_H, i_RSA, tmp_RSA, 0, j_RSA); 
        sig_of_H=tmp_RSA;
      }
      result=signature.verify(sig_of_H);      
    }else
      System.err.println("unknown alg");
    return result;
  }

  public boolean next(Buffer _buf) throws Exception{
    int i,j;
    switch(state){
    case SSH_MSG_KEX_ECDH_REPLY:
      j=_buf.getInt();
      j=_buf.getByte();
      j=_buf.getByte();
      if(j!=31){
	System.err.println("type: must be 31 "+j);
	return false;
      }
      K_S=_buf.getString();
      byte[] Q_S=_buf.getString();
      byte[][] r_s = fromPoint(Q_S);
      if(!ecdh.validate(r_s[0], r_s[1]))
	return false;
      K = ecdh.getSecret(r_s[0], r_s[1]);
      K=normalize(K);
      byte[] sig_of_H=_buf.getString();
      buf.reset();
      buf.putString(V_C); buf.putString(V_S);
      buf.putString(I_C); buf.putString(I_S);
      buf.putString(K_S);
      buf.putString(Q_C); buf.putString(Q_S);
      buf.putMPInt(K);
      byte[] foo=new byte[buf.getLength()];
      buf.getByte(foo, 0, foo.length);
      sha512.update(foo, 0, foo.length);
      H=sha512.digest();
      i=0;
      j=((K_S[i++]<<24)&0xff000000)|((K_S[i++]<<16)&0x00ff0000)|
	((K_S[i++]<<8)&0x0000ff00)|((K_S[i++])&0x000000ff);
      String alg=byte2str(K_S, i, j);
      i+=j;
      boolean result = verify(alg, K_S, i, sig_of_H);
      state=STATE_END;
      return result;
    }
    return false;
  }

  static byte[][] fromPoint(byte[] point) {
    int i = 0;
    while(point[i]!=4) i++;
    i++;
    byte[][] tmp = new byte[2][];
    byte[] r_array = new byte[(point.length-i)/2];
    byte[] s_array = new byte[(point.length-i)/2];
    System.arraycopy(point, i, r_array, 0, r_array.length);
    System.arraycopy(point, i+r_array.length, s_array, 0, s_array.length);
    tmp[0] = r_array;
    tmp[1] = s_array;
    return tmp;
  }
  
  public int getState(){return state; }
  
  class KeyExchangeECDH{
      byte[] Q_array;
      java.security.interfaces.ECPublicKey publicKey;
      private KeyAgreement myKeyAgree;
      public void init(int size) throws Exception{
        myKeyAgree = KeyAgreement.getInstance("ECDH");
        ECDSA kpair = new ECDSA();
        kpair.init(size);
        publicKey = kpair.getPublicKey();
        byte[] r = kpair.getR();
        byte[] s = kpair.getS();
        Q_array = toPoint(r, s);
        myKeyAgree.init(kpair.getPrivateKey());
      }
      public byte[] getQ() throws Exception{
        return Q_array;
      }
      public byte[] getSecret(byte[] r, byte[] s) throws Exception{
        KeyFactory kf = KeyFactory.getInstance("EC");
        ECPoint w = new ECPoint(new BigInteger(1, r), new BigInteger(1, s));
        ECPublicKeySpec spec = new ECPublicKeySpec(w, publicKey.getParams());
        PublicKey theirPublicKey = kf.generatePublic(spec);
        myKeyAgree.doPhase(theirPublicKey, true);
        return myKeyAgree.generateSecret();
      }
      private BigInteger two = BigInteger.ONE.add(BigInteger.ONE);
      private BigInteger three = two.add(BigInteger.ONE);
      public boolean validate(byte[] r, byte[] s) throws Exception{
        BigInteger x = new BigInteger(1, r);
        BigInteger y = new BigInteger(1, s);
        ECPoint w = new ECPoint(x, y);
        if(w.equals(ECPoint.POINT_INFINITY))
          return false;
        ECParameterSpec params = publicKey.getParams();
        EllipticCurve curve = params.getCurve();
        BigInteger p=((ECFieldFp)curve.getField()).getP();
        BigInteger p_sub1=p.subtract(BigInteger.ONE);
        if(!(x.compareTo(p_sub1)<=0 && y.compareTo(p_sub1)<=0))
          return false;
        BigInteger tmp=x.multiply(curve.getA()).add(curve.getB()).add(x.modPow(three, p)).mod(p);
        BigInteger y_2=y.modPow(two, p);
        if(!(y_2.equals(tmp)))
          return false;
        return true;
      }
      private byte[] toPoint(byte[] r_array, byte[] s_array) {
        byte[] tmp = new byte[1+r_array.length+s_array.length];
        tmp[0]=0x04;
        System.arraycopy(r_array, 0, tmp, 1, r_array.length);
        System.arraycopy(s_array, 0, tmp, 1+r_array.length, s_array.length);
        return tmp;
      }
      private byte[] insert0(byte[] buf){
        if ((buf[0] & 0x80) == 0) return buf;
        byte[] tmp = new byte[buf.length+1];
        System.arraycopy(buf, 0, tmp, 1, buf.length);
        bzero(buf);
        return tmp;
      }
      private byte[] chop0(byte[] buf){
        if(buf[0]!=0) return buf;
        byte[] tmp = new byte[buf.length-1];
        System.arraycopy(buf, 1, tmp, 0, tmp.length);
        bzero(buf);
        return tmp;
      }
      private void bzero(byte[] buf){
        for(int i = 0; i<buf.length; i++) buf[i]=0;
      }
      

    class ECDSA{
      byte[] d;
      byte[] r;
      byte[] s;
      java.security.interfaces.ECPublicKey pubKey;
      java.security.interfaces.ECPrivateKey prvKey;
      ECParameterSpec params;
      public void init(int key_size) throws Exception {
        String name=null;
        if(key_size==256) name="secp256r1";
        else if(key_size==384) name="secp384r1";
        else if(key_size==521) name="secp521r1";
        else 
          throw new ExceptionC("unsupported key size: "+key_size);
        for(int i = 0; i<1000; i++){
          java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
          ECGenParameterSpec ecsp = new ECGenParameterSpec(name);
          kpg.initialize(ecsp);
          java.security.KeyPair kp = kpg.genKeyPair();
          prvKey = (java.security.interfaces.ECPrivateKey)kp.getPrivate();
          pubKey = (java.security.interfaces.ECPublicKey)kp.getPublic();
          params=pubKey.getParams();
          d=((java.security.interfaces.ECPrivateKey)prvKey).getS().toByteArray();
          ECPoint w = pubKey.getW();
          r = w.getAffineX().toByteArray();
          s = w.getAffineY().toByteArray();
          if(r.length!=s.length) 
            continue;
          if(key_size==256 && r.length==32) 
            break;
          if(key_size==384 && r.length==48) 
            break;
          if(key_size==521 && r.length==66) 
            break;
        }
        if(d.length<r.length)
          d=insert0(d);
      }
      public byte[] getD(){return d;}
      public byte[] getR(){return r;}
      public byte[] getS(){return s;}
      java.security.interfaces.ECPublicKey getPublicKey(){ return pubKey; }
      java.security.interfaces.ECPrivateKey getPrivateKey(){ return prvKey; }

      private byte[] insert0(byte[] buf){
        byte[] tmp = new byte[buf.length+1];
        System.arraycopy(buf, 0, tmp, 1, buf.length);
        bzero(buf);
        return tmp;
      }
      private byte[] chop0(byte[] buf){
        if(buf[0]!=0 || (buf[1]&0x80)==0) return buf;
        byte[] tmp = new byte[buf.length-1];
        System.arraycopy(buf, 1, tmp, 0, tmp.length);
        bzero(buf);
        return tmp;
      }
      private void bzero(byte[] buf){
        for(int i = 0; i<buf.length; i++) buf[i]=0;
      }
    }
      
  }
  
  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static String byte2str(byte[] str){return byte2str(str, 0, str.length, "UTF-8");}
  static String byte2str(byte[] str, int s, int l){return byte2str(str, s, l, "UTF-8");}  
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}
