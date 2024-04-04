import java.math.BigInteger;
import javax.crypto.*;
import javax.crypto.spec.*;

public class KeyExchangeDH{
  BigInteger p;
  BigInteger g;
  BigInteger e;  // my public key
  byte[] e_array;
  BigInteger f;  // your public key
  BigInteger K;  // shared secret key
  byte[] K_array;

  private java.security.KeyPairGenerator myKpairGen;
  private KeyAgreement myKeyAgree;
  public void init() throws Exception{
    myKpairGen=java.security.KeyPairGenerator.getInstance("DH");
    myKeyAgree=KeyAgreement.getInstance("DH");
  }
  public byte[] getE() throws Exception{
    if(e==null){
      DHParameterSpec dhSkipParamSpec=new DHParameterSpec(p, g);
      myKpairGen.initialize(dhSkipParamSpec);
      java.security.KeyPair myKpair=myKpairGen.generateKeyPair();
      myKeyAgree.init(myKpair.getPrivate());
      e=((javax.crypto.interfaces.DHPublicKey)(myKpair.getPublic())).getY();
      e_array=e.toByteArray();
    }
    return e_array;
  }
  public byte[] getK() throws Exception{
    if(K==null){
      java.security.KeyFactory myKeyFac=java.security.KeyFactory.getInstance("DH");
      DHPublicKeySpec keySpec=new DHPublicKeySpec(f, p, g);
      java.security.PublicKey yourPubKey=myKeyFac.generatePublic(keySpec);
      myKeyAgree.doPhase(yourPubKey, true);
      byte[] mySharedSecret=myKeyAgree.generateSecret();
      K=new BigInteger(1, mySharedSecret);
      K_array=K.toByteArray();
      K_array=mySharedSecret;
    }
    return K_array;
  }
  public void setP(byte[] p){ setP(new BigInteger(1, p)); }
  public void setG(byte[] g){ setG(new BigInteger(1, g)); }
  public void setF(byte[] f){ setF(new BigInteger(1, f)); }
  void setP(BigInteger p){this.p=p;}
  void setG(BigInteger g){this.g=g;}
  void setF(BigInteger f){this.f=f;}

  // e, f must be in [1, p-1].
  public void checkRange() throws Exception {
    /*
    checkRange(e);
    checkRange(f);
    */
  }

  private void checkRange(BigInteger tmp) throws Exception {
    BigInteger one = BigInteger.ONE;
    BigInteger p_1 = p.subtract(one);
    // !(1<tmp && tmp<p-1)  We expect tmp is in the range [2, p-2].
    if(!(one.compareTo(tmp) < 0 && tmp.compareTo(p_1) < 0)){
      throw new JSchException("invalid DH value");
   }
  }
}
