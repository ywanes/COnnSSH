import java.security.interfaces.*;
import java.security.spec.*;

public class KeyPairGenECDSA{
  byte[] d;
  byte[] r;
  byte[] s;
  ECPublicKey pubKey;
  ECPrivateKey prvKey;
  ECParameterSpec params;
  public void init(int key_size) throws Exception {
    String name=null;
    if(key_size==256) name="secp256r1";
    else if(key_size==384) name="secp384r1";
    else if(key_size==521) name="secp521r1";
    else throw new JSchException("unsupported key size: "+key_size);

    for(int i = 0; i<1000; i++) {
      java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
      ECGenParameterSpec ecsp = new ECGenParameterSpec(name);
      kpg.initialize(ecsp);
      java.security.KeyPair kp = kpg.genKeyPair();
      prvKey = (ECPrivateKey)kp.getPrivate();
      pubKey = (ECPublicKey)kp.getPublic();
      params=pubKey.getParams();
      d=((ECPrivateKey)prvKey).getS().toByteArray();
      ECPoint w = pubKey.getW();
      r = w.getAffineX().toByteArray();
      s = w.getAffineY().toByteArray();

      if(r.length!=s.length) continue;
      if(key_size==256 && r.length==32) break;
      if(key_size==384 && r.length==48) break;
      if(key_size==521 && r.length==66) break;
    }
    if(d.length<r.length){
      d=insert0(d);
    }
  }
  public byte[] getD(){return d;}
  public byte[] getR(){return r;}
  public byte[] getS(){return s;}
  ECPublicKey getPublicKey(){ return pubKey; }
  ECPrivateKey getPrivateKey(){ return prvKey; }

  private byte[] insert0(byte[] buf){
//    if ((buf[0] & 0x80) == 0) return buf;
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
