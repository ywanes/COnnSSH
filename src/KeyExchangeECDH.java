import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;
 
public class KeyExchangeECDH{
  byte[] Q_array;
  ECPublicKey publicKey;

  private KeyAgreement myKeyAgree;
  public void init(int size) throws Exception{
    myKeyAgree = KeyAgreement.getInstance("ECDH");
    KeyPairECDSA kpair = new KeyPairECDSA();
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
  private static BigInteger two = BigInteger.ONE.add(BigInteger.ONE);
  private static BigInteger three = two.add(BigInteger.ONE);
  public boolean validate(byte[] r, byte[] s) throws Exception{
    BigInteger x = new BigInteger(1, r);
    BigInteger y = new BigInteger(1, s);
    ECPoint w = new ECPoint(x, y);
    if(w.equals(ECPoint.POINT_INFINITY)){
      return false;
    }

    ECParameterSpec params = publicKey.getParams();
    EllipticCurve curve = params.getCurve();
    BigInteger p=((ECFieldFp)curve.getField()).getP(); //nistp should be Fp. 

    BigInteger p_sub1=p.subtract(BigInteger.ONE);
    if(!(x.compareTo(p_sub1)<=0 && y.compareTo(p_sub1)<=0)){
      return false;
    }

    BigInteger tmp=x.multiply(curve.getA()).
                     add(curve.getB()).
                     add(x.modPow(three, p)).
                     mod(p);
    BigInteger y_2=y.modPow(two, p);
    if(!(y_2.equals(tmp))){ 
      return false;
    }
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
}
