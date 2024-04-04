import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class SignatureRSA implements Signature{

  java.security.Signature signature;
  KeyFactory keyFactory;

  public void init() throws Exception{
    signature=java.security.Signature.getInstance("SHA1withRSA");
    keyFactory=KeyFactory.getInstance("RSA");
  }     
  public void setPubKey(byte[] e, byte[] n) throws Exception{
    RSAPublicKeySpec rsaPubKeySpec = 
	new RSAPublicKeySpec(new BigInteger(n),
			     new BigInteger(e));
    PublicKey pubKey=keyFactory.generatePublic(rsaPubKeySpec);
    signature.initVerify(pubKey);
  }
  public void setPrvKey(byte[] d, byte[] n) throws Exception{
    RSAPrivateKeySpec rsaPrivKeySpec = 
	new RSAPrivateKeySpec(new BigInteger(n),
			      new BigInteger(d));
    PrivateKey prvKey = keyFactory.generatePrivate(rsaPrivKeySpec);
    signature.initSign(prvKey);
  }
  public byte[] sign() throws Exception{
    byte[] sig=signature.sign();      
    return sig;
  }
  public void update(byte[] foo) throws Exception{
   signature.update(foo);
  }
  public boolean verify(byte[] sig) throws Exception{
    int i=0;
    int j=0;
    byte[] tmp;
    Buffer buf=new Buffer(sig);

    if(new String(buf.getString()).equals("ssh-rsa")){
      j=buf.getInt();
      i=buf.getOffSet();
      tmp=new byte[j];
      System.arraycopy(sig, i, tmp, 0, j); sig=tmp;
    }

    return signature.verify(sig);
  }
}
