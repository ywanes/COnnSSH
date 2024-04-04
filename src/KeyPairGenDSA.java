import java.security.interfaces.*;

public class KeyPairGenDSA{
  byte[] x;  // private
  byte[] y;  // public
  byte[] p;
  byte[] q;
  byte[] g;

  public void init(int key_size) throws Exception{
    java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("DSA");
    keyGen.initialize(key_size, new java.security.SecureRandom());
    java.security.KeyPair pair = keyGen.generateKeyPair();
    java.security.PublicKey pubKey=pair.getPublic();
    java.security.PrivateKey prvKey=pair.getPrivate();

    x=((DSAPrivateKey)prvKey).getX().toByteArray();
    y=((DSAPublicKey)pubKey).getY().toByteArray();

    DSAParams params=((DSAKey)prvKey).getParams();
    p=params.getP().toByteArray();
    q=params.getQ().toByteArray();
    g=params.getG().toByteArray();
  }
  public byte[] getX(){return x;}
  public byte[] getY(){return y;}
  public byte[] getP(){return p;}
  public byte[] getQ(){return q;}
  public byte[] getG(){return g;}
}
