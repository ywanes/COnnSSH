import java.security.interfaces.*;

public class KeyPairGenRSA{
  byte[] d;  // private
  byte[] e;  // public
  byte[] n;

  byte[] c; //  coefficient
  byte[] ep; // exponent p
  byte[] eq; // exponent q
  byte[] p;  // prime p
  byte[] q;  // prime q

  public void init(int key_size) throws Exception{
    java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(key_size, new java.security.SecureRandom());
    java.security.KeyPair pair = keyGen.generateKeyPair();

    java.security.PublicKey pubKey=pair.getPublic();
    java.security.PrivateKey prvKey=pair.getPrivate();

    d=((RSAPrivateKey)prvKey).getPrivateExponent().toByteArray();
    e=((RSAPublicKey)pubKey).getPublicExponent().toByteArray();
    n=((RSAPrivateKey)prvKey).getModulus().toByteArray();

    c=((RSAPrivateCrtKey)prvKey).getCrtCoefficient().toByteArray();
    ep=((RSAPrivateCrtKey)prvKey).getPrimeExponentP().toByteArray();
    eq=((RSAPrivateCrtKey)prvKey).getPrimeExponentQ().toByteArray();
    p=((RSAPrivateCrtKey)prvKey).getPrimeP().toByteArray();
    q=((RSAPrivateCrtKey)prvKey).getPrimeQ().toByteArray();
  }
  public byte[] getD(){return d;}
  public byte[] getE(){return e;}
  public byte[] getN(){return n;}
  public byte[] getC(){return c;}
  public byte[] getEP(){return ep;}
  public byte[] getEQ(){return eq;}
  public byte[] getP(){return p;}
  public byte[] getQ(){return q;}
}
