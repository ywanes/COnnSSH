import java.io.*;

class IdentityFile implements Identity{

  private JSch jsch;
  private KeyPairRSA kpair;
  private String identity;

  static IdentityFile newInstance(String prvfile, String pubfile, JSch jsch) throws JSchException{
System.out.println(50000);      
    KeyPairRSA kpair = KeyPairRSA.load(jsch, prvfile, pubfile);
    return new IdentityFile(jsch, prvfile, kpair);
  }

  static IdentityFile newInstance(String name, byte[] prvkey, byte[] pubkey, JSch jsch) throws JSchException{
System.out.println(50000);
    KeyPairRSA kpair = KeyPairRSA.load(jsch, prvkey, pubkey);
    return new IdentityFile(jsch, name, kpair);
  }

  private IdentityFile(JSch jsch, String name, KeyPairRSA kpair) throws JSchException{
System.out.println(50000);      
    this.jsch = jsch;
    this.identity = name;
    this.kpair = kpair;
  }

  public boolean setPassphrase(byte[] passphrase) throws JSchException{
    return kpair.decrypt(passphrase);
  }

  public byte[] getPublicKeyBlob(){
    return kpair.getPublicKeyBlob();
  }

  public byte[] getSignature(byte[] data){
    return kpair.getSignature(data);
  }

  public String getAlgName(){
    byte[] name = kpair.getKeyTypeName();
    try {
      return new String(name, "UTF-8");
    }
    catch (UnsupportedEncodingException e){
      return new String(name);
    }
  }

  public String getName(){
    return identity;
  }

  public boolean isEncrypted(){
    return kpair.isEncrypted();
  }

  public void clear(){
    kpair.dispose();
    kpair = null;
  }

  public KeyPairRSA getKeyPair(){
    return kpair;
  }
}
