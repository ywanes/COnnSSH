import java.io.*;

class IdentityFile implements Identity{
  private JSch jsch;
  private KeyPairA kpair;
  private String identity;

  static IdentityFile newInstance(String prvfile, String pubfile, JSch jsch) throws JSchException{
    KeyPairA kpair = KeyPairA.load(jsch, prvfile, pubfile);
    return new IdentityFile(jsch, prvfile, kpair);
  }

  static IdentityFile newInstance(String name, byte[] prvkey, byte[] pubkey, JSch jsch) throws JSchException{

    KeyPairA kpair = KeyPairA.load(jsch, prvkey, pubkey);
    return new IdentityFile(jsch, name, kpair);
  }

  private IdentityFile(JSch jsch, String name, KeyPairA kpair) throws JSchException{
    this.jsch = jsch;
    this.identity = name;
    this.kpair = kpair;
  }

  /**
   * Decrypts this identity with the specified pass-phrase.
   * @param passphrase the pass-phrase for this identity.
   * @return <tt>true</tt> if the decryption is succeeded
   * or this identity is not cyphered.
   */
  public boolean setPassphrase(byte[] passphrase) throws JSchException{
    return kpair.decrypt(passphrase);
  }

  /**
   * Returns the public-key blob.
   * @return the public-key blob
   */
  public byte[] getPublicKeyBlob(){
    return kpair.getPublicKeyBlob();
  }

  /**
   * Signs on data with this identity, and returns the result.
   * @param data data to be signed
   * @return the signature
   */
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

  /**
   * Returns the name of this identity. 
   * It will be useful to identify this object in the {@link IdentityRepository}.
   */
  public String getName(){
    return identity;
  }

  /**
   * Returns <tt>true</tt> if this identity is cyphered.
   * @return <tt>true</tt> if this identity is cyphered.
   */
  public boolean isEncrypted(){
    return kpair.isEncrypted();
  }

  /**
   * Disposes internally allocated data, like byte array for the private key.
   */
  public void clear(){
    kpair.dispose();
    kpair = null;
  }

  /**
   * Returns an instance of {@link KeyPairA} used in this {@link Identity}.
   * @return an instance of {@link KeyPairA} used in this {@link Identity}.
   */
  public KeyPairA getKeyPair(){
    return kpair;
  }
}
