public interface Identity{
  public boolean setPassphrase(byte[] passphrase) throws JSchException;
  public byte[] getPublicKeyBlob();
  public byte[] getSignature(byte[] data);
  public String getAlgName();
  public String getName();
  public boolean isEncrypted();
  public void clear();
}
