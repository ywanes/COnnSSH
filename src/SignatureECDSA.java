public interface SignatureECDSA extends Signature {
  void setPubKey(byte[] r, byte[] s) throws Exception;
  void setPrvKey(byte[] s) throws Exception;
}
