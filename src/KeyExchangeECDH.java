public interface KeyExchangeECDH {
  void init(int size) throws Exception;
  byte[] getSecret(byte[] r, byte[] s) throws Exception;
  byte[] getQ() throws Exception;
  boolean validate(byte[] r, byte[] s) throws Exception;
}
