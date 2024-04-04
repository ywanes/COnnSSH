public interface Signature{
  void init() throws Exception;
  void update(byte[] H) throws Exception;
  boolean verify(byte[] sig) throws Exception;
  byte[] sign() throws Exception;
}
