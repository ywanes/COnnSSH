import java.security.MessageDigest;

public class HASHSHA384 implements HASH {
  MessageDigest md;
  public int getBlockSize(){return 48;}
  public void init() throws Exception {
    try{ md=MessageDigest.getInstance("SHA-384"); }
    catch(Exception e){
        LoadClass.DebugPrintException("ex_82");
      System.err.println(e);
    }
  }
  public void update(byte[] foo, int start, int len) throws Exception {
    md.update(foo, start, len);
  }
  public byte[] digest() throws Exception {
    return md.digest();
  }
}
