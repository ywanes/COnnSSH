import java.security.*;

public class HASHSHA256 implements HASH {
  MessageDigest md;
  public int getBlockSize(){return 32;}
  public void init() throws Exception {
    try{ md=MessageDigest.getInstance("SHA-256"); }
    catch(Exception e){
        LoadClass.DebugPrintException("ex_81");
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
