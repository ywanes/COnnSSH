import java.security.*;

public class HASHMD5 implements HASH{
  MessageDigest md;
  public int getBlockSize(){return 16;}
  public void init() throws Exception{
    try{ md=MessageDigest.getInstance("MD5"); }
    catch(Exception e){
        LoadClass.DebugPrintException("ex_79");
      System.err.println(e);
    }
  }
  public void update(byte[] foo, int start, int len) throws Exception{
    md.update(foo, start, len);
  }
  public byte[] digest() throws Exception{
    return md.digest();
  }
}
