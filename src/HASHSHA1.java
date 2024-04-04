import java.security.*;

public class HASHSHA1 implements HASH{
  MessageDigest md;
  public int getBlockSize(){return 20;}
  public void init() throws Exception{
    try{ md=MessageDigest.getInstance("SHA-1"); }
    catch(Exception e){
        LoadClass.DebugPrintException("ex_80");
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
