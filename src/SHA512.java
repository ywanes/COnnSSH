import java.security.*;

public class SHA512{
  MessageDigest md;
  public int getBlockSize(){return 64;}
  public void init() throws Exception {
    try{
      md=MessageDigest.getInstance("SHA-512"); 
    }catch(Exception e){
      AConfig.DebugPrintException("ex_83");
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
