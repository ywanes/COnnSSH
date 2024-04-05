import javax.crypto.*;
import javax.crypto.spec.*;

public class HmacSHA1{
  protected int bsize = 20;
  private Mac mac;
  private final byte[] tmp = new byte[4];
  public int getBlockSize() {
    return bsize;
  };
  public void init(byte[] key) throws Exception {
    if(key.length>bsize){
      byte[] tmp = new byte[bsize];
      System.arraycopy(key, 0, tmp, 0, bsize);	  
      key = tmp;
    }
    SecretKeySpec skey = new SecretKeySpec(key, "HmacSHA1");
    mac = Mac.getInstance("HmacSHA1");
    mac.init(skey);
  }   
  public void update(int i){
    tmp[0] = (byte)(i>>>24);
    tmp[1] = (byte)(i>>>16);
    tmp[2] = (byte)(i>>>8);
    tmp[3] = (byte)i;
    update(tmp, 0, 4);
  }
  public void update(byte foo[], int s, int l){
    mac.update(foo, s, l);      
  }
  public void doFinal(byte[] buf, int offset){
    try{
      mac.doFinal(buf, offset);
    }catch(ShortBufferException e){
      System.err.println(e);
    }
  }
  public String getName(){
    return "hmac-sha1";
  }
}
