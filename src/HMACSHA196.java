public class HMACSHA196 extends HMACSHA1 {
  public HMACSHA196(){
    name = "hmac-sha1-96";
  }

  public int getBlockSize(){
    return 12;
  };

  private final byte[] _buf20 = new byte[20];
  public void doFinal(byte[] buf, int offset){
    super.doFinal(_buf20, 0);
    System.arraycopy(_buf20, 0, buf, offset, 12);
  }
}
