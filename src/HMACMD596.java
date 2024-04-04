public class HMACMD596 extends HMACMD5 {
  public HMACMD596(){
    name="hmac-md5-96";
  }

  public int getBlockSize(){
    return 12;
  };

  private final byte[] _buf16 = new byte[16];
  public void doFinal(byte[] buf, int offset){
    super.doFinal(_buf16, 0);
    System.arraycopy(_buf16, 0, buf, offset, 12);
  }
}
