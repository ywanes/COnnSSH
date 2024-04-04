public class Random{
  private byte[] tmp=new byte[16];
  private java.security.SecureRandom random=null;
  public Random(){
    random=new java.security.SecureRandom();
  }
  public void fill(byte[] foo, int start, int len){
    if(len>tmp.length){ tmp=new byte[len]; }
    random.nextBytes(tmp);
    System.arraycopy(tmp, 0, foo, start, len);
  }
}
