public class HostKey{

  private static final byte[][] names = {
    str2byte("ssh-dss"),
    str2byte("ssh-rsa"),
    str2byte("ecdsa-sha2-nistp256"),
    str2byte("ecdsa-sha2-nistp384"),
    str2byte("ecdsa-sha2-nistp521")
  };

  protected static final int GUESS=0;
  public static final int SSHDSS=1;
  public static final int SSHRSA=2;//used!
  public static final int ECDSA256=3;
  public static final int ECDSA384=4;
  public static final int ECDSA521=5;
  static final int UNKNOWN=6;

  protected String marker;
  protected String host;
  protected int type;
  protected byte[] key;
  protected String comment;

  public HostKey(String host, byte[] key) throws ExceptionC {
    this(host, GUESS, key);
  }
  public HostKey(String host, int type, byte[] key) throws ExceptionC {
    this(host, type, key, null);
  }
  public HostKey(String host, int type, byte[] key, String comment) throws ExceptionC {
    this("", host, type, key, comment);
  }
  public HostKey(String marker, String host, int type, byte[] key, String comment) throws ExceptionC {
    this.marker=marker;
    this.host=host; 
    if(type==GUESS){
      if(key[8]=='d'){ this.type=SSHDSS; }
      else if(key[8]=='r'){ this.type=SSHRSA; }
      else if(key[8]=='a' && key[20]=='2'){ this.type=ECDSA256; }
      else if(key[8]=='a' && key[20]=='3'){ this.type=ECDSA384; }
      else if(key[8]=='a' && key[20]=='5'){ this.type=ECDSA521; }
      else { throw new ExceptionC("invalid key type");}
    }else
      this.type=type; 
    this.key=key;
    this.comment=comment;
  }
  public String getHost(){ 
    return host; 
  }
  public String getType(){
    if(type==SSHDSS ||
       type==SSHRSA ||
       type==ECDSA256 ||
       type==ECDSA384 ||
       type==ECDSA521){
      return byte2str(names[type-1]);
    }
    return "UNKNOWN";
  }
  protected static int name2type(String name){
    for(int i = 0; i < names.length; i++){
      if(byte2str(names[i]).equals(name)){
        return i + 1;
      }
    }
    return UNKNOWN;
  }
  public String getComment(){ return comment; }
  public String getMarker(){ return marker; }

  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static String byte2str(byte[] str){return byte2str(str, 0, str.length, "UTF-8");}
  static String byte2str(byte[] str, int s, int l){return byte2str(str, s, l, "UTF-8");}  
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}
