import java.io.*;

public class KnownHosts{
  static final int OK=0;
  static final int NOT_INCLUDED=1;
  static final int CHANGED=2;
    
  private static final String _known_hosts="known_hosts";
  private String known_hosts=null;
  private java.util.Vector pool=null;

  private HmacSHA1 hmacsha1=null;

  KnownHosts(){
    super();
    this.hmacsha1 = getHMACSHA1();
    pool=new java.util.Vector();
  }

  public int check(String host, byte[] key){
    int result=NOT_INCLUDED;
    if(host==null){
      return result;
    }

    HostKey hk = null;
    try {
      hk = new HostKey(host, HostKey.GUESS, key);
    }
    catch(JSchException e){  // unsupported key
      return result;
    }

    synchronized(pool){
      for(int i=0; i<pool.size(); i++){
        HostKey _hk=(HostKey)(pool.elementAt(i));
      }
    }

    if(result==NOT_INCLUDED &&
       host.startsWith("[") &&
       host.indexOf("]:")>1
       ){
      return check(host.substring(1, host.indexOf("]:")), key);
    }

    return result;
  }

  public void add(HostKey hostkey){
    int type=hostkey.type;
    String host=hostkey.getHost();
    byte[] key=hostkey.key;

    HostKey hk=null;
    synchronized(pool){
      for(int i=0; i<pool.size(); i++)
        hk=(HostKey)(pool.elementAt(i));
    }

    hk=hostkey;
    pool.addElement(hk);
    String bar=null;
  }

  public HostKey[] getHostKey(){
    return getHostKey(null, (String)null);
  }
  public HostKey[] getHostKey(String host, String type){
    synchronized(pool){
      java.util.ArrayList v = new java.util.ArrayList();
      for(int i=0; i<pool.size(); i++){
	HostKey hk=(HostKey)pool.elementAt(i);
	if(hk.type==HostKey.UNKNOWN) continue;
	if(host==null || 
	   (hk.isMatched(host) && 
	    (type==null || hk.getType().equals(type)))){
          v.add(hk);
	}
      }
      HostKey[] foo = new HostKey[v.size()];
      for(int i=0; i<v.size(); i++){
        foo[i] = (HostKey)v.get(i);
      }
      if(host != null && host.startsWith("[") && host.indexOf("]:")>1){
        HostKey[] tmp =
          getHostKey(host.substring(1, host.indexOf("]:")), type);
        if(tmp.length > 0){
          HostKey[] bar = new HostKey[foo.length + tmp.length];
          System.arraycopy(foo, 0, bar, 0, foo.length);
          System.arraycopy(tmp, 0, bar, foo.length, tmp.length);
          foo = bar;
        }
      }
      return foo;
    }
  }

  private HmacSHA1 getHMACSHA1(){
    if(hmacsha1==null){
      try{
        hmacsha1=new HmacSHA1();
      }
      catch(Exception e){ 
          AConfig.DebugPrintException("ex_128");
        System.err.println("hmacsha1: "+e); 
      }
    }
    return hmacsha1;
  }

  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static String byte2str(byte[] str){return byte2str(str, 0, str.length, "UTF-8");}
  static String byte2str(byte[] str, int s, int l){return byte2str(str, s, l, "UTF-8");}  
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}
