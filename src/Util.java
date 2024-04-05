import java.net.Socket;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

class Util{
  private static final byte[] b64 =Util.str2byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");

  static String[] split(String foo, String split){
    if(foo==null)
      return null;
    byte[] buf=Util.str2byte(foo);
    java.util.Vector bar=new java.util.Vector();
    int start=0;
    int index;
    while(true){
      index=foo.indexOf(split, start);
      if(index>=0){
	bar.addElement(Util.byte2str(buf, start, index-start));
	start=index+1;
	continue;
      }
      bar.addElement(Util.byte2str(buf, start, buf.length-start));
      break;
    }
    String[] result=new String[bar.size()];
    for(int i=0; i<result.length; i++){
      result[i]=(String)(bar.elementAt(i));
    }
    return result;
  }

  static byte[] str2byte(String str, String encoding){
    if(str==null) 
      return null;
    try{ return str.getBytes(encoding); }
    catch(java.io.UnsupportedEncodingException e){
      return str.getBytes();
    }
  }

  static byte[] str2byte(String str){
    return str2byte(str, "UTF-8");
  }

  static String byte2str(byte[] str, String encoding){
    return byte2str(str, 0, str.length, encoding);
  }

  static String byte2str(byte[] str, int s, int l, String encoding){
    try{ return new String(str, s, l, encoding); }
    catch(java.io.UnsupportedEncodingException e){
      return new String(str, s, l);
    }
  }

  static String byte2str(byte[] str){
    return byte2str(str, 0, str.length, "UTF-8");
  }

  static String byte2str(byte[] str, int s, int l){
    return byte2str(str, s, l, "UTF-8");
  }

  static String toHex(byte[] str){
    StringBuffer sb = new StringBuffer();
    for(int i = 0; i<str.length; i++){
      String foo = Integer.toHexString(str[i]&0xff);
      sb.append("0x"+(foo.length() == 1 ? "0" : "")+foo);
      if(i+1<str.length)
        sb.append(":");
    }
    return sb.toString();
  }
  static final byte[] empty = str2byte("");
  static void bzero(byte[] foo){
    if(foo==null)
      return;
    for(int i=0; i<foo.length; i++)
      foo[i]=0;
  }

  static String diffString(String str, String[] not_available){
    String[] stra=Util.split(str, ",");
    String result=null;
    loop:
    for(int i=0; i<stra.length; i++){
      for(int j=0; j<not_available.length; j++){
        if(stra[i].equals(not_available[j])){
          continue loop;
        }
      }
      if(result==null){ result=stra[i]; }
      else{ result=result+","+stra[i]; }
    }
    return result;
  }

  static String checkTilde(String str){
    try{
      if(str.startsWith("~")){
        str = str.replace("~", System.getProperty("user.home"));
      }
    }
    catch(SecurityException e){
    }
    return str;
  }

  private static int skipUTF8Char(byte b){
    if((byte)(b&0x80)==0) return 1;
    if((byte)(b&0xe0)==(byte)0xc0) return 2;
    if((byte)(b&0xf0)==(byte)0xe0) return 3;
    return 1;
  }

  static byte[] fromFile(String _file) throws IOException {
    _file = checkTilde(_file);
    File file = new File(_file);
    FileInputStream fis = new FileInputStream(_file);
    try {
      byte[] result = new byte[(int)(file.length())];
      int len=0;
      while(true){
        int i=fis.read(result, len, result.length-len);
        if(i<=0)
          break;
        len+=i;
      }
      fis.close();
      return result;
    }
    finally {
      if(fis!=null)
        fis.close();
    }
  }
}
