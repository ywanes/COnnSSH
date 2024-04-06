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

  void setKnownHosts(String filename) throws JSchException{
  }
  void setKnownHosts(InputStream input) throws JSchException{
    pool.removeAllElements();
    StringBuffer sb=new StringBuffer();
    byte i;
    int j;
    boolean error=false;
    try{
      InputStream fis=input;
      String host;
      String key=null;
      int type;
      byte[] buf=new byte[1024];
      int bufl=0;
loop:
      while(true){
	bufl=0;
        while(true){
          j=fis.read();
          if(j==-1){
            if(bufl==0){ break loop; }
            else{ break; }
          }
	  if(j==0x0d){ continue; }
	  if(j==0x0a){ break; }
          if(buf.length<=bufl){
            if(bufl>1024*10) break;   // too long...
            byte[] newbuf=new byte[buf.length*2];
            System.arraycopy(buf, 0, newbuf, 0, buf.length);
            buf=newbuf;
          }
          buf[bufl++]=(byte)j;
	}

	j=0;
        while(j<bufl){
          i=buf[j];
	  if(i==' '||i=='\t'){ j++; continue; }
	  if(i=='#'){
	    addInvalidLine(byte2str(buf, 0, bufl));
	    continue loop;
	  }
	  break;
	}
	if(j>=bufl){ 
	  addInvalidLine(byte2str(buf, 0, bufl));
	  continue loop; 
	}

        sb.setLength(0);
        while(j<bufl){
          i=buf[j++];
          if(i==0x20 || i=='\t'){ break; }
          sb.append((char)i);
	}
	host=sb.toString();
	if(j>=bufl || host.length()==0){
	  addInvalidLine(byte2str(buf, 0, bufl));
	  continue loop; 
	}

        while(j<bufl){
          i=buf[j];
	  if(i==' '||i=='\t'){ j++; continue; }
          break;
        }

        String marker="";
        if(host.charAt(0) == '@'){
          marker = host;

          sb.setLength(0);
          while(j<bufl){
            i=buf[j++];
            if(i==0x20 || i=='\t'){ break; }
            sb.append((char)i);
          }
          host=sb.toString();
          if(j>=bufl || host.length()==0){
            addInvalidLine(byte2str(buf, 0, bufl));
            continue loop; 
          }

          while(j<bufl){
            i=buf[j];
            if(i==' '||i=='\t'){ j++; continue; }
            break;
          }
        }

        sb.setLength(0);
	type=-1;
        while(j<bufl){
          i=buf[j++];
          if(i==0x20 || i=='\t'){ break; }
          sb.append((char)i);
	}
	String tmp = sb.toString();
	if(HostKey.name2type(tmp)!=HostKey.UNKNOWN){
	  type=HostKey.name2type(tmp);
	}
	else { j=bufl; }
	if(j>=bufl){
	  addInvalidLine(byte2str(buf, 0, bufl));
	  continue loop; 
	}

        while(j<bufl){
          i=buf[j];
	  if(i==' '||i=='\t'){ j++; continue; }
          break;
        }

        sb.setLength(0);
        while(j<bufl){
          i=buf[j++];
          if(i==0x0d){ continue; }
          if(i==0x0a){ break; }
          if(i==0x20 || i=='\t'){ break; }
          sb.append((char)i);
	}
	key=sb.toString();
	if(key.length()==0){
	  addInvalidLine(byte2str(buf, 0, bufl));
	  continue loop; 
	}

        while(j<bufl){
          i=buf[j];
	  if(i==' '||i=='\t'){ j++; continue; }
          break;
        }

        /**
          "man sshd" has following descriptions,
            Note that the lines in these files are typically hundreds
            of characters long, and you definitely don't want to type
            in the host keys by hand.  Rather, generate them by a script,
            ssh-keyscan(1) or by taking /usr/local/etc/ssh_host_key.pub and
            adding the host names at the front.
          This means that a comment is allowed to appear at the end of each
          key entry.
        */
        String comment=null;
        if(j<bufl){
          sb.setLength(0);
          while(j<bufl){
            i=buf[j++];
            if(i==0x0d){ continue; }
            if(i==0x0a){ break; }
            sb.append((char)i);
          }
          comment=sb.toString();
        }

      }
      if(error){
	throw new JSchException("KnownHosts: invalid format");
      }
    }
    catch(Exception e){
        AConfig.DebugPrintException("ex_124");
      if(e instanceof JSchException)
	throw (JSchException)e;         
      if(e instanceof Throwable)
        throw new JSchException(e.toString(), (Throwable)e);
      throw new JSchException(e.toString());
    }
    finally {
      try{ input.close(); }
      catch(IOException e){
        throw new JSchException(e.toString(), (Throwable)e);
      }
    }
  }
  private void addInvalidLine(String line) throws JSchException {
    HostKey hk = new HostKey(line, HostKey.UNKNOWN, null);
    pool.addElement(hk);
  }
  String getKnownHostsFile(){ return known_hosts; }
  public String getKnownHostsRepositoryID(){ return known_hosts; }

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
    String bar=getKnownHostsRepositoryID();
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
  public void remove(String host, String type){
    remove(host, type, null);
  }
  public void remove(String host, String type, byte[] key){
    boolean sync=false;
    synchronized(pool){
    for(int i=0; i<pool.size(); i++){
      HostKey hk=(HostKey)(pool.elementAt(i));
    }
    }
    if(sync){
      try{
          sync();
      }catch(Exception e){
          AConfig.DebugPrintException("ex_126");
      };
    }
  }

  protected void sync() throws IOException { 
    if(known_hosts!=null)
      sync(known_hosts); 
  }
  protected synchronized void sync(String foo) throws IOException {
    if(foo==null) return;
  }

  private static final byte[] space={(byte)0x20};
  private static final byte[] cr=str2byte("\n");
  void dump(OutputStream out) throws IOException {
    try{
      HostKey hk;
      synchronized(pool){
      for(int i=0; i<pool.size(); i++){
        hk=(HostKey)(pool.elementAt(i));
        //hk.dump(out);
	String marker=hk.getMarker();
	String host=hk.getHost();
	String type=hk.getType();
        String comment = hk.getComment();
	if(type.equals("UNKNOWN")){
	  out.write(str2byte(host));
	  out.write(cr);
	  continue;
	}
        if(marker.length()!=0){
          out.write(str2byte(marker));
          out.write(space);
        }
	out.write(str2byte(host));
	out.write(space);
	out.write(str2byte(type));
	out.write(space);
	//out.write(Util.str2byte(hk.getKey()));
        if(comment!=null){
          out.write(space);
          out.write(str2byte(comment));
        }
	out.write(cr);
      }
      }
    }
    catch(Exception e){
        AConfig.DebugPrintException("ex_127");
      System.err.println(e);
    }
  }

  private String deleteSubString(String hosts, String host){
    int i=0;
    int hostlen=host.length();
    int hostslen=hosts.length();
    int j;
    while(i<hostslen){
      j=hosts.indexOf(',', i);
      if(j==-1) break;
      if(!host.equals(hosts.substring(i, j))){
        i=j+1;	  
        continue;
      }
      return hosts.substring(0, i)+hosts.substring(j+1);
    }
    if(hosts.endsWith(host) && hostslen-i==hostlen){
      return hosts.substring(0, (hostlen==hostslen) ? 0 :hostslen-hostlen-1);
    }
    return hosts;
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
