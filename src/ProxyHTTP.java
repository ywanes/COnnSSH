import java.io.*;
import java.net.*;

public class ProxyHTTP implements Proxy{
  private static int DEFAULTPORT=80;
  private String proxy_host;
  private int proxy_port;
  private InputStream in;
  private OutputStream out;
  private Socket socket;

  private String user;
  private String passwd;

  public ProxyHTTP(String proxy_host){
    int port=DEFAULTPORT;
    String host=proxy_host;
    if(proxy_host.indexOf(':')!=-1){
      try{
	host=proxy_host.substring(0, proxy_host.indexOf(':'));
	port=Integer.parseInt(proxy_host.substring(proxy_host.indexOf(':')+1));
      }
      catch(Exception e){
          ALoadClass.DebugPrintException("ex_134");
      }
    }
    this.proxy_host=host;
    this.proxy_port=port;
  }
  public ProxyHTTP(String proxy_host, int proxy_port){
    this.proxy_host=proxy_host;
    this.proxy_port=proxy_port;
  }
  public void setUserPasswd(String user, String passwd){
    this.user=user;
    this.passwd=passwd;
  }
  static Socket createSocket(String host, int port, int timeout) throws JSchException{
    Socket socket=null;
    if(timeout==0){
      try{
        socket=new Socket(host, port);
        return socket;
      }
      catch(Exception e){
          ALoadClass.DebugPrintException("ex_162");
        String message=e.toString();
        if(e instanceof Throwable)
          throw new JSchException(message, (Throwable)e);
        throw new JSchException(message);
      }
    }
    final String _host=host;
    final int _port=port;
    final Socket[] sockp=new Socket[1];
    final Exception[] ee=new Exception[1];
    String message="";
    Thread tmp=new Thread(new Runnable(){
        public void run(){
          sockp[0]=null;
          try{
            sockp[0]=new Socket(_host, _port);
          }
          catch(Exception e){
              ALoadClass.DebugPrintException("ex_163");
            ee[0]=e;
            if(sockp[0]!=null && sockp[0].isConnected()){
              try{
                sockp[0].close();
              }
              catch(Exception eee){}
            }
            sockp[0]=null;
          }
        }
      });
    tmp.setName("Opening Socket "+host);
    tmp.start();
    try{ 
      tmp.join(timeout);
      message="timeout: ";
    }
    catch(java.lang.InterruptedException eee){
    }
    if(sockp[0]!=null && sockp[0].isConnected()){
      socket=sockp[0];
    }
    else{
      message+="socket is not established";
      if(ee[0]!=null){
        message=ee[0].toString();
      }
      tmp.interrupt();
      tmp=null;
      throw new JSchException(message, ee[0]);
    }
    return socket;
  } 
  
  public void connect(SocketFactory socket_factory, String host, int port, int timeout) throws JSchException{
    try{
        socket=createSocket(proxy_host, proxy_port, timeout);    
        in=socket.getInputStream();
        out=socket.getOutputStream();
      if(timeout>0){
        socket.setSoTimeout(timeout);
      }
      socket.setTcpNoDelay(true);

      out.write(str2byte("CONNECT "+host+":"+port+" HTTP/1.0\r\n"));

      out.write(str2byte("\r\n"));
      out.flush();

      int foo=0;

      StringBuffer sb=new StringBuffer();
      while(foo>=0){
        foo=in.read(); if(foo!=13){sb.append((char)foo);  continue;}
        foo=in.read(); if(foo!=10){continue;}
        break;
      }
      if(foo<0){
        throw new IOException();
      }

      String response=sb.toString(); 
      String reason="Unknow reason";
      int code=-1;
      try{
        foo=response.indexOf(' ');
        int bar=response.indexOf(' ', foo+1);
        code=Integer.parseInt(response.substring(foo+1, bar));
        reason=response.substring(bar+1);
      }
      catch(Exception e){
          ALoadClass.DebugPrintException("ex_135");
      }
      if(code!=200){
        throw new IOException("proxy error: "+reason);
      }

      /*
      while(foo>=0){
        foo=in.read(); if(foo!=13) continue;
        foo=in.read(); if(foo!=10) continue;
        foo=in.read(); if(foo!=13) continue;      
        foo=in.read(); if(foo!=10) continue;
        break;
      }
      */

      int count=0;
      while(true){
        count=0;
        while(foo>=0){
          foo=in.read(); if(foo!=13){count++;  continue;}
          foo=in.read(); if(foo!=10){continue;}
          break;
        }
        if(foo<0){
          throw new IOException();
        }
        if(count==0)break;
      }
    }
    catch(RuntimeException e){
      throw e;
    }
    catch(Exception e){
        ALoadClass.DebugPrintException("ex_136");
      try{ if(socket!=null)socket.close(); }
      catch(Exception eee){
      }
      String message="ProxyHTTP: "+e.toString();
      if(e instanceof Throwable)
        throw new JSchException(message, (Throwable)e);
      throw new JSchException(message);
    }
  }
  public InputStream getInputStream(){ return in; }
  public OutputStream getOutputStream(){ return out; }
  public Socket getSocket(){ return socket; }
  public void close(){
    try{
      if(in!=null)in.close();
      if(out!=null)out.close();
      if(socket!=null)socket.close();
    }
    catch(Exception e){
        ALoadClass.DebugPrintException("ex_137");
    }
    in=null;
    out=null;
    socket=null;
  }
  public static int getDefaultPort(){
    return DEFAULTPORT;
  }

  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static String byte2str(byte[] str){return byte2str(str, 0, str.length, "UTF-8");}
  static String byte2str(byte[] str, int s, int l){return byte2str(str, s, l, "UTF-8");}  
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}
