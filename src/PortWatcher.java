import java.net.*;
import java.io.*;

class PortWatcher{}// implements Runnable{
/*
  private static java.util.Vector pool=new java.util.Vector();
  private static InetAddress anyLocalAddress=null;
  static{
    // 0.0.0.0
    try{ anyLocalAddress=InetAddress.getByName("0.0.0.0"); }
    catch(UnknownHostException e){
    }
  }

  Session session;
  int lport;
  int rport;
  String host;
  InetAddress boundaddress;
  Runnable thread;
  ServerSocket ss;
  int connectTimeout=0;

  static String[] getPortForwarding(Session session){
    java.util.Vector foo=new java.util.Vector();
    synchronized(pool){
      for(int i=0; i<pool.size(); i++){
	PortWatcher p=(PortWatcher)(pool.elementAt(i));
	if(p.session==session){
	  foo.addElement(p.lport+":"+p.host+":"+p.rport);
	}
      }
    }
    String[] bar=new String[foo.size()];
    for(int i=0; i<foo.size(); i++){
      bar[i]=(String)(foo.elementAt(i));
    }
    return bar;
  }
  static PortWatcher getPort(Session session, String address, int lport) throws JSchException{
    InetAddress addr;
    try{
      addr=InetAddress.getByName(address);
    }
    catch(UnknownHostException uhe){
      throw new JSchException("PortForwardingL: invalid address "+address+" specified.", uhe);
    }
    synchronized(pool){
      for(int i=0; i<pool.size(); i++){
	PortWatcher p=(PortWatcher)(pool.elementAt(i));
	if(p.session==session && p.lport==lport){
	  if(
             (anyLocalAddress!=null &&  p.boundaddress.equals(anyLocalAddress)) ||
	     p.boundaddress.equals(addr))
	  return p;
	}
      }
      return null;
    }
  }
  private static String normalize(String address){
    if(address!=null){
      if(address.length()==0 || address.equals("*"))
        address="0.0.0.0";
      else if(address.equals("localhost"))
        address="127.0.0.1";
    }
    return address;
  }
  static PortWatcher addPort(Session session, String address, int lport, String host, int rport) throws JSchException{
    address = normalize(address);
    if(getPort(session, address, lport)!=null){
      throw new JSchException("PortForwardingL: local port "+ address+":"+lport+" is already registered.");
    }
    PortWatcher pw=new PortWatcher(session, address, lport, host, rport);
    pool.addElement(pw);
    return pw;
  }
  static void delPort(Session session, String address, int lport) throws JSchException{
    address = normalize(address);
    PortWatcher pw=getPort(session, address, lport);
    if(pw==null){
      throw new JSchException("PortForwardingL: local port "+address+":"+lport+" is not registered.");
    }
    pw.delete();
    pool.removeElement(pw);
  }
  static void delPort(Session session){
    synchronized(pool){
      PortWatcher[] foo=new PortWatcher[pool.size()];
      int count=0;
      for(int i=0; i<pool.size(); i++){
	PortWatcher p=(PortWatcher)(pool.elementAt(i));
	if(p.session==session) {
	  p.delete();
	  foo[count++]=p;
	}
      }
      for(int i=0; i<count; i++){
	PortWatcher p=foo[i];
	pool.removeElement(p);
      }
    }
  }
  PortWatcher(Session session, 
	      String address, int lport, 
	      String host, int rport) throws JSchException{
    this.session=session;
    this.lport=lport;
    this.host=host;
    this.rport=rport;
    try{
      boundaddress=InetAddress.getByName(address);
      ss=new ServerSocket(lport, 0, boundaddress);
    }
    catch(Exception e){ 
        ALoadClass.DebugPrintException("ex_131");      
      String message="PortForwardingL: local port "+address+":"+lport+" cannot be bound.";
      if(e instanceof Throwable)
        throw new JSchException(message, (Throwable)e);
      throw new JSchException(message);
    }
    if(lport==0){
      int assigned=ss.getLocalPort();
      if(assigned!=-1)
        this.lport=assigned;
    }
  }

  public void run(){}

  void delete(){
    thread=null;
    try{ 
      if(ss!=null)ss.close();
      ss=null;
    }
    catch(Exception e){
        ALoadClass.DebugPrintException("ex_133");
    }
  }

  void setConnectTimeout(int connectTimeout){
    this.connectTimeout=connectTimeout;
  }
}
*/
