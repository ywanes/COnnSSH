import java.io.InputStream;
import java.util.Vector;

public class JSch{  
  private java.util.Vector sessionPool = new java.util.Vector();
  private IdentityRepository defaultIdentityRepository = new LocalIdentityRepository(this);
  private IdentityRepository identityRepository = defaultIdentityRepository;
  private ConfigRepository configRepository = null;
        
  public synchronized void setIdentityRepository(IdentityRepository identityRepository){
    if(identityRepository == null){
      this.identityRepository = defaultIdentityRepository;
    }
    else{
      this.identityRepository = identityRepository;
    }
  }

  public synchronized IdentityRepository getIdentityRepository(){
    return this.identityRepository;
  }

  public ConfigRepository getConfigRepository() {
    return this.configRepository;
  }

  public void setConfigRepository(ConfigRepository configRepository) {
    this.configRepository = configRepository;
  }

  private HostKeyRepository known_hosts=null;

  private static final Logger DEVNULL=new Logger(){
      public boolean isEnabled(int level){return false;}
      public void log(int level, String message){}
    };
  static Logger logger=DEVNULL;


  public Session getSession(String host)
     throws JSchException {
    return getSession(null, host, 22);
  }

  public Session getSession(String username, String host)
     throws JSchException {
    return getSession(username, host, 22);
  }

  public Session getSession(String username, String host, int port) throws JSchException {
    if(host==null){
      throw new JSchException("host must not be null.");
    }
    Session s = new Session(this, username, host, port); 
    return s;
  }

  protected void addSession(Session session){
    synchronized(sessionPool){
      sessionPool.addElement(session);
    }
  }

  protected boolean removeSession(Session session){
    synchronized(sessionPool){
      return sessionPool.remove(session);
    }
  }

  public void setHostKeyRepository(HostKeyRepository hkrepo){
    known_hosts=hkrepo;
  }

  public void setKnownHosts(String filename) throws JSchException{
    if(known_hosts==null) known_hosts=new KnownHosts(this);
    if(known_hosts instanceof KnownHosts){
      synchronized(known_hosts){
	((KnownHosts)known_hosts).setKnownHosts(filename); 
      }
    }
  }

  public void setKnownHosts(InputStream stream) throws JSchException{ 
    if(known_hosts==null) known_hosts=new KnownHosts(this);
    if(known_hosts instanceof KnownHosts){
      synchronized(known_hosts){
	((KnownHosts)known_hosts).setKnownHosts(stream); 
      }
    }
  }

  public HostKeyRepository getHostKeyRepository(){ 
    if(known_hosts==null) known_hosts=new KnownHosts(this);
    return known_hosts; 
  }

  public void addIdentity(String prvkey) throws JSchException{
    addIdentity(prvkey, (byte[])null);
  }

  public void addIdentity(String prvkey, String passphrase) throws JSchException{
    byte[] _passphrase=null;
    if(passphrase!=null){
      _passphrase=Util.str2byte(passphrase);
    }
    addIdentity(prvkey, _passphrase);
    if(_passphrase!=null)
      Util.bzero(_passphrase);
  }

  public void addIdentity(String prvkey, byte[] passphrase) throws JSchException{
    Identity identity=IdentityFile.newInstance(prvkey, null, this);
    addIdentity(identity, passphrase);
  }

  public void addIdentity(String prvkey, String pubkey, byte[] passphrase) throws JSchException{
    Identity identity=IdentityFile.newInstance(prvkey, pubkey, this);
    addIdentity(identity, passphrase);
  }

  public void addIdentity(String name, byte[]prvkey, byte[]pubkey, byte[] passphrase) throws JSchException{
    Identity identity=IdentityFile.newInstance(name, prvkey, pubkey, this);
    addIdentity(identity, passphrase);
  }

  public void addIdentity(Identity identity, byte[] passphrase) throws JSchException{
    if(passphrase!=null){
      try{ 
        byte[] goo=new byte[passphrase.length];
        System.arraycopy(passphrase, 0, goo, 0, passphrase.length);
        passphrase=goo;
        identity.setPassphrase(passphrase); 
      }
      finally{
        Util.bzero(passphrase);
      }
    }

    if(identityRepository instanceof LocalIdentityRepository){
      ((LocalIdentityRepository)identityRepository).add(identity);
    }
    else if(identity instanceof IdentityFile && !identity.isEncrypted()) {
      identityRepository.add(((IdentityFile)identity).getKeyPair().forSSHAgent());
    }
    else {
      synchronized(this){
        if(!(identityRepository instanceof IdentityRepository.Wrapper)){
          setIdentityRepository(new IdentityRepository.Wrapper(identityRepository));
        }
      }
      ((IdentityRepository.Wrapper)identityRepository).add(identity);
    }
  }

  public void removeIdentity(Identity identity) throws JSchException{
    identityRepository.remove(identity.getPublicKeyBlob());
  }

  public Vector getIdentityNames() throws JSchException{
    Vector foo=new Vector();
    Vector identities = identityRepository.getIdentities();
    for(int i=0; i<identities.size(); i++){
      Identity identity=(Identity)(identities.elementAt(i));
      foo.addElement(identity.getName());
    }
    return foo;
  }
  public void removeAllIdentity() throws JSchException{
    identityRepository.removeAll();
  }
  public static void setLogger(Logger logger){
    if(logger==null) logger=DEVNULL;
    JSch.logger=logger;
  }
  static Logger getLogger(){
    return logger;
  }
}
