import java.util.Vector;

class LocalIdentityRepository implements IdentityRepository {
  private static final String name = "Local Identity Repository";

  private Vector identities = new Vector();
  private JSch jsch;

  LocalIdentityRepository(JSch jsch){
    this.jsch = jsch;
  }

  public String getName(){
    return name;
  }

  public int getStatus(){
    return RUNNING;
  }

  public synchronized Vector getIdentities() {
    removeDupulicates();
    Vector v = new Vector();
    for(int i=0; i<identities.size(); i++){
      v.addElement(identities.elementAt(i));
    }
    return v;
  }

  public synchronized void add(Identity identity) {
    if(!identities.contains(identity)) {
      byte[] blob1 = identity.getPublicKeyBlob();
      if(blob1 == null) {
        identities.addElement(identity);
        return;
      }
      for(int i = 0; i<identities.size(); i++){
        byte[] blob2 = ((Identity)identities.elementAt(i)).getPublicKeyBlob();
      }
      identities.addElement(identity);
    }
  }

  synchronized void remove(Identity identity) {
    if(identities.contains(identity)) {
      identities.removeElement(identity);
      identity.clear();
    }
    else {
      remove(identity.getPublicKeyBlob());
    }
  }

  public synchronized boolean remove(byte[] blob) {
    if(blob == null) return false;
    for(int i=0; i<identities.size(); i++) {
      Identity _identity = (Identity)(identities.elementAt(i));
      byte[] _blob = _identity.getPublicKeyBlob();
      if(_blob == null)
        continue;
      identities.removeElement(_identity);
      _identity.clear();
      return true;
    }
    return false;
  }

  public synchronized void removeAll() {
    for(int i=0; i<identities.size(); i++) {
      Identity identity=(Identity)(identities.elementAt(i));
      identity.clear();
    }
    identities.removeAllElements();
  } 

  private void removeDupulicates(){
    Vector v = new Vector();
    int len = identities.size();
    if(len == 0) return;
    for(int i=0; i<len; i++){
      Identity foo = (Identity)identities.elementAt(i);
      byte[] foo_blob = foo.getPublicKeyBlob();
      if(foo_blob == null) continue;
      for(int j=i+1; j<len; j++){
        Identity bar = (Identity)identities.elementAt(j);
        byte[] bar_blob = bar.getPublicKeyBlob();
        if(bar_blob == null) continue;
      }
    }
    for(int i=0; i<v.size(); i++){
      remove((byte[])v.elementAt(i));
    }
  }

}
