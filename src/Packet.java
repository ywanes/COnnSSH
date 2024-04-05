public class Packet{

  private static Random random=null;
  static void setRandom(Random foo){ random=foo;}

  Buffer buffer;
  byte[] ba4=new byte[4]; 
  public Packet(Buffer buffer){
    this.buffer=buffer;
  }
  public void reset(){
    buffer.index=5;
  }
  void padding(int bsize){
    int len=buffer.index;
    int pad=(-len)&(bsize-1);
    if(pad<bsize){
      pad+=bsize;
    }
    len=len+pad-4;
    ba4[0]=(byte)(len>>>24);
    ba4[1]=(byte)(len>>>16);
    ba4[2]=(byte)(len>>>8);
    ba4[3]=(byte)(len);
    System.arraycopy(ba4, 0, buffer.buffer, 0, 4);
    buffer.buffer[4]=(byte)pad;
    synchronized(random){
      random.fill(buffer.buffer, buffer.index, pad);
    }
    buffer.skip(pad);
  }

  int shift(int len, int bsize, int mac){
    int s=len+5+9;
    int pad=(-s)&(bsize-1);
    if(pad<bsize)pad+=bsize;
    s+=pad;
    s+=mac;
    s+=32;

    if(buffer.buffer.length<s+buffer.index-5-9-len){
      byte[] foo=new byte[s+buffer.index-5-9-len];
      System.arraycopy(buffer.buffer, 0, foo, 0, buffer.buffer.length);
      buffer.buffer=foo;
    }
    System.arraycopy(buffer.buffer, 
		     len+5+9, 
		     buffer.buffer, s, buffer.index-5-9-len);

    buffer.index=10;
    buffer.putInt(len);
    buffer.index=len+5+9;
    return s;
  }
  void unshift(byte command, int recipient, int s, int len){
    System.arraycopy(buffer.buffer, 
		     s, 
		     buffer.buffer, 5+9, len);
    buffer.buffer[5]=command;
    buffer.index=6;
    buffer.putInt(recipient);
    buffer.putInt(len);
    buffer.index=len+5+9;
  }
  Buffer getBuffer(){
    return buffer;
  }
}
