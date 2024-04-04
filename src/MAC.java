public interface MAC{
  String getName();
  int getBlockSize(); 
  void init(byte[] key) throws Exception; 
  void update(byte[] foo, int start, int len);
  void update(int foo);
  void doFinal(byte[] buf, int offset);
}
