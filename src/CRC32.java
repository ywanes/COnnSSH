final public class CRC32 implements Checksum {
  private int v = 0;
  private static int[] crc_table = null;
  static {
    crc_table = new int[256];
    for (int n = 0; n < 256; n++) {
      int c = n;
      for (int k = 8;  --k >= 0; ) {
        if ((c & 1) != 0)
	  c = 0xedb88320 ^ (c >>> 1);
        else
          c = c >>> 1;
      }
      crc_table[n] = c;
    }
  }

  public void update (byte[] buf, int index, int len) {
    int c = ~v;
    while (--len >= 0)
      c = crc_table[(c^buf[index++])&0xff]^(c >>> 8);
    v = ~c;
  }

  public void reset(){
    v = 0;
  }

  public void reset(long vv){
    v = (int)(vv&0xffffffffL);
  }

  public long getValue(){
    return (long)(v&0xffffffffL);
  }

  private static final int GF2_DIM = 32;
  static long combine(long crc1, long crc2, long len2){
    long row;
    long[] even = new long[GF2_DIM];
    long[] odd = new long[GF2_DIM];

    if (len2 <= 0)
      return crc1;

    odd[0] = 0xedb88320L;          // CRC-32 polynomial
    row = 1;
    for (int n = 1; n < GF2_DIM; n++) {
        odd[n] = row;
        row <<= 1;
    }

    gf2_matrix_square(even, odd);

    gf2_matrix_square(odd, even);

    do {
      gf2_matrix_square(even, odd);
      if ((len2 & 1)!=0)
        crc1 = gf2_matrix_times(even, crc1);
      len2 >>= 1;

      if (len2 == 0)
        break;

      gf2_matrix_square(odd, even);
      if ((len2 & 1)!=0)
        crc1 = gf2_matrix_times(odd, crc1);
      len2 >>= 1;

    } while (len2 != 0);

    crc1 ^= crc2;
    return crc1;
  }

  private static long gf2_matrix_times(long[] mat, long vec){
    long sum = 0;
    int index = 0;
    while (vec!=0) {
      if ((vec & 1)!=0)
        sum ^= mat[index];
      vec >>= 1;
      index++;
    }
    return sum;
  }

  static final void gf2_matrix_square(long[] square, long[] mat) {
    for (int n = 0; n < GF2_DIM; n++)
      square[n] = gf2_matrix_times(mat, mat[n]);
  }

  public CRC32 copy(){
    CRC32 foo = new CRC32();
    foo.v = this.v;
    return foo;
  }

  public static int[] getCRC32Table(){
    int[] tmp = new int[crc_table.length];
    System.arraycopy(crc_table, 0, tmp, 0, tmp.length);
    return tmp;
  }
}
