class UtilC{
    static void show(String cipher, int completed, byte[] array){
        boolean _enable=false;
        if ( _enable ){
            if ( completed > 0 ){
                System.out.print("["+cipher+"-");
                for(int i=0;i<completed;i++){
                    if ( i > 0 )
                        System.out.print("-");
                    System.out.print((int)array[i]);
                }
                System.out.println("]");
            }else{
                System.out.print("["+cipher+"]");
            }
        }
    }    
    static String byte2str(byte[] str) {
        return byte2str(str, 0, str.length, "UTF-8");
    }
    static String byte2str(byte[] str, int s, int l, String encoding) {
        try {
            return new String(str, s, l, encoding);
        } catch (java.io.UnsupportedEncodingException e) {
            System.err.println(".Util UnsupportedEncodingException " + e);
            return new String(str, s, l);
        }
    }
    static byte[] str2byte(String str, String encoding) {
        if (str == null) return null;
        try {
            return str.getBytes(encoding);
        } catch (java.io.UnsupportedEncodingException e) {
            System.err.println("..Util UnsupportedEncodingException " + e);
            return str.getBytes();
        }
    }       
    static void sleep(long a){
        try {
            Thread.sleep(a);
        } catch (Exception e) {
            System.err.println("...Util Error sleep " + e);
        };        
    }
}
