import java.text.SimpleDateFormat;
import java.util.Date;

public class SftpStatVFS {

  /*
   It seems data is serializsed according to sys/statvfs.h; for example,
   http://pubs.opengroup.org/onlinepubs/009604499/basedefs/sys/statvfs.h.html  
  */

  private long bsize;
  private long frsize;
  private long blocks;
  private long bfree;
  private long bavail;
  private long files;
  private long ffree;
  private long favail;
  private long fsid;
  private long flag;
  private long namemax;

  int flags=0;
  long size;
  int uid;
  int gid;
  int permissions;
  int atime;
  int mtime;
  String[] extended=null;

  private SftpStatVFS(){
  }

  static SftpStatVFS getStatVFS(Buffer buf){
    SftpStatVFS statvfs=new SftpStatVFS();

    statvfs.bsize = buf.getLong();
    statvfs.frsize = buf.getLong();
    statvfs.blocks = buf.getLong();
    statvfs.bfree = buf.getLong();
    statvfs.bavail = buf.getLong();
    statvfs.files = buf.getLong();
    statvfs.ffree = buf.getLong();
    statvfs.favail = buf.getLong();
    statvfs.fsid = buf.getLong();
    int flag = (int)buf.getLong();
    statvfs.namemax = buf.getLong();

    statvfs.flag =
      (flag & 1/*SSH2_FXE_STATVFS_ST_RDONLY*/) != 0 ? 1/*ST_RDONLY*/ : 0;
    statvfs.flag |=
      (flag & 2/*SSH2_FXE_STATVFS_ST_NOSUID*/) != 0 ? 2/*ST_NOSUID*/ : 0;

    return statvfs;
  } 

  public long getBlockSize() { return bsize; }
  public long getFragmentSize() { return frsize; }
  public long getBlocks() { return blocks; }
  public long getFreeBlocks() { return bfree; }
  public long getAvailBlocks() { return bavail; }
  public long getINodes() { return files; }
  public long getFreeINodes() { return ffree; }
  public long getAvailINodes() { return favail; }
  public long getFileSystemID() { return fsid; }
  public long getMountFlag() { return flag; }
  public long getMaximumFilenameLength() { return namemax; }

  public long getSize(){
    return getFragmentSize()*getBlocks()/1024;
  }

  public long getUsed(){
    return getFragmentSize()*(getBlocks()-getFreeBlocks())/1024;
  }

  public long getAvailForNonRoot(){
    return getFragmentSize()*getAvailBlocks()/1024;
  }

  public long getAvail(){
    return getFragmentSize()*getFreeBlocks()/1024;
  }

  public int getCapacity(){
    return (int)(100*(getBlocks()-getFreeBlocks())/getBlocks()); 
  }

//  public String toString() { return ""; }
}
