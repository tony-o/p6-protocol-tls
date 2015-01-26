use Protocol::TLS::Constants;

class Protocol::TLS::Compression {
  method new{!!!};
  method decode($ctx, Buf $buf, Int $offset, Int $len) {
    $buf[$offset .. $offset+$len];
  }

  method encode($v) {
    $v;
  }
}
