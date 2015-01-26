enum LOGLEVEL is export <debug info notice warning error critical alert emergency>;


class Protocol::TLS::Trace {
  my Protocol::TLS::Trace $trace = Protocol::TLS::Trace.bless;

  has $start-time = time;
  has LOGLEVEL $.min-level = %*ENV<TLS_DEBUG> && LOGLEVEL.enums{%*ENV<TLS_DEBUG>} ??
                               LOGLEVEL.enums{%*ENV<TLS_DEBUG>.uc} !!
                               error; 

  method new {!!!};
  method instance { $trace };
 
  method !log(LOGLEVEL $level, Str $message) {
    return if $level.value < $.min-level; 
    $message.chomp;
    my $time = time;
    printf "[%05.3f] %s\n", $time - $start-time, $message;
  }

  method debug($msg) {
    self!log(debug,$msg);
  }
  method info($msg) {
    self!log(info,$msg);
  }
  method notice($msg) {
    self!log(notice,$msg);
  }
  method warning($msg) {
    self!log(warning,$msg);
  }
  method error($msg) {
    self!log(error,$msg);
  }
  method critical($msg) {
    self!log(critical,$msg);
  }
  method alert($msg) {
    self!log(alert,$msg);
  }
  method emergency($msg) {
    self!log(emergency,$msg);
  }
  method bin2hex(Buf $bin) {
    my $c = 0;
    my $s = '';
    join '', map {
      $c++;
      $s = !( $c % 16 ) ?? "\n" !! ( $c % 2) ?? '' !! ' ';
      "$_$s";
    }, $bin.unpack('(H2)*');
  }
}
