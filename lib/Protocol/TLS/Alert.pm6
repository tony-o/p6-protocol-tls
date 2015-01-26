use Protocol::TLS::Constants;
use Protocol::TLS::Trace;

class Protocol::TLS::Alert {
  has $.tracer = Protocol::TLS::Trace.instance;

  method decode($ctx, Buf $buf, Int $offset, Int $len) {
    return if $buf.bytes - $offset < 2;
    my ($alert, $desc) = $buf.unpack("x{$offset}C2");
    if $alert == WARNING {
      $.tracer.warning("warning: {Protocol::TLS::Constants.name('alert_desc', $desc)}\n");    
    }
    if $alert == FATAL {
      if $desc == CLOSE_NOTIFY {
        $ctx.close;
      } else {
        $.tracer.error("fatal: {Protocol::TLS::Constants.name('alert_desc', $desc)}\n");
        $ctx.shutdown(1);
      }
    } else {
      $.tracer.error("Unknown alert type: $alert\n");
      return Nil;
    }
    return 2;
  }

  method encode($ctx, $alert, $desc) {
    pack 'C2', $alert, $desc;
  }
}
