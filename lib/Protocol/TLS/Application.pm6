use Protocol::TLS::Trace;
use Protocol::TLS::Constants;

class Protocol::TLS::Application {
  method decode($ctx, *@data) {
    $ctx.state-machine('recv', CTYPE_APPLICATION_DATA);
    return $ctx.application-data(@data)
  }
  method encode($d) {
    $d;
  }
}

