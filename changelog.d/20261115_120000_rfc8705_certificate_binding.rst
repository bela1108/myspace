Added
~~~~~

- Resource servers can enforce :rfc:`8705` certificate-bound access tokens with
  `authlib.oauth2.rfc8705`: the `x5t#S256` thumbprint is computed from the TLS
  peer certificate DER and compared to the token `cnf` claim. Strong binding
  (the default) rejects unbound tokens without any fallback; an explicit
  compatibility mode still accepts legacy unbound tokens.
