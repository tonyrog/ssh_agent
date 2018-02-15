
rsa_sign for embedded use

The idea with rsa_sign is to generate a small firmware image
by generateing RSA keys into a header file at compile time
and generate a rsa signing server that can sign SSH server
ssh_agentc_rsa_challenge and ssh2_agentc_sign_request are
forwarded to a agentino stick (or something)

The real stick should ofcourse be locked for real flash updates
and memory reads (stop JTAG and boot-loader request) unless
a button/switch is pressed.

Operation. A special ssh-agent that can interface the stick is
running and serv list and signing requests. A signing request
is signaled by a beep and/or a led blink. If the user has unlocked
the key fingerprint/pincode then it is enoungh to press a button
one time to allow access. Otherwise a fingerprint/pincode must be
entered to unlock the signing functionality. The function will be
active for a T number of seconds and then the key must be unlocked
again.

The real stick should probably have

1 - memory to store several private keys, write only

2 - key generation capability ( prefered, key never leave )

3 - micro sd card reader for backups / and restore using PINCODE!!!
