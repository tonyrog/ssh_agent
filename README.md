# ssh agent 

start the agent

    erl -s ssh_agent

The name of the socket is /tmp/ssh-<uid>-egent 
where the <uid> is the user id of the current user.
Then in a shell do:

    export SSH_AUTH_SOCK=/tmp/ssh-<uid>-egent 

Add keys to the agent by using ssh-add

    ssh-add .ssh/id_ras
    ssh-add .ssh/foo.pwm

Now we can list the stored keys with

    ssh-add -l
    