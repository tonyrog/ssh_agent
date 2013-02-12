%%
%% To use from ssh: set SSH_AUTHSOCKET_ENV_NAME to a AF_UNIX socket
%%
-module(ssh_agent).

-compile(export_all).
-import(lists, [reverse/1]).

%% ssh agent use unix domain socket with packet = 4

%% reply <<Type:8, ..>>

getuid() ->
    trim(os:cmd("echo -n $UID")).

start() ->
    UID = getuid(),
    SocketName = "/tmp/ssh-"++UID++"-egent",
    file:delete(SocketName),
    {ok,L} = afunix:listen(SocketName,
			   [{active,false},{packet,4},{mode,binary}]),
    listen_loop(L).

listen_loop(L) ->
    SELF = self(),
    {Pid,Mon} = spawn_opt(fun() -> accept_init(SELF,L) end, [monitor]),
    receive
	{'DOWN',Mon,process,Pid,Reason} ->
	    io:format("ssh_agent: listen_loop: crashed: ~p\n", [Reason]),
	    listen_loop(L);
	{Pid, ok} ->
	    erlang:demonitor(Mon, [flush]),
	    listen_loop(L);
	{Pid, Error} ->
	    io:format("ssh_agent: listen_loop: error: ~p\n", [Error]),
	    erlang:demonitor(Mon, [flush]),
	    listen_loop(L)
    end.

accept_init(Caller, L) ->
    case afunix:accept(L) of
	{ok, S} ->
	    Caller ! {self(), ok},
	    inet:setopts(S, [{active, once}]),
	    session(S);
	Error ->
	    Caller ! {self, Error}
    end.

session(S) ->
    receive
	{tcp, S, Data} ->
	    io:format("ssh_agent: session: Data=~p\n", [Data]),
	    inet:setopts(S, [{active, once}]),
	    session(S);
	{tcp_closed, S} ->
	    gen_tcp:close(S),
	    ok;
	{tcp_error, S, Error} ->
	    io:format("ssh_agent: session: error=~p\n", [Error]),
	    gen_tcp:close(S),
	    Error
    end.


trim(Cs) ->
    reverse(trim_hd(reverse(trim_hd(Cs)))).

trim_hd([$\n|Cs]) -> trim_hd(Cs);
trim_hd([$\r|Cs]) -> trim_hd(Cs);
trim_hd([$\s|Cs]) -> trim_hd(Cs);
trim_hd([$\t|Cs]) -> trim_hd(Cs);
trim_hd(Cs) -> Cs.
