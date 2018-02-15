%%
%% Test signing using rsa_sign
%%

-module(rsa_sign).

-export([start/0, stop/0, stop/1]).
-export([list_blobs/1, list_blobs/2]).
-export([raw_list_blobs/1, raw_list_blobs/2]).
-export([sign/2, sign/3]).
-export([echo/1, echo/2]).

-export([test/0]).
-export([print_blobs/1]).

-define(SERVER, rsa_sign_srv).
-define(RSA_TIMEOUT, 120000).

start() ->
    application:load(ssh_agent),
    rsa_sign_srv:start(?SERVER).

stop() -> stop(?SERVER).
stop(Pid) -> gen_server:call(Pid,stop).

echo(Message) -> echo(?SERVER, Message).
echo(Pid,Message) when is_binary(Message); is_list(Message) ->
    gen_server:call(Pid, {echo, iolist_to_binary(Message)}).

sign(Index, Message) -> sign(?SERVER, Index, Message).
sign(Pid, Index, Message) when is_integer(Index), 
			       is_binary(Message); is_list(Message) ->
    gen_server:call(Pid, {sign, Index, iolist_to_binary(Message)}, 
		    ?RSA_TIMEOUT).

list_blobs(Version) -> list_blobs(?SERVER,Version).
list_blobs(Pid,Version) ->
    gen_server:call(Pid, {list_blobs,Version}).

raw_list_blobs(Version) -> raw_list_blobs(?SERVER,Version).
raw_list_blobs(Pid,Version) ->
    gen_server:call(Pid, {raw_list_blobs,Version}).

test() ->
    start(),
    {ok,<<"echo">>} = echo(<<"echo">>),
    {ok,BlobsV1} = list_blobs(v1),
    {ok,BlobsV2} = list_blobs(v2),
    Blobs = BlobsV1++BlobsV2,
    print_blobs(Blobs),
    {ok,Signature} = 
	case Blobs of
	    [{K,_Vsn,_KeySize,_}|_] -> sign(K, <<"Hello world">>)
	end,
    stop(),
    {ok,Signature}.

hex(Binary) when is_binary(Binary) ->
    [h(X) || <<X:4>> <= Binary].

h(X) when X >= 0, X =< 15 ->
    element(X+1, {$0,$1,$2,$3,$4,$5,$6,$7,$8,$9,$a,$b,$c,$d,$e,$f}).

print_blobs([{K,Vsn,KeySize,Blob}|Blobs]) ->
    io:format("~w: vsn=~w, size=~w, finger=~s\n",
	      [K,Vsn,KeySize,ssh_agent:format_blob(Vsn,Blob)]),
    print_blobs(Blobs);
print_blobs([]) ->
    ok.
