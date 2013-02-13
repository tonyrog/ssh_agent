%%
%% To use from ssh: set SSH_AUTHSOCKET_ENV_NAME to a AF_UNIX socket
%%
-module(ssh_agent).

-compile(export_all).
-import(lists, [reverse/1]).
-export([key_init/0, key_loop/3]).
-export([listen_init/0, listen_loop/1]).

-include_lib("public_key/include/public_key.hrl").
-include("ssh_agent.hrl").

%% ssh agent use unix domain socket with packet = 4

-define(KEY_SERVER, key_store).

%% reply <<Type:8, ..>>
agent_messages() ->
    [
     {ssh_agentc_request_rsa_identities, 
      ?SSH_AGENTC_REQUEST_RSA_IDENTITIES, 
      []},

     %% #bits/uint32 E/mpint N/mpint Challenge/mpint
     %%  sessionid:16/bin Resp/uint32
     {ssh_agentc_rsa_challenge, 
      ?SSH_AGENTC_RSA_CHALLENGE,
      [uint32,bignum,bignum,bignum,'...']}, 

     {ssh_agentc_add_rsa_identity,
      ?SSH_AGENTC_ADD_RSA_IDENTITY,
      [uint32,bignum,bignum,bignum,bignum,bignum,bignum,string]},

     %% followed by [lifetime,uint32] [confirm]
     {ssh_agentc_add_rsa_id_constrained,
      ?SSH_AGENTC_ADD_RSA_ID_CONSTRAINED, 
      [uint32,bignum,bignum,bignum,bignum,bignum,bignum,bignum,'...']},

     %% #Bits/uint32, E/mpint, N/mpint
     {ssh_agentc_remove_rsa_identity,
      ?SSH_AGENTC_REMOVE_RSA_IDENTITY,
      [uint32, mpint, mpint]},

     {ssh_agentc_remove_all_rsa_identities,
      ?SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES,
      []},

     {ssh_agentc_add_smartcard_key,
      ?SSH_AGENTC_ADD_SMARTCARD_KEY,
      [string, string]},

     {ssh_agentc_add_smartcard_key_constrained,
      ?SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED,
      [string, string, '...']},  %% [lifetime,uint32] [confirm]

     {ssh_agentc_lock,   ?SSH_AGENTC_LOCK, [string]},

     {ssh_agentc_unlock, ?SSH_AGENTC_UNLOCK, [string]},

     %% private OpenSSH extensions for SSH2
     {ssh2_agentc_request_identities,
      ?SSH2_AGENTC_REQUEST_IDENTITIES,
      []},

     %% Blob/binary, Data/binary => SSH2_AGENT_SIGN_RESPONSE string
     {ssh2_agentc_sign_request, ?SSH2_AGENTC_SIGN_REQUEST,
      [binary,binary,uint32]},

     {ssh2_agentc_add_identity, ?SSH2_AGENTC_ADD_IDENTITY,
      [string,'...']},

     {ssh2_agentc_add_id_constrained,
      ?SSH2_AGENTC_ADD_ID_CONSTRAINED,
      [string,'...']},

     {ssh2_agentc_remove_identity, ?SSH2_AGENTC_REMOVE_IDENTITY, 
      [binary]},

     {ssh2_agentc_remove_all_identities, ?SSH2_AGENTC_REMOVE_ALL_IDENTITIES,
      []}
    ].
    
getuid() ->
    trim(os:cmd("echo $UID")).

start() ->
    start_key_server(),
    start_server(ssh_agent, listen_init, []).

listen_init() ->
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
	    ?MODULE:listen_loop(L);
	{Pid, ok} ->
	    erlang:demonitor(Mon, [flush]),
	    ?MODULE:listen_loop(L);
	{Pid, Error} ->
	    io:format("ssh_agent: listen_loop: error: ~p\n", [Error]),
	    erlang:demonitor(Mon, [flush]),
	    ?MODULE:listen_loop(L)
    end.

accept_init(Caller, L) ->
    case afunix:accept(L) of
	{ok, S} ->
	    Caller ! {self(), ok},
	    inet:setopts(S, [{active, once}]),
	    ssh_bits:install_messages(agent_messages()),
	    session(S);
	Error ->
	    Caller ! {self, Error}
    end.

session(S) ->
    receive
	{tcp, S, Data} ->
	    case ssh_bits:decode(Data) of
		{unknown, _Data} ->
		    gen_tcp:send(S, <<?SSH_AGENT_FAILURE>>),
		    gen_tcp:close(S),
		    error;
		Request ->
		    case handle_request(Request) of
			{ok,Reply} -> 
			    gen_tcp:send(S, Reply),
			    inet:setopts(S, [{active, once}]),
			    session(S);
			{error,Error} when is_binary(Error) ->
			    gen_tcp:send(S, Error),
			    gen_tcp:close(S),
			    error
		    end
	    end;
	{tcp_closed, S} ->
	    io:format("ssh_agent: session: closed\n", []),
	    gen_tcp:close(S),
	    ok;
	{tcp_error, S, Error} ->
	    io:format("ssh_agent: session: error=~p\n", [Error]),
	    gen_tcp:close(S),
	    Error
    end.

handle_request({ssh_agentc_request_rsa_identities}) ->
    case list_all(v1) of
	{ok,L} ->
	    Length = length(L),
	    Items = lists:map(fun({Blob,Comment}) ->
				      [Blob,ssh_bits:encode([Comment],[string])]
			      end, L),
	    Reply = erlang:iolist_to_binary(
		      [<<?SSH_AGENT_RSA_IDENTITIES_ANSWER,Length:32>>,Items]),
	    {ok, Reply};
	_Error ->
	    {error, <<?SSH_AGENT_FAILURE>>}
    end;
handle_request({ssh_agentc_rsa_challenge,Size,E,N,Chal,
		<<_SessionID:16/binary, _ResponseType:32>>}) ->
    Blob = make_blob(v1, [Size,E,N]),
    case lookup_key(Blob) of
	{ok,Key} ->
	    Data = ssh_bits:encode([Chal],[bignum]),
	    case public_key:sign(Data,sha,Key) of
		{error, _Reason} ->
		    {error, <<?SSH_AGENT_FAILURE>>};
		Resp ->
		    {ok, <<?SSH_AGENT_RSA_RESPONSE, Resp/binary>>}
	    end;
	_ ->
	    {error, <<?SSH_AGENT_FAILURE>>}
    end;

handle_request({ssh_agentc_add_rsa_identity,Size,N,E,D,_IQMP,_Q,_P,Comment}) ->
    Blob = make_blob(v1,[Size,E,N]),
    Key  = #'RSAPrivateKey' { modulus = N, publicExponent = E,
			      privateExponent = D },
    add_key(Blob,v1,Key,Comment,<<>>,false);
handle_request({ssh_agentc_add_rsa_id_constrained,
		Size,N,E,D,_IQMP,_Q,_P,Comment,Rest}) ->
    Blob = make_blob(v1,[Size,E,N]),
    Key  = #'RSAPrivateKey' { modulus = N, publicExponent = E,
			      privateExponent = D },
    add_key(Blob,v1,Key,Comment,Rest,true);
handle_request({ssh_agentc_remove_rsa_identity,Size,N,E}) ->
    Blob = make_blob(v1,[Size,E,N]),
    delete_key(Blob),
    {ok, <<?SSH_AGENT_SUCCESS>>};
handle_request({ssh_agentc_remove_all_rsa_identities}) ->
    delete_all(v1),
    {ok, <<?SSH_AGENT_SUCCESS>>};
handle_request({ssh2_agentc_request_identities}) ->
    case list_all(v2) of
	{ok,L} ->
	    Length = length(L),
	    Items = lists:map(fun({Blob,Comment}) ->
				      ssh_bits:encode([Blob,Comment],
						      [binary,string])
			      end, L),
	    Reply = erlang:iolist_to_binary(
		      [<<?SSH2_AGENT_IDENTITIES_ANSWER, Length:32>>,
		       Items]),
	    {ok, Reply};
	_Error ->
	    {error, <<?SSH_AGENT_FAILURE>>}
    end;
handle_request({ssh2_agentc_sign_request,Blob,Data,_Flags}) ->
    io:format("SIGN-REQUEST: Blob=~p, Flags=~p\n",
	      [format_blob(v2,Blob),_Flags]),
    case lookup_key(Blob) of
	{ok,Key} ->
	    case sign_data(Key, Data) of
		{error, _Reason} ->
		    {error, <<?SSH_AGENT_FAILURE>>};
		Signed ->
		    Reply = ssh_bits:encode([Signed], [binary]),
		    {ok, <<?SSH2_AGENT_SIGN_RESPONSE, Reply/binary>>}
	    end;
	_ ->
	    {error, <<?SSH_AGENT_FAILURE>>}
    end;
handle_request({ssh2_agentc_add_id_constrained,Type,Data}) ->
    add_identity(Type, Data, true);
handle_request({ssh2_agentc_add_identity,Type,Data}) ->
    add_identity(Type, Data, false);
handle_request({ssh2_agentc_remove_identity, Blob}) ->
    delete_key(Blob),
    {ok, <<?SSH_AGENT_SUCCESS>>};
handle_request({ssh2_agentc_remove_all_identities}) ->
    delete_all(v2),
    {ok, <<?SSH_AGENT_SUCCESS>>};
handle_request({ssh_agentc_lock, Password}) ->
    case lock(Password) of
	ok ->
	    {ok, <<?SSH_AGENT_SUCCESS>>};
	{error,_Reason} ->
	    {ok, <<?SSH_AGENT_FAILURE>>}
    end;
handle_request({ssh_agentc_unlock, Password}) ->
    case unlock(Password) of
	ok ->
	    {ok, <<?SSH_AGENT_SUCCESS>>};
	{error,_Reason} ->
	    {ok, <<?SSH_AGENT_FAILURE>>}
    end.

add_identity("ssh-rsa", Data, Constrained) ->
    [N,E,D,_IQMP,_P,_Q,Comment,Rest] = 
	ssh_bits:decode(Data, [mpint,mpint,mpint,
			       mpint,mpint,mpint,string,'...']),
    Key  = #'RSAPrivateKey' { modulus = N, publicExponent = E,
			      privateExponent = D },
    Blob = ssh_bits:encode(["ssh-rsa",E,N],[string,mpint,mpint]),
    add_key(Blob,v2,Key,Comment,Rest,Constrained);
add_identity("ssh-dss", Data, Constrained) ->
    %% Y = Pub, X = Priv
    [P,Q,G,Y,X,Comment,Rest] = 
	ssh_bits:decode(Data, [mpint,mpint,mpint,
			       mpint,mpint,string,'...']),
    Key = #'DSAPrivateKey'{p = P, q = Q, g = G, x=X, y=Y},
    Blob = ssh_bits:encode(["ssh-dss",P,Q,G,Y],
			   [string,mpint,mpint,mpint,mpint]),
    add_key(Blob,v2,Key,Comment,Rest,Constrained);
add_identity(_, _Data, _Constrained) ->
    {error, <<?SSH_AGENT_FAILURE>>}.


add_key(_Blob,_Version,_Key,_Comment,<<>>,true) ->
    {error, <<?SSH_AGENT_FAILURE>>};
add_key(Blob,Version,Key,Comment,Rest,_Constrained) ->
    try parse_constrained(Rest) of
	{Life,Confirm} ->
	    cast(add_key, [Blob, Version, Key, Comment, Life, Confirm]),
	    {ok, <<?SSH_AGENT_SUCCESS>>}
    catch
	error:_ ->
	    {error, <<?SSH_AGENT_FAILURE>>}
    end.

dump() -> cast(dump, v1), cast(dump, v2).
delete_key(Blob) ->    cast(delete_key, Blob).
delete_all(Version) -> cast(delete_all, Version).

lookup_key(Blob) ->   call(lookup_key, Blob).
list_all(Version) ->  call(list_all, Version).
lock(Password) ->     call(lock, Password).
unlock(Password) ->   call(unlock, Password).

    
parse_constrained(Data) ->
    case Data of
	<<>> -> {0, false};
	<<?SSH_AGENT_CONSTRAIN_CONFIRM>>       -> {0, true};
	<<?SSH_AGENT_CONSTRAIN_LIFETIME,L:32>> -> {L, false};
	<<?SSH_AGENT_CONSTRAIN_LIFETIME,L:32,
	  ?SSH_AGENT_CONSTRAIN_CONFIRM>> -> {L, true}
    end.

trim(Cs) ->
    reverse(trim_hd(reverse(trim_hd(Cs)))).

trim_hd([$\n|Cs]) -> trim_hd(Cs);
trim_hd([$\r|Cs]) -> trim_hd(Cs);
trim_hd([$\s|Cs]) -> trim_hd(Cs);
trim_hd([$\t|Cs]) -> trim_hd(Cs);
trim_hd(Cs) -> Cs.

%%
%% Small identity server
%%
-record(key_item,
	{
	  blob,
	  ref,
	  version,
	  key,
	  comment
	}).

call(Request,Args) ->
    Ref = erlang:monitor(process, ?KEY_SERVER),
    ?KEY_SERVER ! {Request,[Ref|self()],Args},
    receive
	{Ref,Value} ->
	    erlang:demonitor(Ref, [flush]),
	    Value;
	{'DOWN', Ref, process, _Srv, Reason} ->
	    {error, Reason}
    end.

cast(Request,Args) ->
    ?KEY_SERVER ! {Request,Args},
    ok.

reply([Ref|Caller],Value) ->
    Caller ! {Ref, Value}.

%%
%% Key store server
%%
start_key_server() ->
    start_server(?KEY_SERVER, key_init, []).

key_init() ->
    key_loop([],false,"").

key_loop(KeyList,Locked,Password) ->
    receive
	{add_key, [Blob, Version, Key, Comment, Life, _Confirm]} ->
	    io:format("ADD-KEY: blob=~p, version=~p, key=~p, comment=~p, life=~p, confirm=~p\n", [format_blob(Version,Blob),Version,Key,Comment,Life,_Confirm]),
	    %% first delete 
	    KeyList1 = lists:keydelete(Blob, #key_item.blob, KeyList),
	    Ref = make_ref(),
	    %% then add, also make sure it is first!
	    KeyList2 = [#key_item{blob=Blob,
				  ref=Ref,
				  version=Version,
				  key=Key,
				  comment=Comment} | KeyList1],
	    life_time(Life, Ref),
	    ?MODULE:key_loop(KeyList2,Locked,Password);

	{lookup_key,From,Blob} ->
	    io:format("LOOKUP-KEY: blob=~p\n", [format_blob(Blob)]),
	    case lists:keyfind(Blob,#key_item.blob,KeyList) of
		false ->
		    reply(From, {error, enoent}),
		    ?MODULE:key_loop(KeyList,Locked,Password);
		K ->
		    reply(From, {ok, K#key_item.key}),
		    ?MODULE:key_loop(KeyList,Locked,Password)
	    end;

	{list_all,From,Version} ->
	    Ks = lists:filter(
		   fun(K) -> K#key_item.version =:= Version end,
		   KeyList),
	    Ls = 
		lists:map(fun(K) -> {K#key_item.blob, K#key_item.comment} end,
			  Ks),
	    io:format("LIST-ALL: version=~p #items=~w\n", [Version,length(Ls)]),
	    reply(From,{ok, Ls}),
	    ?MODULE:key_loop(KeyList,Locked,Password);
	    
	{life, Ref} ->
	    io:format("LIFE: timeout for=~p\n", [Ref]),
	    KeyList1 = lists:keydelete(Ref, #key_item.ref, KeyList),
	    ?MODULE:key_loop(KeyList1,Locked,Password);

	{delete_key, Blob} ->
	    io:format("DELETE-KEY: blob=~p\n", [format_blob(Blob)]),
	    KeyList1 = lists:keydelete(Blob, #key_item.blob, KeyList),
	    ?MODULE:key_loop(KeyList1,Locked,Password);

	{delete_all,Version} ->
	    io:format("DELETE-ALL: version=~p\n", [Version]),
	    KeyList1 = lists:filter(
			 fun(K) -> K#key_item.version =:= Version end,
			 KeyList),
	    ?MODULE:key_loop(KeyList1,Locked,Password);

	{lock,From,Password1} ->
	    io:format("LOCK\n", []),
	    case Locked of
		true ->
		    reply(From, {error,locked}),
		    ?MODULE:key_loop(KeyList,Locked,Password);
		false ->
		    reply(From, ok),
		    ?MODULE:key_loop(KeyList,true,Password1)
	    end;

	{unlock,From,Password1} ->
	    io:format("UNLOCK\n", []),
	    if Locked =:= true, Password =:= Password1 ->
		    reply(From, ok),
		    ?MODULE:key_loop(KeyList,false,"");
	       Locked =:= false ->
		    reply(From, ok),
		    ?MODULE:key_loop(KeyList,false,"");
	       Locked =:= true ->
		    reply(From, {error,wrong_password}),
		    ?MODULE:key_loop(KeyList,Locked,Password)
	    end;

	{dump,Version} ->
	    lists:foreach(
	      fun(K) when K#key_item.version =:= Version ->
		      io:format("~4w ~s ~s (~s)\n", 
				[key_size(K#key_item.key),
				 format_blob(K#key_item.version,
					     K#key_item.blob),
				 K#key_item.comment,
				 key_type(K#key_item.key)]);
		 (_K) ->
		      ok
	      end, KeyList),
	    ?MODULE:key_loop(KeyList,Locked,Password);

	Other ->
	    io:format("ssh_agent: server_loop gor ~p\n", [Other]),
	    ?MODULE:key_loop(KeyList,Locked,Password)
    end.

sign_data(#'RSAPrivateKey'{} = Private, SigData) ->
    Signature = sign(SigData, sha, Private),
    ssh_bits:encode(["ssh-rsa", Signature],[string, binary]);
sign_data(#'DSAPrivateKey'{} = Private, SigData) ->
    RawSignature = sign(SigData, sha, Private),
    ssh_bits:encode(["ssh-dss", RawSignature],[string, binary]).

sign(SigData, Hash, #'DSAPrivateKey'{} = Key) ->
    DerSignature = public_key:sign(SigData, Hash, Key),
    #'Dss-Sig-Value'{r = R, s = S} = 
	public_key:der_decode('Dss-Sig-Value', DerSignature),
    <<R:160/big-unsigned-integer, S:160/big-unsigned-integer>>;
sign(SigData, Hash, Key) ->
    public_key:sign(SigData, Hash, Key).

key_type(#'RSAPrivateKey' {}) ->
    "RSA";
key_type(#'DSAPrivateKey'{}) ->
    "DSA".

key_size(#'RSAPrivateKey' { modulus=N }) ->
    ssh_bits:isize(N);
key_size(#'DSAPrivateKey'{ y=Y }) ->
    ssh_bits:isize(Y)+1.

	
life_time(0, _Ref) ->
    ok;
life_time(Time, Ref) when is_integer(Time), Time > 0 ->
    erlang:send_after(Time*1000, self(), {life, Ref}).

make_blob(v1, [Size,E,N]) ->
    ssh_bits:encode([Size,E,N],[uint32,bignum,bignum]).

format_blob(Blob) ->
    format_blob(v2, Blob).

format_blob(Version, Blob) ->
    format_fingerprint(blob_to_fingerprint(Version, Blob)).

blob_to_fingerprint(v1, Blob) ->
    <<_Size:32, EBits:16, Rest0/binary>> = Blob,
    EBytes = (EBits+7) div 8,
    <<E:EBytes/binary, NBits:16, Rest1/binary>> = Rest0,
    NBytes = (NBits+7) div 8,
    <<N:NBytes/binary>> = Rest1,
    erlang:md5(<<N/binary, E/binary>>);
blob_to_fingerprint(v2, Blob) ->
    erlang:md5(Blob).

format_fingerprint(Binary) ->
    string:join([ [hex(H), hex(L)] || <<H:4,L:4>> <= Binary], ":").

hex(I) when I < 10 -> I+$0;
hex(I) when I < 16 -> (I-10)+$a.

%%
%% Server utils
%% 

start_server(Name, Func, Args) ->
    SELF = self(),
    Ref  = make_ref(),
    {Pid,Mon} = spawn_opt(fun() -> server_init(SELF,Ref,Name,Func,Args) end,
			  [monitor]),
    receive
	{Ref,Value} ->
	    erlang:demonitor(Mon, [flush]),
	    Value;
	{'DOWN',Mon,process,Pid,Reason} ->
	    {error, Reason}
    end.
    
server_init(Caller,Ref,Name,Func,Args) ->
    try register(Name, self()) of
	true ->
	    Caller ! {Ref, {ok, self()}},
	    apply(?MODULE, Func, Args)
    catch
	error:_ ->
	    %% may actually return undefined!?
	    Pid = whereis(Name),
	    Caller ! {Ref, {error,{already_started,Pid}}}
    end.
