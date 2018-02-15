%%
%% To use from ssh: set SSH_AUTH_SOCK to a AF_UNIX socket
%%
-module(ssh_agent).

-compile(export_all).
-import(lists, [reverse/1]).
-export([key_init/0, key_loop/4]).
-export([listen_init/0, listen_loop/1]).

-include_lib("public_key/include/public_key.hrl").
-include("ssh_agent.hrl").

%% ssh agent use unix domain socket with packet = 4

-define(KEY_SERVER, key_store).

-define(BYTE(X),          (X):8/unsigned-big-integer).
-define(UINT16(X),        (X):16/unsigned-big-integer).
-define(UINT32(X),        (X):32/unsigned-big-integer).
-define(STRING(X,Len),    ?UINT32(Len), X:Len/binary).
-define(BINARY(X,Len),    ?UINT32(Len), X:Len/binary ).
-define(MPINT(I,Len),     ?UINT32(Len), I:Len/big-signed-integer-unit:8 ).


start() ->
    application:load(ssh_agent),
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
	    session(S);
	Error ->
	    Caller ! {self, Error}
    end.

session(S) ->
    receive
	{tcp, S, Data} ->
	    case decode(Data) of
		{unknown, _Data} ->
		    io:format("unknown message ~p\n", [Data]),
		    gen_tcp:send(S, <<?SSH_AGENT_FAILURE>>),
		    gen_tcp:close(S),
		    error;
		Request ->
		    io:format("request ~p\n", [Request]),
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

handle_request({ssh_agentc_request_rsa_identities,[]}) ->
    case list_all(v1) of
	{ok,L} ->
	    Length = length(L),
	    Items = lists:map(fun({Blob,Comment}) ->
				      Len = byte_size(Comment),
				      [Blob,<<?STRING(Comment,Len)>>]
			      end, L),
	    Reply = erlang:iolist_to_binary(
		      [<<?SSH_AGENT_RSA_IDENTITIES_ANSWER,Length:32>>,Items]),
	    {ok, Reply};
	_Error ->
	    {error, <<?SSH_AGENT_FAILURE>>}
    end;
handle_request({ssh_agentc_rsa_challenge,
		[Size,E,N,Chal,
		 <<_SessionID:16/binary, _ResponseType:32>>]}) ->
    Blob = make_blob(v1, [Size,E,N]),
    case sign_call(Blob,encode_bignum(Chal)) of
	{ok,Resp} ->
	    {ok, <<?SSH_AGENT_RSA_RESPONSE, Resp/binary>>};
	_ ->
	    {error, <<?SSH_AGENT_FAILURE>>}
    end;
handle_request({ssh_agentc_add_rsa_identity,
		[Size,N,E,D,_IQMP,_Q,_P,Comment]}) ->
    Blob = make_blob(v1,[Size,E,N]),
    Key  = #'RSAPrivateKey' { modulus = N, publicExponent = E,
			      privateExponent = D },
    add_key(Blob,v1,Key,Comment,<<>>,false);
handle_request({ssh_agentc_add_rsa_id_constrained,
		[Size,N,E,D,_IQMP,_Q,_P,Comment,Rest]}) ->
    Blob = make_blob(v1,[Size,E,N]),
    Key  = #'RSAPrivateKey' { modulus = N, publicExponent = E,
			      privateExponent = D },
    add_key(Blob,v1,Key,Comment,Rest,true);
handle_request({ssh_agentc_remove_rsa_identity,[Size,N,E]}) ->
    Blob = make_blob(v1,[Size,E,N]),
    delete_key(Blob),
    {ok, <<?SSH_AGENT_SUCCESS>>};
handle_request({ssh_agentc_remove_all_rsa_identities,[]}) ->
    delete_all(v1),
    {ok, <<?SSH_AGENT_SUCCESS>>};
handle_request({ssh2_agentc_request_identities,[]}) ->
    case list_all(v2) of
	{ok,L} ->
	    Length = length(L),
	    Items = lists:map(fun({Blob,Comment}) ->
				      BlobLen = byte_size(Blob),
				      CommentLen = byte_size(Comment),
				      <<?BINARY(Blob,BlobLen),
					?STRING(Comment,CommentLen)>>
			      end, L),
	    Reply = erlang:iolist_to_binary(
		      [<<?SSH2_AGENT_IDENTITIES_ANSWER, Length:32>>,
		       Items]),
	    {ok, Reply};
	_Error ->
	    {error, <<?SSH_AGENT_FAILURE>>}
    end;
handle_request({ssh2_agentc_sign_request,[Blob,Data,_Flags]}) ->
    io:format("SIGN-REQUEST: Blob=~p, Flags=~p\n",
	      [format_blob(v2,Blob),_Flags]),
    case sign_call(Blob,Data) of
	{error, _Reason} ->
	    {error, <<?SSH_AGENT_FAILURE>>};
	{ok,Signed} ->
	    SignedLen = byte_size(Signed),
	    Reply = <<?BINARY(Signed,SignedLen)>>,
	    {ok, <<?SSH2_AGENT_SIGN_RESPONSE, Reply/binary>>}
    end;
handle_request({ssh2_agentc_add_id_constrained,[Type,Data]}) ->
    add_identity(Type, Data, true);
handle_request({ssh2_agentc_add_identity,[Type,Data]}) ->
    add_identity(Type, Data, false);
handle_request({ssh2_agentc_remove_identity,[Blob]}) ->
    delete_key(Blob),
    {ok, <<?SSH_AGENT_SUCCESS>>};
handle_request({ssh2_agentc_remove_all_identities,[]}) ->
    delete_all(v2),
    {ok, <<?SSH_AGENT_SUCCESS>>};
handle_request({ssh_agentc_lock,[Password]}) ->
    case lock(Password) of
	ok ->
	    {ok, <<?SSH_AGENT_SUCCESS>>};
	{error,_Reason} ->
	    {ok, <<?SSH_AGENT_FAILURE>>}
    end;
handle_request({ssh_agentc_unlock,[Password]}) ->
    case unlock(Password) of
	ok ->
	    {ok, <<?SSH_AGENT_SUCCESS>>};
	{error,_Reason} ->
	    {ok, <<?SSH_AGENT_FAILURE>>}
    end.

add_identity(<<"ssh-rsa">>, Data, Constrained) ->
    <<?MPINT(N,NLen),?MPINT(E,ELen),?MPINT(D,_DLen),
      ?MPINT(_IQMP,_QMPLen),?MPINT(_P,_PLen),?MPINT(_Q,_QLen),
      ?STRING(Comment,_CLen),Rest/binary>> = Data,
    Key  = #'RSAPrivateKey' { modulus = N, publicExponent = E,
			      privateExponent = D },
    Blob = <<?STRING(<<"ssh-rsa">>,7),?MPINT(E,ELen),?MPINT(N,NLen)>>,
    add_key(Blob,v2,Key,Comment,Rest,Constrained);
add_identity(<<"ssh-dss">>, Data, Constrained) ->
    %% Y = Pub, X = Priv
    <<?MPINT(P,PLen),?MPINT(Q,QLen),?MPINT(G,GLen),
      ?MPINT(Y,YLen),?MPINT(X,XLen),?STRING(Comment,_CommentLen),
      Rest/binary>> = Data,
    Key = #'DSAPrivateKey'{p = P, q = Q, g = G, x=X, y=Y},
    Blob = <<?STRING(<<"ssh-dss">>,7),
	     ?MPINT(P,PLen),?MPINT(Q,QLen),
	     ?MPINT(G,GLen),?MPINT(Y,YLen)>>,
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

encode_bignum(X) ->
    XSz = isize(X),
    Pad = (8 - (XSz rem 8)) rem 8,
    <<?UINT16(XSz),0:Pad/unsigned-integer,X:XSz/big-unsigned-integer>>.

decode_bignum(<<?UINT16(XSz),Bin/binary>>) ->
    Pad = (8 - (XSz rem 8)) rem 8,
    case Bin of
	<<_:Pad,X:XSz/big-unsigned-integer,Rest/binary>> ->
	    {X,Rest}
    end.

getuid() ->
    trim(os:cmd("id -u")).

decode(<<?BYTE(?SSH_AGENTC_REQUEST_RSA_IDENTITIES),Args/binary>>) ->
    <<>> = Args,
    {ssh_agentc_request_rsa_identities,[]};

%% #bits/uint32 E/mpint N/mpint Challenge/mpint
%%  sessionid:16/bin Resp/uint32
decode(<<?BYTE(?SSH_AGENTC_RSA_CHALLENGE),?UINT32(NBits),Bin/binary>>) ->
    {E,Bin1} = decode_bignum(Bin),
    {N,Bin2} = decode_bignum(Bin1),
    {Challenge,Args} = decode_bignum(Bin2),
    {ssh_agentc_rsa_challenge,[NBits,E,N,Challenge,Args]};

%% Size,N,E,D,_IQMP,_Q,_P,Comment
decode(<<?BYTE(?SSH_AGENTC_ADD_RSA_IDENTITY),?UINT32(Size),Bin/binary>>) ->
    {N,Bin1} = decode_bignum(Bin),
    {E,Bin2} = decode_bignum(Bin1),
    {D,Bin3} = decode_bignum(Bin2),
    {IQMP,Bin4} = decode_bignum(Bin3),
    {Q,Bin5} = decode_bignum(Bin4),
    {P,Bin6} = decode_bignum(Bin5),
    <<?STRING(Comment,_Len1),Args/binary>> = Bin6,
    <<>> = Args,
    {ssh_agentc_add_rsa_identity,[Size,N,E,D,IQMP,Q,P,Comment]};

%% Size,N,E,D,_IQMP,_Q,_P,Comment  followed by [lifetime,uint32] [confirm]
decode(<<?BYTE(?SSH_AGENTC_ADD_RSA_ID_CONSTRAINED),?UINT32(Size),
	 Bin/binary>>) ->
    {N,Bin1} = decode_bignum(Bin),
    {E,Bin2} = decode_bignum(Bin1),
    {D,Bin3} = decode_bignum(Bin2),
    {IQMP,Bin4} = decode_bignum(Bin3),
    {Q,Bin5} = decode_bignum(Bin4),
    {P,Bin6} = decode_bignum(Bin5),
    <<?STRING(Comment,_Len1),Args/binary>> = Bin6,
    {ssh_agentc_add_rsa_id_constrained,[Size,N,E,D,IQMP,Q,P,Comment,Args]};

%% #Bits/uint32, E/mpint, N/mpint
decode(<<?BYTE(?SSH_AGENTC_REMOVE_RSA_IDENTITY),
	 ?UINT32(Bits),?MPINT(E,_L0),?MPINT(N,_L0),Args/binary>>) ->
    <<>> = Args,
    {ssh_agentc_remove_rsa_identity,[Bits,E,N]};

decode(<<?BYTE(?SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES),Args/binary>>) ->
    <<>> = Args,
    {ssh_agentc_remove_all_rsa_identities,[]};

decode(<<?BYTE(?SSH_AGENTC_ADD_SMARTCARD_KEY),
	 ?STRING(A1,_L1),?STRING(A2,_L2),Args/binary>>) ->
    <<>> = Args,
    {ssh_agentc_add_smartcard_key,[A1,A2]};

%% [lifetime,uint32] [confirm]
decode(<<?BYTE(?SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED),
	 ?STRING(A1,_L1),?STRING(A2,_L2),Args/binary>>) ->
    {ssh_agentc_add_smartcard_key_constrained,[A1,A2,Args]};

decode(<<?BYTE(?SSH_AGENTC_LOCK),?STRING(Password,_Len),Args/binary>>) ->
    <<>> = Args,
    {ssh_agentc_lock,[Password]};

decode(<<?BYTE(?SSH_AGENTC_UNLOCK),?STRING(Password,_Len),Args/binary>>) ->
    <<>> = Args,
    {ssh_agentc_unlock,[Password]};

%% private OpenSSH extensions for SSH2
decode(<<?BYTE(?SSH2_AGENTC_REQUEST_IDENTITIES),Args/binary>>) ->
    <<>> = Args,
    {ssh2_agentc_request_identities,[]};

%% Blob/binary, Data/binary => SSH2_AGENT_SIGN_RESPONSE string
decode(<<?BYTE(?SSH2_AGENTC_SIGN_REQUEST),?BINARY(Blob,_Len1),
	 ?BINARY(Data,_Len2),?UINT32(Flags),Args/binary>>) ->
    <<>> = Args,
    {ssh2_agentc_sign_request,[Blob,Data,Flags]};

decode(<<?BYTE(?SSH2_AGENTC_ADD_IDENTITY),
	 ?STRING(Type,_Len1),Args/binary>>) ->
    {ssh2_agentc_add_identity,[Type,Args]};

decode(<<?BYTE(?SSH2_AGENTC_ADD_ID_CONSTRAINED),
	 ?STRING(Type,_Len1),Args/binary>>) ->
    {ssh2_agentc_add_id_constrained,[Type,Args]};

decode(<<?BYTE(?SSH2_AGENTC_REMOVE_IDENTITY),
	 ?BINARY(Blob,_Len1),Args/binary>>) ->
    <<>> = Args,
    {ssh2_agentc_remove_identity, [Blob]};

decode(<<?BYTE(?SSH2_AGENTC_REMOVE_ALL_IDENTITIES),Args/binary>>) ->
    <<>> = Args,
    {ssh2_agentc_remove_all_identities,[]};

decode(Data) ->
    {unknown, Data}.


dump() -> cast(dump, v1), cast(dump, v2).
delete_key(Blob) ->    cast(delete_key, Blob).
delete_all(Version) -> cast(delete_all, Version).

lookup_key(Blob) ->   call(lookup_key, Blob).
list_all(Version) ->  call(list_all, Version).
lock(Password) ->     call(lock, Password).
unlock(Password) ->   call(unlock, Password).
sign_call(Blob,Data) -> call(sign, {Blob, Data}).
    
    
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
	  key_size,
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
    {ok,Srv} = rsa_sign:start(),
    KeyList = load_srv_keys(Srv,[]),
    key_loop(KeyList,false,"",Srv).

key_loop(KeyList,Locked,Password,Srv) ->
    receive
	{sign, From, {Blob, Data}} ->
	    case lists:keyfind(Blob,#key_item.blob,KeyList) of
		false ->
		    reply(From, {error, enoent}),
		    ?MODULE:key_loop(KeyList,Locked,Password,Srv);
		K ->
		    Reply =
			case K#key_item.key of
			    {rsa_sign,Index} ->
				sign_remote(K#key_item.version,Srv,Index,Data);
			    Key ->
				case sign_data(K#key_item.version,Key,Data) of 
				    {error, _Reason} ->
					{error, <<?SSH_AGENT_FAILURE>>};
				    Resp ->
					{ok,Resp}
				end
			end,
		    reply(From, Reply),
		    ?MODULE:key_loop(KeyList,Locked,Password,Srv)
	    end;

	{add_key, [Blob, Version, Key, Comment, Life, _Confirm]} ->
	    io:format("ADD-KEY: blob=~s\n", [format_blob(Version,Blob)]),
	    io:format("         version=~p\n", [Version]),
	    io:format("         comment=~p\n", [Comment]),
	    io:format(" BLOB-DATA:~p\n", [Blob]),

	    %% first delete 
	    KeyList1 = lists:keydelete(Blob, #key_item.blob, KeyList),
	    Ref = make_ref(),
	    %% then add, also make sure it is first!
	    KeyList2 = [#key_item{blob=Blob,
				  ref=Ref,
				  key_size=key_size(Key),
				  version=Version,
				  key=Key,
				  comment=Comment} | KeyList1],
	    life_time(Life, Ref),
	    ?MODULE:key_loop(KeyList2,Locked,Password,Srv);

	{lookup_key,From,Blob} ->
	    io:format("LOOKUP-KEY: blob=~p\n", [format_blob(Blob)]),
	    case lists:keyfind(Blob,#key_item.blob,KeyList) of
		false ->
		    reply(From, {error, enoent}),
		    ?MODULE:key_loop(KeyList,Locked,Password,Srv);
		K ->
		    reply(From, {ok, K#key_item.key}),
		    ?MODULE:key_loop(KeyList,Locked,Password,Srv)
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
	    ?MODULE:key_loop(KeyList,Locked,Password,Srv);
	    
	{life, Ref} ->
	    io:format("LIFE: timeout for=~p\n", [Ref]),
	    KeyList1 = lists:keydelete(Ref, #key_item.ref, KeyList),
	    ?MODULE:key_loop(KeyList1,Locked,Password,Srv);

	{delete_key, Blob} ->
	    io:format("DELETE-KEY: blob=~p\n", [format_blob(Blob)]),
	    KeyList1 = lists:keydelete(Blob, #key_item.blob, KeyList),
	    ?MODULE:key_loop(KeyList1,Locked,Password,Srv);

	{delete_all,Version} ->
	    io:format("DELETE-ALL: version=~p\n", [Version]),
	    KeyList1 = lists:filter(
			 fun(K) -> K#key_item.version =:= Version end,
			 KeyList),
	    ?MODULE:key_loop(KeyList1,Locked,Password,Srv);

	{lock,From,Password1} ->
	    io:format("LOCK\n", []),
	    case Locked of
		true ->
		    reply(From, {error,locked}),
		    ?MODULE:key_loop(KeyList,Locked,Password,Srv);
		false ->
		    reply(From, ok),
		    ?MODULE:key_loop(KeyList,true,Password1,Srv)
	    end;

	{unlock,From,Password1} ->
	    io:format("UNLOCK\n", []),
	    if Locked =:= true, Password =:= Password1 ->
		    reply(From, ok),
		    ?MODULE:key_loop(KeyList,false,"",Srv);
	       Locked =:= false ->
		    reply(From, ok),
		    ?MODULE:key_loop(KeyList,false,"",Srv);
	       Locked =:= true ->
		    reply(From, {error,wrong_password}),
		    ?MODULE:key_loop(KeyList,Locked,Password,Srv)
	    end;

	{dump,Version} ->
	    lists:foreach(
	      fun(K) when K#key_item.version =:= Version ->
		      io:format("~4w MD5:~s ~s (~s)\n", 
				[K#key_item.key_size,
				 format_blob(K#key_item.version,
					     K#key_item.blob),
				 K#key_item.comment,
				 key_type(K#key_item.key)]);
		 (_K) ->
		      ok
	      end, KeyList),
	    ?MODULE:key_loop(KeyList,Locked,Password,Srv);

	Other ->
	    io:format("ssh_agent: server_loop gor ~p\n", [Other]),
	    ?MODULE:key_loop(KeyList,Locked,Password)
    end.

load_srv_keys(Srv,KeyList) ->
    {ok,ListV1} = rsa_sign:list_blobs(Srv,v1),
    {ok,ListV2} = rsa_sign:list_blobs(Srv,v2),
    add_srv_keys(ListV1++ListV2, KeyList).

add_srv_keys([{Index,Version,KeySize,Blob}|Bs], KeyList) ->
    Key={rsa_sign,Index},
    Comment = <<"Key on a stick">>,
    io:format("ADD-SRV: blob=~s\n", [format_blob(Version,Blob)]),
    io:format("         version=~p\n", [Version]),
    io:format("         comment=~p\n", [Comment]),
    io:format(" BLOB-DATA:~p\n", [Blob]),

    KeyList1 = lists:keydelete(Blob, #key_item.blob, KeyList),
    add_srv_keys(Bs, 
		 [ #key_item { blob=Blob,
			       ref=undefined,
			       version=Version,
			       key=Key,
			       key_size=KeySize,
			       comment=Comment}|KeyList1]);
add_srv_keys([], KeyList) ->
    KeyList.

sign_remote(v1,Srv,Index,Data) ->
    rsa_sign:sign(Srv, Index, Data);
sign_remote(v2,Srv,Index,Data) ->
    case rsa_sign:sign(Srv, Index, Data) of
	{ok,Signature} ->
	    SigSize = byte_size(Signature),
	    {ok,<<?STRING(<<"ssh-rsa">>,7), ?BINARY(Signature,SigSize)>>};
	Error ->
	    Error
    end.

sign_data(v1,Key,Data) ->
    public_key:sign(Data,sha,Key);
sign_data(v2,#'RSAPrivateKey'{} = Private, SigData) ->
    Signature = sign(SigData, sha, Private),
    SigSize = byte_size(Signature),
    <<?STRING(<<"ssh-rsa">>,7), ?BINARY(Signature,SigSize)>>;
sign_data(v2,#'DSAPrivateKey'{} = Private, SigData) ->
    RawSignature = sign(SigData, sha, Private),
    SigSize = byte_size(RawSignature),
    <<?STRING(<<"ssh-dss">>,7), ?BINARY(RawSignature,SigSize)>>.

sign(SigData, Hash, #'DSAPrivateKey'{} = Key) ->
    DerSignature = public_key:sign(SigData, Hash, Key),
    #'Dss-Sig-Value'{r = R, s = S} = 
	public_key:der_decode('Dss-Sig-Value', DerSignature),
    <<R:160/big-unsigned-integer, S:160/big-unsigned-integer>>;
sign(SigData, Hash, Key) ->
    public_key:sign(SigData, Hash, Key).

key_type({rsa_sign,Index}) ->
    "REMOTE:RSA:"++integer_to_list(Index);
key_type(#'RSAPrivateKey' {}) ->
    "RSA";
key_type(#'DSAPrivateKey'{}) ->
    "DSA".

key_size(#'RSAPrivateKey' { modulus=N }) ->
    isize(N);
key_size(#'DSAPrivateKey'{ y=Y }) ->
    isize(Y)+1.

	
life_time(0, _Ref) ->
    ok;
life_time(Time, Ref) when is_integer(Time), Time > 0 ->
    erlang:send_after(Time*1000, self(), {life, Ref}).

make_blob(v1, [Size,E,N]) ->
    EBin = encode_bignum(E),
    NBin = encode_bignum(N),
    <<?UINT32(Size),EBin/binary,NBin/binary>>.

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

%%--------------------------------------------------------------------
%% @doc
%%     Count number of bits used to represent a non negative integer
%% @end
%%--------------------------------------------------------------------
-spec isize(X::non_neg_integer()) -> non_neg_integer().

isize(X) -> isize_(X).

isize_(0) -> %% defined to 0, but we really need one bit!
    0;
isize_(X) when is_integer(X), X > 0 ->
    isize32_(X,0).

isize32_(X, I) ->
    if X > 16#FFFFFFFF -> isize32_(X bsr 32, I+32);
       true -> isize8_(X, I)
    end.

isize8_(X, I) ->
    if X > 16#FF -> isize8_(X bsr 8, I+8);
       X >= 2#10000000 -> I+8;
       X >= 2#1000000 -> I+7;
       X >= 2#100000 -> I+6;
       X >= 2#10000 -> I+5;
       X >= 2#1000 -> I+4;
       X >= 2#100 -> I+3;
       X >= 2#10 -> I+2;
       X >= 2#1 -> I+1;
       true -> I
    end.

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
