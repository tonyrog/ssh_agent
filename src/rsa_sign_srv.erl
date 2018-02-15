%%%-------------------------------------------------------------------
%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2018, Tony Rogvall
%%% @doc
%%%    rsa_sign controller
%%% @end
%%% Created : 11 Feb 2018 by Tony Rogvall <tony@rogvall.se>
%%%-------------------------------------------------------------------
-module(rsa_sign_srv).

-behaviour(gen_server).

%% API
-export([start_link/0]).
-export([start_link/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-record(blob,
	{
	  index    :: integer(),
	  version  :: v1 | v2,
	  key_size :: 1024|2048|4096,
	  blob     :: binary()
	}).

-record(state, 
	{
	  type :: undefined|port|uart,
	  handle :: port(),    %% port
	  device :: string(),  %% dev string or port name
	  blobs = [] :: [#blob{}] 
	}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link(?MODULE, [], []).

start_link(Name) ->
    gen_server:start_link({local, Name}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    process_flag(trap_exit, true),
    case application:get_env(ssh_agent, rsa_sign, {port,"rsa_sign"}) of
	{port,Driver} ->
	    {ok,P} = port_open(Driver),
	    io:format("driver open ~s\n", [Driver]),
	    {ok,Blobs} = port_list(P),
	    {ok, #state { type = port,
			  handle = P,
			  device = Driver,
			  blobs = Blobs }, 10000};
	{uart,Device} ->
	    {ok,U} = uart_open(Device),
	    io:format("uart open ~s\n", [Device]),
	    {ok,Blobs} = uart_list(U),
	    {ok, #state { type = uart,
			  handle = U,
			  device = Device,
			  blobs = Blobs }, 10000}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call({list_blobs,Vsn}, _From, State) ->
    Blobs = [extern_blob(B) || B<-State#state.blobs, B#blob.version =:= Vsn ],
    {reply, {ok,Blobs}, State};
handle_call({raw_list_blobs,Vsn}, _From, State) ->
    case State#state.type of
	uart when State#state.handle =/= undefined ->
	    case uart_list(State#state.handle) of
		{ok,List} ->
		    Blobs = [extern_blob(B) || B <- List,
					       B#blob.version =:= Vsn ],
		    {reply, {ok,Blobs}, State};
		Error ->
		    {reply, Error, State}
	    end;
	port when State#state.handle =/= undefined ->
	    case port_list(State#state.handle) of
		{ok,List} ->
		    Blobs = [extern_blob(B) || B <- List,
					       B#blob.version =:= Vsn],
		    {reply, {ok,Blobs}, State};
		Error ->
		    {reply, Error, State}
	    end;
	_ ->
	    {reply, {error,ebadfd}, State}
    end;
handle_call({echo,Message}, _From, State) ->
    case State#state.type of
	uart when State#state.handle =/= undefined ->
	    Reply = uart_echo(State#state.handle, Message),
	    {reply, Reply, State};
	port when State#state.handle =/= undefined ->
	    Reply = port_echo(State#state.handle, Message),
	    {reply, Reply, State};
	_ ->
	    {reply, {error,ebadfd}, State}
    end;

handle_call({sign,Index,Message}, _From, State) ->
    case State#state.type of
	uart when State#state.handle =/= undefined ->
	    Reply = uart_sign(State#state.handle,Index,Message),
	    {reply, Reply, State};
	port when State#state.handle =/= undefined ->
	    Reply = port_sign(State#state.handle,Index,Message),
	    {reply, Reply, State};
	_ ->
	    {reply, {error,ebadfd}, State}
    end;
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    {reply, {error,bad_call}, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info({uart_error,U,Reason}, State)
  when U =:= State#state.handle ->
    if Reason =:= enxio ->
	    io:format("uart error ~p device ~s unplugged?", 
		      [Reason,State#state.device]),
	    uart:close(State#state.handle),
	    {noreply, State#state { handle = undefined }};
       true ->
	    lager:error("uart error ~p for device ~s", 
			[Reason,State#state.device]),
	    {noreply, State}
	    end;
handle_info({uart_closed,U}, State) when 
      U =:= State#state.handle ->
    io:format("uart device closed, will try again in ~p msecs.",
	      [never]), %% S#s.retry_interval]),
    %% S1 = reopen(S),
    {noreply, State#state { handle = undefined }};
    
handle_info(_Info, State) ->
    io:format("Got into ~w\n", [_Info]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, State) ->
    case State#state.type of
	uart when State#state.handle =/= undefined ->
	    uart:close(State#state.handle);
	port when State#state.handle =/= undefined ->
	    port_close(State#state.handle);
	_ ->
	    ok
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

extern_blob(B) ->
    {B#blob.index,B#blob.version,B#blob.key_size,B#blob.blob}.

uart_open(Device) ->
    case uart:open(Device, [{baud,9600},{mode,binary}]) of
	{ok,U} ->
	    uart:flush(U, both),
	    uart:setopts(U, [{packet,4},{active,true}]),
	    {ok,U};
	Error ->
	    Error
    end.

port_open(Name) ->
    Driver = filename:join(code:priv_dir(ssh_agent), Name),
    P=erlang:open_port({spawn,Driver}, [use_stdio,binary,eof,{packet,4}]),
    {ok,P}.


port_echo(Port, Message) ->
    true = erlang:port_command(Port,[0, Message]),
    receive
	{Port, {data,<<0,Data/binary>>}} ->
	    {ok,Data};
	{Port, {data,<<1,Error/binary>>}} ->
	    {error,Error};
	Other ->
	    io:format("Got other: ~p\n", [Other]),
	    {error,other}
    after 2000 ->
	    {error, timeout}
    end.

uart_echo(U, Message) ->
    ok = uart:send(U, [0, Message]),
    receive
	{uart, U, <<0,Data/binary>>} ->
	    {ok,Data};
	{uart, U, <<1,Error/binary>>} ->
	    {error,Error};
	Other ->
	    io:format("Got other: ~p\n", [Other]),
	    {error,other}
    after 2000 ->
	    {error, timeout}
    end.

%% list keys 
uart_list(U) ->
    ok = uart:send(U, <<1>>),
    receive
	{uart, U, <<0,N,Blobs/binary>>} ->
	    {ok,list_blobs(0, N, Blobs, [])};
	{uart, U, <<1,Error/binary>>} ->
	    {error,Error};
	Other ->
	    io:format("Got other: ~p\n", [Other]),
	    error
    after 3000 ->
	    {error, timeout}
    end.

port_list(P) ->
    true = port_command(P, <<1>>),
    receive
	{P, {data,<<0,N,Blobs/binary>>}} ->
	    {ok,list_blobs(0, N, Blobs, [])};
	{P, {data,<<1,Error/binary>>}} ->
	    {error,Error};
	Other ->
	    io:format("Got other: ~p\n", [Other]),
	    error
    after 3000 ->
	    {error, timeout}
    end.

list_blobs(_I, 0, <<>>, Acc) ->
    lists:reverse(Acc);
list_blobs(I, N, <<Size:32, VBlob:Size/binary,Rest/binary>>, Acc) ->
    case VBlob of
	<<1,Blob/binary>> ->
	    <<KeySize:32,_/binary>> = Blob,
	    B = #blob{index=I,version=v1,key_size=KeySize,blob=Blob},
	    list_blobs(I+1, N-1, Rest, [B|Acc]);
	<<2,Blob/binary>> ->
	    <<L1:32,_:L1/binary,L2:32,_:L2/binary,L3:32,MSB,_/binary>> = Blob,
	    KeySize = if MSB =:= 0 -> (L3-1)*8;
			 true -> L3*8
		      end,
	    B = #blob{index=I,version=v2,key_size=KeySize,blob=Blob},
	    list_blobs(I+1, N-1, Rest, [B|Acc])
    end.

uart_sign(U, Index, Data) ->
    M = iolist_to_binary(Data),
    MSize = byte_size(M),
    uart:setopts(U, [{packet,4}]),
    ok = uart:send(U, <<2, Index, MSize:32, M/binary>>),
    receive
	{uart,U,<<0,Len:32,Signature:Len/binary>>} ->
	    {ok,Signature};
	{uart,U,<<1,Error/binary>>} ->
	    {error,Error}
    after 20000 ->
	    {error, timeout}
    end.

port_sign(P, K, Data) ->
    M = iolist_to_binary(Data),
    MSize = byte_size(M),
    true = port_command(P, <<2, K, MSize:32, M/binary>>),
    receive
	{P, {data, <<0,Len:32,Signature:Len/binary>>}} ->
	    {ok,Signature};
	{P, {data, <<1,Error/binary>>}} ->
	    {error,Error}
    after 20000 ->
	    {error, timeout}
    end.
