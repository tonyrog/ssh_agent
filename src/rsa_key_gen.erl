%%
%% Dump SSH prvate keys as C code
%%
%% - generate test keys with:
%%   ssh-keygen -t rsa -b <size> -f key_<size>
%%
-module(rsa_key_gen).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").

-define(UINT32(X),   (X):32/unsigned-big-integer).
-define(STRING(X),   ?UINT32((size(X))), (X)/binary).
-define(BINARY(X),   ?UINT32((size(X))),(X)/binary ).

-define(DEXP, 16).  %% digit size = 16 bit

-export([test/0, test/1, test/2, test/3]).
-export([generate/0]).
-export([load_private_ssh_key/1, load_private_ssh_key/2]).
-export([load_public_ssh_key/1]).
-export([sign/2]).
-export([native_sign/2]).

-export([rsasp1/2]).
-export([rsassa_pkcs1_v1_5_sign/2]).
-export([dump_message/2, dump_message/3]).
-export([dump_private_key/1]).
-export([agent_encode/1]).

-compile(export_all).

test() -> 
    test(<<"Hello world">>).
test(Data) -> 
    KeyFile = filename:join([code:lib_dir(ssh_agent),"test","key_1024"]),
    test(KeyFile, Data).
test(KeyFile, Data) -> 
    test("abc123", KeyFile, Data).
test(Password, KeyFile, Data) ->
    Key = load_private_ssh_key(Password, KeyFile),
    A = sign(Key, Data),
    B = native_sign(Key, Data),
    {A=:=B, A, B}.

native_sign(Key, Data) ->
    B = public_key:sign(Data, sha, Key),
    io:format("S[~w] = ~s\n", [byte_size(B)*8, hex(B)]),
    B.

print_private_key(#'RSAPrivateKey'{privateExponent=D,
				   modulus=N}) ->
    DSize = (isize(D)+7) div 8,
    NSize = (isize(N)+7) div 8,
    io:format("D = ~s\n", [hex(i2bin(D, DSize))]),
    io:format("N = ~s\n", [hex(i2bin(N, NSize))]).

generate() ->
    KeyDir = filename:join([code:lib_dir(ssh_agent),"test"]),
    K1024 = load_private_ssh_key(filename:join(KeyDir,"key_1024")),
    dump_private_key("key_1024.h", K1024),
    K2048 = load_private_ssh_key(filename:join(KeyDir,"key_2048")),
    dump_private_key("key_2048.h", K2048),
    K4096 = load_private_ssh_key(filename:join(KeyDir,"key_4096")),
    dump_private_key("key_4096.h", K4096),

    dump_message("message_1024.h", 1024, <<"Hello world">>),
    dump_message("message_2048.h", 2048, <<"Hello world">>),
    dump_message("message_4096.h", 4096, <<"Hello world">>),
    ok.

%% rsa only!
%% load_private_key(Password) ->
%%    ssh_file:user_key('ssh-rsa', [{rsa_pass_phrase,Password}]).

%% load ssh public key (test)
load_public_ssh_key(File) ->
    {ok,Public} = file:read_file(File),
    pubkey_ssh:decode(Public, public_key).

%% test version
load_private_ssh_key(File) when is_list(File) ->
    load_private_ssh_key("abc123", File).
    
load_private_ssh_key(Password,File) when 
      is_list(Password), is_list(File) ->
    {ok,Private} = file:read_file(File),
    case public_key:pem_decode(Private) of
	[{_, _, not_encrypted} = Entry]  -> 
	    public_key:pem_entry_decode(Entry);
	[Entry] ->
	    public_key:pem_entry_decode(Entry, Password)    
    end.

agent_encode(Signature) when is_binary(Signature) ->
    <<?STRING(<<"ssh-rsa">>), ?BINARY(Signature)>>.

%% Dump as C code to be used in agentuino
dump_private_key(File, PrivateKey) ->
    case file:open(File, [write]) of
	{ok,Fd} ->
	    Base = filename:basename(File, ".h"),
	    dump_private_key_(Fd, Base, PrivateKey),
	    file:close(Fd);
	Error ->
	    Error
    end.
    
dump_private_key(PrivateKey) ->
    dump_private_key_(user, "key", PrivateKey).

dump_private_key_(Fd,Base,
		  #'RSAPrivateKey'{modulus = N, 
				   prime1 = P1,
				   prime2 = P2,
				   privateExponent = D,
				   publicExponent = E }) ->
    io:format(Fd,"// privateExponent D\n", []),
    io:format(Fd,"~s;\n",[integer_as_digit_array(Base++"_d",D,?DEXP)]),
    io:format(Fd,"// moduls N\n", []),
    io:format(Fd,"~s;\n",[integer_as_digit_array(Base++"_n",N,?DEXP)]),
    io:format(Fd,"// prime1 P1\n", []),
    io:format(Fd,"~s;\n",[integer_as_digit_array(Base++"_p1",P1,?DEXP)]),
    io:format(Fd,"// prime2 P2\n", []),
    io:format(Fd,"~s;\n",[integer_as_digit_array(Base++"_p2",P2,?DEXP)]),
    io:format(Fd,"// publicExponent E\n", []),
    io:format(Fd,"~s;\n",[integer_as_digit_array(Base++"_e",E,?DEXP)]),
    ok.

%% testing variouse messages
%% dump message using N bits (matchin key size!)
dump_message(File, N, Message) ->
    case file:open(File, [write]) of
	{ok,Fd} ->
	    dump_message_(Fd, N, Message),
	    file:close(Fd);
	Error ->
	    Error
    end.
    
dump_message(N, Message) ->
    dump_message_(user, N, Message).

dump_message_(Fd, N, Message) when is_integer(N) ->
    EM = emsa_pkcs1_v1_5_encode('id-sha1',Message, N),
    M = bin2i(EM),
    io:format(Fd, "~s;\n", [integer_as_digit_array("m_ds",M,?DEXP)]),
    ok.

sign(Key=#'RSAPrivateKey'{}, Data) ->
    rsassa_pkcs1_v1_5_sign(Key, Data).

rsassa_pkcs1_v1_5_sign(Key=#'RSAPrivateKey'{modulus=N},Message)->
    NSize = isize(N),
    EM = emsa_pkcs1_v1_5_encode('id-sha1',Message,NSize),
    M = bin2i(EM),
    S = rsasp1(Key, M),
    K = (NSize+7) div 8,
    i2bin(S, K).

rsasp1(#'RSAPrivateKey'{version='two-prime',
			modulus = N,
			prime1 = P1,
			prime2 = P2,
			privateExponent = D}, M) -> 
    ipow(M, D, N).
    %% ipow_two_prime(M, D, P1, P2).

integer_as_digit_array(Name,0,Size) -> 
    ["const digit_t ",Name,"[1]"," = ",digit_to_chex(0,Size)];
integer_as_digit_array(Name,N,Size) ->
    {Length,Array} = format_ds(N,Size,[]),
    ["const digit_t ",Name,"[",integer_to_list(Length),"]"," = ",Array].

integer_as_digit_array(0,Size) ->
    [${,digit_to_chex(0,Size),$}];
integer_as_digit_array(N,Size) ->
    format_ds(N,Size,[]).

format_ds(0, _Size, Acc) ->
    {length(Acc),[${,string:join(lists:reverse(Acc), ","),$}]};
format_ds(N, Size, Acc) ->
    B = digit_to_chex(N, Size),
    format_ds(N bsr Size, Size, [B|Acc]).

digit_to_chex(N, Size) ->
    K = (1 bsl Size),
    "0x"++tl(integer_to_list(K+(N band (K-1)), 16)). 

hex(Binary) when is_binary(Binary) ->
    [h(X) || <<X:4>> <= Binary].

h(X) when X >= 0, X =< 15 ->
    element(X+1, {$0,$1,$2,$3,$4,$5,$6,$7,$8,$9,$a,$b,$c,$d,$e,$f}).

emsa_pkcs1_v1_5_encode(Type,Message,N) ->
    K = (N+7) div 8,  %% K = number of bytes
    T = encode_digest(Type, Message),
    PS = fill_bits(K - byte_size(T) - 3, 16#ff),
    <<16#00, 16#01, PS/binary, 16#00, T/binary>>.

encode_digest(Name, Message) ->
    H = crypto:hash(name_to_hash_type(Name), Message),
    Prefix = pkcs1_v1_5_prefix(Name),
    <<Prefix/binary, H/binary>>.

%% this replaces the need for asn1 encode

pkcs1_v1_5_prefix('id-md5') ->
    <<16#30,16#20,16#30,16#0c,16#06,16#08,16#2a,
      16#86,16#48,16#86,16#f7,16#0d,16#02,16#05,
      16#05,16#00,16#04,16#10>>;
pkcs1_v1_5_prefix('id-sha1') ->
    <<16#30,16#21,16#30,16#09,16#06,16#05,16#2b,
      16#0e,16#03,16#02,16#1a,16#05,16#00,16#04,16#14>>;
pkcs1_v1_5_prefix('id-sha256') ->
    fixme;
pkcs1_v1_5_prefix('id-sha384') ->
    fixme;
pkcs1_v1_5_prefix('id-sha512') ->
    fixme;
pkcs1_v1_5_prefix('id-sha224') ->
    fixme;
pkcs1_v1_5_prefix(ID) -> %% generate others
    der_encode(ID).

der_encode(ID) ->
    Alg = #'AlgorithmNull' { algorithm = name_to_oid(ID),
			     parameters = <<>> },    
    Data = #'DigestInfoNull' { digestAlgorithm = Alg,
			       digest = <<>> },
    {Bytes,_Len} = enc_DigestInfoNull(Data),
    iolist_to_binary(Bytes).

name_to_oid('id-md2') -> {1,2,840,113549,2,2};
name_to_oid('id-md5') -> {1,2,840,113549,2,5};
name_to_oid('id-sha1') ->  {1,3,14,3,2,26};
name_to_oid('id-sha256') -> {2,16,840,1,101,3,4,2,1};
name_to_oid('id-sha384') -> {2,16,840,1,101,3,4,2,2};
name_to_oid('id-sha512') -> {2,16,840,1,101,3,4,2,3};
name_to_oid('id-sha224') -> {2,16,840,1,101,3,4,2,4}.

name_to_hash_type('id-md5')    -> md5;
name_to_hash_type('id-md2')    -> md2;
name_to_hash_type('id-sha1')   -> sha;
name_to_hash_type('id-sha224') -> sha224;
name_to_hash_type('id-sha256') -> sha256;
name_to_hash_type('id-sha384') -> sha384;
name_to_hash_type('id-sha512') -> sha512.

fill_bits(N,C) when N>=0 ->
    fill_(N,C).

fill_(0,_C) -> <<>>;
fill_(1,C) -> <<C>>;
fill_(N,C) ->
    Fill = fill_(N div 2, C),
    if N band 1 =:= 0 ->
	    <<Fill/binary,Fill/binary>>;
       true ->
	    <<C,Fill/binary,Fill/binary>>
    end.

%% Convert integer into binary 
i2bin(X, XLen) ->
    XSz = isize(X),
    Sz = XLen*8,
    if Sz < XSz -> 
	    exit(integer_to_large);
       true ->
	    (<<X:Sz/big-unsigned-integer>>)
    end.

%% Convert a binary into an integer
bin2i(X) when is_binary(X) ->
    Sz = byte_size(X)*8,
    <<Y:Sz/big-unsigned-integer>> = X,
    Y.

isize(N) when is_integer(N), N >= 0 ->
    isize_(N, 0).

isize_(N, Size) when N >= 16#10000000000000000 -> isize_(N bsr 64, Size+64);
isize_(N, Size) when N >= 16#100000000 -> isize_(N bsr 32, Size+32);
isize_(N, Size) when N >= 16#10000 -> isize_(N bsr 16, Size+16);
isize_(N, Size) when N >= 16#100 -> isize_(N bsr 8, Size+8);
isize_(N, Size) when N >= 16#10 -> isize_(N bsr 4, Size+4);
isize_(N, Size) -> %% 4 top bits 
    Size + 
	element(N+1,
		%% 0000 0001 0010 0011 0100 0101 0110 0111
		{  0,   1,   2,   2,   3,   3,   3,   3,
		%% 1000 1001 1010 1011 1100 1101 1110 1111
		   4,   4,   4,   4,   4,   4,   4,   4 }).

icount(N) when is_integer(N), N >= 0 ->
    icount_(N, 0).

icount_(0, Count) -> Count;
icount_(N, Count) -> %% 4 top bits 
    %% 0000 0001 0010 0011 0100 0101 0110 0111
    C = element((N band 16#f)+1,
    %% 0000 0001 0010 0011 0100 0101 0110 0111
    {  0,   1,   1,   2,   1,   2,   2,   3,
       1,   2,   2,   3,   2,   3,   3,   4 }),
    icount_(N bsr 4, Count+C).

%% calculate A^B mod P1*P2 (p1 and p2 prime)
ipow_two_prime(A, B, P1, P2) when P1 > 0, P2 > 0, B >= 0 ->
    A1 = ipow_mod_prime(A, B, P1),
    A2 = ipow_mod_prime(A, B, P2),
    {1, {M1,M2}} = imath:egcd(P1,P2),
    N = P1*P2,
    imath:mod(A1*M2*P2 + A2*M1*P1, N).

%% simplify A^B mod P by using fermats little:
%% A^P = A (mod P)  
%% Set B = kP + B' ( R = B rem P )
%% A^B = A^(kP+B') = A^(k+B') 
%% 
ipow_mod_prime(A, B, P) when P > 0, B >= 0 ->
    if A =:= 1 -> 1;
       true -> 
	    B1 = (B div P)+(B rem P),
	    ipow_(A, B1, P, 1)
    end.

%% calculate A^B mod M
ipow(A, B, M) when M > 0, B >= 0 ->
    if A =:= 1 -> 1;
       true -> ipow_(A, B, M, 1)
    end.
                                                                               
ipow_(A, 1, M, Prod) ->
    (A*Prod) rem M;
ipow_(_A, 0, _M, Prod) ->
    Prod;
ipow_(A, B, M, Prod)  ->
    B1 = B bsr 1,
    A1 = (A*A) rem M,
    if B - B1 == B1 ->
            ipow_(A1, B1, M, Prod);
       true ->
            ipow_(A1, B1, M, (A*Prod) rem M)
    end.

%% FIXME: convert this into inline C code for the future
enc_DigestInfoNull(Val) ->
    enc_DigestInfoNull(Val, [<<48>>]).

enc_DigestInfoNull(Val, TagIn) ->
    {_,Cindex1,Cindex2} = Val,
    {EncBytes1,EncLen1} = enc_AlgorithmNull(Cindex1, [<<48>>]),
    {EncBytes2,EncLen2} = encode_restricted_string(Cindex2, [<<4>>]),
    BytesSoFar = [EncBytes1, EncBytes2],
    LenSoFar = EncLen1 + EncLen2,
    encode_tags(TagIn, BytesSoFar, LenSoFar).

enc_AlgorithmNull(Val, TagIn) ->
    {_,Cindex1,Cindex2} = Val,
    {EncBytes1,EncLen1} = encode_object_identifier(Cindex1, [<<6>>]),
    {EncBytes2,EncLen2} = encode_null(Cindex2, [<<5>>]),
    BytesSoFar = [EncBytes1, EncBytes2],
    LenSoFar = EncLen1 + EncLen2,
    encode_tags(TagIn, BytesSoFar, LenSoFar).

encode_null(_Val, TagIn) ->
    encode_tags(TagIn, [], 0).

encode_object_identifier(Val, TagIn) ->
    encode_tags(TagIn, e_object_identifier(Val)).

e_object_identifier({'OBJECT IDENTIFIER',V}) ->
    e_object_identifier(V);
e_object_identifier(V) when is_tuple(V) ->
    e_object_identifier(tuple_to_list(V));
e_object_identifier([E1,E2|Tail]) ->
    Head = 40 * E1 + E2,
    {H,Lh} = mk_object_val(Head),
    {R,Lr} = lists:mapfoldl(fun enc_obj_id_tail/2, 0, Tail),
    {[H|R],Lh + Lr}.

enc_obj_id_tail(H, Len) ->
    {B,L} = mk_object_val(H),
    {B,Len + L}.

mk_object_val(0, Ack, Len) ->
    {Ack,Len};
mk_object_val(Val, Ack, Len) ->
    mk_object_val(Val bsr 7, [Val band 127 bor 128|Ack], Len + 1).

mk_object_val(Val) when Val =< 127 ->
    {[255 band Val],1};
mk_object_val(Val) ->
    mk_object_val(Val bsr 7, [Val band 127], 1).


encode_restricted_string(OctetList, TagIn) when is_binary(OctetList) ->
    encode_tags(TagIn, OctetList, byte_size(OctetList));
encode_restricted_string(OctetList, TagIn) when is_list(OctetList) ->
    encode_tags(TagIn, OctetList, length(OctetList)).

encode_tags(TagIn, {BytesSoFar,LenSoFar}) ->
    encode_tags(TagIn, BytesSoFar, LenSoFar).

encode_tags([Tag|Trest], BytesSoFar, LenSoFar) ->
    {Bytes2,L2} = encode_length(LenSoFar),
    encode_tags(Trest,
                [Tag,Bytes2|BytesSoFar],
                LenSoFar + byte_size(Tag) + L2);
encode_tags([], BytesSoFar, LenSoFar) ->
    {BytesSoFar,LenSoFar}.

encode_length(L) when L =< 127 ->
    {[L],1};
encode_length(L) ->
    Oct = minimum_octets(L),
    Len = length(Oct),
    if
        Len =< 126 ->
            {[128 bor Len|Oct],Len + 1};
        true ->
            exit({error,{asn1,too_long_length_oct,Len}})
    end.

minimum_octets(0, Acc) ->
    Acc;
minimum_octets(Val, Acc) ->
    minimum_octets(Val bsr 8, [Val band 255|Acc]).

minimum_octets(Val) ->
    minimum_octets(Val, []).
