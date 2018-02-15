-module(two_prime).
-compile(export_all).

-define(P1, 4205092373).
-define(P2, 2648892151).
-define(N, 11138836181069664323).  %% N  = P1*P2 
-define(L, 11138836174215679800).  %% L = (P1-1)*(P2-1)
-define(E, 65537).                 %% public exponent
-define(D, 8048237016610999673).   %% private exponent, D = modinv(E,L)
%%
%% Message = <<"HELLO",0,0,0>> = 5207652434750472192
%%
-define(M,    5207652434750472192).
-define(MDN,  1783597635534869275).  %% M^D mod N (encrypted)

-define(MDP1, 1797691939).           %% M^D mod P1
-define(MDP2, 882983471).            %% M^D mod P2

test() ->
    P1 = ?P1,                %% prime1 (private)
    P2 = ?P2,                %% prime2 (private)
    N  = ?N,
    N  = P1*P2,              %% calculate modulus
    L  = ?L,
    L  = (P1-1)*(P2-1),      %% calculate phi
    E  = ?E,                 %% public exponent (fixed selected)
    D = ?D,
    D = imath:invert(E, L),  %% calculate private exponent
    M = ?M,
    MDN = ?MDN,
    MDN = imath:pow(M, D, N), %% encrypted message M
    
    %% calculate MDN using CRT
    MDP1 = ?MDP1,
    MDP1 = imath:pow(M, D, P1),

    MDP2 = ?MDP2,
    MDP2 = imath:pow(M, D, P2),
    MDN = powmod_two_prime(M, D, P1, P2),

    %% calculate MDN using fermants little and CRT
    MDP1 = powmod_prime(M, D, P1),   %% m^(d/p1+D%p1) = M^D (mod p1)
    MDP2 = powmod_prime(M, D, P2),   %% m^(d/p2+D%p2) = M^D (mod p2)

    io:format("N=~w\n", [N]),
    MDN.

powmod_two_prime(M, D, P1, P2) ->
    A1 = powmod_prime(M, D, P1),
    A2 = powmod_prime(M, D, P2),
    {1,{M1,M2}} = imath:egcd(P1, P2),
    N = P1*P2,
    %% io:format("A1=~w,M2=~w,P2=~w\n", [A1,M2,P2]),
    %% io:format("A2=~w,M1=~w,P1=~w\n", [A2,M1,P1]),
    imath:mod(A1*M2*P2 + A2*M1*P1, N).

powmod_prime(M, D, P) ->
    D0 = D div P,
    D1 = D rem P,
    %% io:format("P=~w, D=~w, D0=~w, D1=~w, D0+D1=~w\n", [P,D,D0,D1,D0+D1]),
    R = imath:pow(M, D0+D1, P),
    %% A = imath:pow(M, D0, P),
    %% B = imath:pow(M, D1, P),
    %% R = (A*B rem P),
    R.
