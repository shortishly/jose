-module(jose_sup).


-behaviour(supervisor).
-export([init/1]).
-export([start_link/0]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    {ok, {#{}, children()}}.


children() ->
    [worker(jose_jwe),
     worker(jose_jwk),
     worker(jose_jws),
     worker(jose_jwt)].


worker(M) ->
    #{id => M, start => {M, start_link, []}}.
