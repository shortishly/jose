%% Copyright (c) 2022 Peter Morgan <peter.james.morgan@gmail.com>
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.


-module(jose_jwe).


-export([alg/1]).
-export([callback_mode/0]).
-export([enc/1]).
-export([init/1]).
-export([start_link/0]).
-include_lib("kernel/include/logger.hrl").


start_link() ->
    gen_statem:start_link({local, ?MODULE}, ?MODULE, [], []).


init([]) ->
    ?MODULE = ets:new(?MODULE, [named_table]),

    true = ets:insert_new(
             ?MODULE,
             lists:append(
               lists:map(
                 prefix(alg),
                 jose_exprs:consult("priv/jwa/jwe-alg.terms")),

               lists:map(
                 prefix(enc),
                 jose_exprs:consult("priv/jwa/jwe-enc.terms")))),

    {ok, ready, #{}}.


prefix(Prefix) ->
    fun
        (#{name := Name} = Definition) ->
            {{Prefix, Name}, maps:without([name], Definition)}
    end.


callback_mode() ->
    handle_event_function.


alg(Name) ->
    lookup({?FUNCTION_NAME, Name}).


enc(Name) ->
    lookup({?FUNCTION_NAME, Name}).


lookup(Name) ->
    case ets:lookup(?MODULE, Name) of
        [{_, Definition}] ->
            Definition;

        [] ->
            error(badarg, [Name])
    end.
