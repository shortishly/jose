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


-module(jose_jwt).


-export([callback_mode/0]).
-export([init/1]).
-export([issue/1]).
-export([start_link/0]).
-export([verify/1]).
-export_type([claim/0]).
-export_type([header/0]).
-include_lib("kernel/include/logger.hrl").


-type header() :: #{typ => binary(), cty => binary()}.

-type claim() :: registered_claim()
               | public_claim()
               | private_claim().

-type registered_claim() :: issuer_claim()
                          | subject_claim()
                          | audience_claim()
                          | expiration_claim()
                          | not_before_claim()
                          | issued_at_claim()
                          | jwt_id_claim().

-type issuer_claim() :: iss.
-type subject_claim() :: sub.
-type audience_claim() :: aud.
-type expiration_claim() :: exp.
-type not_before_claim() :: nbf.
-type issued_at_claim() :: iat.
-type jwt_id_claim() :: jti.

-type public_claim() :: any().

-type private_claim() :: any().


verify(#{jwt := JWT} = Arg) ->
    case binary:split(JWT, <<".">>, [global]) of

        %%
        %% JWT represented by JWE Compact Seralization
        %%
        [_Header, _EncryptedKey, _IV, _CipherText, _AuthenticationTag] ->
            error(not_implemented);

        %%
        %% JWT represented by JWS Compact Seralization
        %%
        [Header, Payload, _Signature] ->
            verify_header(jsx:decode(jose_base64url:decode(Header)))
                andalso
                verify_payload(jsx:decode(jose_base64url:decode(Payload)))
                andalso
                jose_jws:verify(maps:without([jwt], Arg#{jws => JWT}))
    end.

verify_header(_Header) -> true.

verify_payload(Payload) ->
    Now = os:system_time(second),
    lists:all(
      fun
          ({<<"exp">>, ExpirationTime}) ->
              is_integer(ExpirationTime) andalso Now =< ExpirationTime;

          ({<<"iat">>, IssuedAtTime}) ->
              is_integer(IssuedAtTime) andalso Now >= IssuedAtTime;

          ({<<"aud">>, _}) ->
              true;

          ({<<"iss">>, _}) ->
              true;

          ({<<"sub">>, _}) ->
              true;

          ({<<"nbf">>, NotBefore}) ->
              is_integer(NotBefore) andalso Now >= NotBefore
      end,
      maps:to_list(Payload)).


issue(Arg) ->
    ?LOG_DEBUG(#{arg => Arg}),
    jose_jws:issue(Arg).


start_link() ->
    gen_statem:start_link({local, ?MODULE}, ?MODULE, [], []).


callback_mode() ->
    handle_event_function.


init([]) ->
    ?MODULE = ets:new(?MODULE, [named_table]),
    {ok, CSV} = file:read_file("priv/jwt/claims.csv"),

    [_Header | T] = binary:split(CSV, <<"\r\n">>, [global, trim_all]),

    true = ets:insert_new(
             ?MODULE,
             lists:map(
               fun
                   (Row) ->
                       [Name, Description | _] = binary:split(
                                                   Row, <<",">>, [global]),
                       {{claim, Name}, Description}
               end,
               T)),

    {ok, ready, #{}}.
