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


-module(jose_jws).


-export([callback_mode/0]).
-export([init/1]).
-export([issue/1]).
-export([none/1]).
-export([sign/1]).
-export([start_link/0]).
-export([verify/1]).
-include_lib("kernel/include/logger.hrl").
-include_lib("public_key/include/public_key.hrl").


start_link() ->
    gen_statem:start_link({local, ?MODULE}, ?MODULE, [], []).


none(_) ->
    <<>>.


init([]) ->
    ?MODULE = ets:new(?MODULE, [named_table]),
    true = ets:insert_new(
             ?MODULE,
             lists:map(
               prefix(alg),
               jose_exprs:consult("priv/jwa/jws-alg.terms"))),
    {ok, ready, #{}}.


prefix(Prefix) ->
    fun
        (#{name := Name} = Definition) ->
            {{Prefix, Name}, maps:without([name], Definition)}
    end.


callback_mode() ->
    handle_event_function.


-spec issue(#{header := binary(),
              payload := binary(),
              key := jose_jwk:key()}) -> binary().

issue(#{header := Header, payload := Payload} = Arg) ->
    iolist_to_binary(
      lists:join(".",
                 [jose_base64url:encode(Header),
                  jose_base64url:encode(Payload),
                  sign(Arg)])).


verify(#{jws := JWS} = Arg) ->
    case binary:split(JWS, <<".">>, [global]) of
        [Header, Payload, Signature] ->
            verify_secure(
              maps:merge(
                Arg#{header => Header,
                   payload => Payload,
                   signature => Signature},
              algorithm(jose_base64url:decode(Header))));

        [Header, Payload] ->
            verify_insecure(Arg#{header => Header, payload => Payload})
    end.


verify_insecure(#{header := Header}) ->
    #{<<"alg">> := Alg} = jsx:decode(jose_base64url:decode(Header)),
    Alg == <<"none">>.


verify_secure(#{key := #{kty := KTY} = Key,
                verify := Verify,
                options := Options,
                a := [Type, Subtype]} = Arg) when KTY == rsa; KTY == ec ->
    Verify(Type,
           Subtype,
           verify_msg(Arg),
           verify_signature_encode(Arg),
           jose_jwk:public_key(Key),
           Options);

verify_secure(#{key := #{kty := oct, k := Key},
                sign := Sign,
                signature := Signature,
                a := [Type, Subtype]} = Arg) ->
    Signature == jose_base64url:encode(
                   Sign(Type,
                        Subtype,
                        Key,
                        verify_msg(Arg))).


verify_msg(#{header := Header, payload := Payload}) ->
    iolist_to_binary([Header, ".", Payload]).


verify_signature_encode(#{key := #{kty := rsa}, signature := Signature}) ->
    jose_base64url:decode(Signature);
verify_signature_encode(#{key := #{kty := ec}, signature := Signature}) ->
    der_encode_ecdsa_sig_value(jose_base64url:decode(Signature)).


der_encode_ecdsa_sig_value(Signature) ->
    Size = bit_size(Signature) div 2,
    <<R:Size/integer, S:Size/integer>> = Signature,
    public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r = R, s = S}).


sign_signature_decode(#{key := #{kty := rsa}}, Signature) ->
    Signature;
sign_signature_decode(#{key := #{kty := ec}}, Signature) ->
    der_decode_ecdsa_sig_value(Signature).


der_decode_ecdsa_sig_value(Signature) ->
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode(
                                         'ECDSA-Sig-Value',
                                         Signature),
    iolist_to_binary([binary:encode_unsigned(X) || X <- [R, S]]).



-spec sign(#{header := binary(),
             payload := binary(),
             key => jose_jwk:key()}) -> binary().

sign(#{header := Header} = Arg) ->
    ?LOG_DEBUG(#{arg => Arg}),
    sign_with(maps:merge(Arg, algorithm(Header))).


sign_with(#{key := #{kty := KTY} = Key,
            header := Header,
            payload := Payload,
            sign := Sign,
            a := [Type, Subtype],
            options := Options} = Arg) when KTY == rsa; KTY == ec ->
    jose_base64url:encode(
      sign_signature_decode(
        Arg,
        Sign(
          Type,
          Subtype,
          signing_input_value(Header, Payload),
          jose_jwk:private_key(Key),
          Options)));

sign_with(#{key := #{kty := oct, k:= Key},
            header := Header,
            payload := Payload,
            sign := Sign,
            a := [Type, Subtype]}) ->
    jose_base64url:encode(
      Sign(Type, Subtype, Key, signing_input_value(Header, Payload)));

sign_with(#{sign := _}) ->
    <<>>.


signing_input_value(Header, Payload) ->
    iolist_to_binary([jose_base64url:encode(Header),
                      ".",
                      jose_base64url:encode(Payload)]).


algorithm(Header) ->
    #{<<"alg">> := Alg} = jsx:decode(Header),
    #{algorithm := Algorithm} = alg(binary_to_list(Alg)),
    Algorithm.


alg(Name) ->
    lookup({?FUNCTION_NAME, Name}).


lookup(K) ->
    case ets:lookup(?MODULE, K) of
        [{_, Definition}] ->
            Definition;

        [] ->
            error(badarg, [K])
    end.
