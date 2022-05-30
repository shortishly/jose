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


-module(jose_jwk).


-export([callback_mode/0]).
-export([init/1]).
-export([kty/1]).
-export([private_decrypt/1]).
-export([private_encrypt/1]).
-export([private_key/1]).
-export([public_decrypt/1]).
-export([public_encrypt/1]).
-export([public_key/1]).
-export([start_link/0]).
-export([use/1]).
-export_type([key/0]).
-include_lib("kernel/include/logger.hrl").
-include_lib("public_key/include/public_key.hrl").


start_link() ->
    gen_statem:start_link({local, ?MODULE}, ?MODULE, [], []).


init([]) ->
    ?MODULE = ets:new(?MODULE, [named_table]),
    ets:insert_new(
      ?MODULE,
      lists:map(
        fun
            (#{name := Name} = Definition) ->
                {{kty, Name}, maps:without([name], Definition)}
        end,
        jose_exprs:consult("priv/jwa/jwk-kty.terms"))),
    {ok, ready, #{}}.


callback_mode() ->
    handle_event_function.


kty(Name) ->
    lookup({?FUNCTION_NAME, Name}).


lookup(Name) ->
    case ets:lookup(?MODULE, Name) of
        [{_, Definition}] ->
            Definition;

        [] ->
            error(badarg, [Name])
    end.


-type key() :: symetric().

-type symetric() :: #{kty := oct, k := binary(), alg => binary()}.


use(#{<<"kty">> := KTY} = Arg) ->
    maps:fold(from_json(KTY),
              #{kty => binary_to_atom(string:lowercase(KTY))},
              maps:without([<<"kty">>], Arg));

use(#'RSAPrivateKey'{version = 'two-prime',
                     modulus = N,
                     publicExponent = E,
                     privateExponent = D,
                     prime1 = P1,
                     prime2 = P2,
                     exponent1 = E1,
                     exponent2 = E2,
                     coefficient = C,
                     otherPrimeInfos = asn1_NOVALUE}) ->
    #{kty => rsa,
      e => E,
      n => N,
      d => D,
      p => P1,
      q => P2,
      dp => E1,
      dq => E2,
      qi => C};

use(#'RSAPublicKey'{modulus = N, publicExponent = E}) ->
    #{kty => rsa, e => E, n => N};


use({#'ECPoint'{point = <<4, X:256/bits, Y:256/bits>>}, {namedCurve, Curve}}) ->
    #{kty => ec,
      curve => pubkey_cert_records:namedCurves(Curve),
      x => X,
      y => Y};

use({#'ECPoint'{point = <<4, X:384/bits, Y:384/bits>>}, {namedCurve, Curve}}) ->
    #{kty => ec,
      curve => pubkey_cert_records:namedCurves(Curve),
      x => X,
      y => Y};

use({#'ECPoint'{point = <<4, X:528/bits, Y:528/bits>>}, {namedCurve, Curve}}) ->
    #{kty => ec,
      curve => pubkey_cert_records:namedCurves(Curve),
      x => X,
      y => Y};

use(#'ECPrivateKey'{privateKey = <<D:256/bits>>,
                    parameters = {namedCurve, Curve},
                    publicKey = <<4, X:256/bits, Y:256/bits>>}) ->
    #{kty => ec,
      curve => pubkey_cert_records:namedCurves(Curve),
      d => D,
      x => X,
      y => Y};

use(#'ECPrivateKey'{privateKey = <<D:384/bits>>,
                    parameters = {namedCurve, Curve},
                    publicKey = <<4, X:384/bits, Y:384/bits>>}) ->
    #{kty => ec,
      curve => pubkey_cert_records:namedCurves(Curve),
      d => D,
      x => X,
      y => Y};

use(#'ECPrivateKey'{privateKey = <<D:528/bits>>,
                    parameters = {namedCurve, Curve},
                    publicKey = <<4, X:528/bits, Y:528/bits>>}) ->
    #{kty => ec,
      curve => pubkey_cert_records:namedCurves(Curve),
      d => D,
      x => X,
      y => Y}.


private_key(#{kty := rsa,
              e := E,
              n := N,
              d := D,
              p := P1,
              q := P2,
              dp := E1,
              dq := E2,
              qi := C}) ->
    [E, N, D, P1, P2, E1, E2, C];

private_key(#{kty := rsa, e := E, n := N, d := D}) ->
    [E, N, D];

private_key(#{kty := ec, d := <<D:256/bits>>}) ->
    [D, secp256r1];

private_key(#{kty := ec, d := <<D:384/bits>>}) ->
    [D, secp384r1];

private_key(#{kty := ec, d := <<D:528/bits>>}) ->
    [D, secp521r1].


public_key(#{kty := rsa, e := E, n := N}) ->
    [E, N];

public_key(#{kty := ec, x := <<X:256/bits>>, y := <<Y:256/bits>>}) ->
    [<<4, X/bits, Y/bits>>, secp256r1];

public_key(#{kty := ec, x := <<X:384/bits>>, y := <<Y:384/bits>>}) ->
    [<<4, X/bits, Y/bits>>, secp384r1];

public_key(#{kty := ec, x := <<X:528/bits>>, y := <<Y:528/bits>>}) ->
    [<<4, X/bits, Y/bits>>, secp521r1].


pk_encrypt_decrypt_opts(#{key := #{kty := rsa}}) ->
    [].


public_encrypt(#{key := Key, plain_text := PlainText} = Arg) ->
    crypto:public_encrypt(rsa,
                          PlainText,
                          public_key(Key),
                          pk_encrypt_decrypt_opts(Arg)).


private_encrypt(#{key := Key, plain_text := PlainText} = Arg) ->
    crypto:private_encrypt(rsa,
                           PlainText,
                           private_key(Key),
                           pk_encrypt_decrypt_opts(Arg)).


public_decrypt(#{key := Key, cipher_text := CipherText} = Arg) ->
    crypto:public_decrypt(rsa,
                          CipherText,
                          public_key(Key),
                          pk_encrypt_decrypt_opts(Arg)).


private_decrypt(#{key := Key, cipher_text := CipherText} = Arg) ->
    crypto:private_decrypt(rsa,
                           CipherText,
                           private_key(Key),
                           pk_encrypt_decrypt_opts(Arg)).


from_json(<<"RSA">>) ->
    fun
        (K, V, A) when K == <<"n">>;
                       K == <<"e">>;
                       K == <<"p">>;
                       K == <<"q">>;
                       K == <<"dp">>;
                       K == <<"dq">>;
                       K == <<"qi">>;
                       K == <<"d">> ->
            A#{binary_to_atom(K) => jose_base64url:decode(V)};

        (_, _, A) ->
            A
    end;

from_json(<<"EC">>) ->
      fun
          (K, V, A) when K == <<"crv">> ->
              A#{binary_to_atom(K) => V};


          (K, V, A) when K == <<"x">>;
                         K == <<"y">>;
                         K == <<"d">> ->
              A#{binary_to_atom(K) => jose_base64url:decode(V)};

          (_, _, A) ->
              A
      end;

from_json(<<"oct">>) ->
    fun
        (<<"k">> = K, V, A) ->
            A#{binary_to_atom(K) => jose_base64url:decode(V)};

        (<<"alg">> = K, V, A) ->
            A#{binary_to_atom(K) => V};

          (_, _, A) ->
              A
      end.
