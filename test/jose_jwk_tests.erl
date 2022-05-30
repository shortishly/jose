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


-module(jose_jwk_tests).


-include_lib("eunit/include/eunit.hrl").


use_test_() ->
    lists:map(

      t(fun
            (Filename) ->
                jose_jwk:use(jose_jsx:read_file(Filename))
        end),

      [{#{kty => oct,
          k => <<3,35,53,75,43,15,165,188,131,126,6,101,119,123,166,143,
                 90,179,40,230,240,84,201,40,169,15,132,178,210,80,46,
                 191,211,251,90,146,210,6,71,239,150,138,180,195,119,98,
                 61,34,61,46,33,114,5,46,79,8,192,205,154,245,103,208,
                 128,163>>},

        "test/jwk/example-002.json"}]).


public_encrypt_private_decrypt_test_() ->
    PlainText = "Hello World!",

    lists:map(

      t(fun
            ({ClearText, Filename}) ->
                Key = jose_jwk:use(jose_jsx:read_file(Filename)),

                CipherText = jose_jwk:public_encrypt(
                               #{key => Key,
                                 plain_text => list_to_binary(ClearText)}),

                binary_to_list(
                  jose_jwk:private_decrypt(
                    #{key => Key,
                      cipher_text => CipherText}))
        end),

      [{PlainText, {PlainText, "test/jwe/a1.3-rsa-public-key.json"}}]).


private_encrypt_public_decrypt_test_() ->
    PlainText = "Hello World!",

    lists:map(

      t(fun
            ({ClearText, Filename}) ->
                Key = jose_jwk:use(jose_jsx:read_file(Filename)),

                CipherText = jose_jwk:private_encrypt(
                               #{key => Key,
                                 plain_text => list_to_binary(ClearText)}),

                binary_to_list(
                  jose_jwk:public_decrypt(
                    #{key => Key,
                      cipher_text => CipherText}))
        end),

      [{PlainText, {PlainText, "test/jwe/a1.3-rsa-public-key.json"}}]).


t(F) ->
    fun
        ({Expected, Input} = Test) ->
            {nm(Test), ?_assertEqual(Expected, F(Input))}
    end.


nm(Test) ->
    iolist_to_binary(io_lib:fwrite("~p", [Test])).
