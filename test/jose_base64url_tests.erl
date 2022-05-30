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


-module(jose_base64url_tests).


-include_lib("eunit/include/eunit.hrl").


encode_test_() ->
    lists:map(

      t(fun
            (Unencoded) ->
                unicode:characters_to_list(jose_base64url:encode(Unencoded))
        end),

      [{"JC4wMg", "$.02"},


       {"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",

        "{\"typ\":\"JWT\",\r\n"
        " \"alg\":\"HS256\"}"},


       {"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",

        "{\"iss\":\"joe\",\r\n"
        " \"exp\":1300819380,\r\n"
        " \"http://example.com/is_root\":true}"},

       {"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ",
        "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}"},

       {"eyJhbGciOiJSUzI1NiJ9", "{\"alg\":\"RS256\"}"}]).


t(F) ->
    fun
        ({Expected, Input} = Test) ->
            {nm(Test), ?_assertEqual(Expected, F(Input))}
    end.


nm(Test) ->
    iolist_to_binary(io_lib:fwrite("~p", [Test])).
