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


-module(jose_jwt_tests).


-include_lib("eunit/include/eunit.hrl").


issue_test_() ->
    Payload = <<"{\"iss\":\"joe\",\r\n"
                " \"exp\":1300819380,\r\n"
                " \"http://example.com/is_root\":true}">>,

    {foreach,
     setup(),
     cleanup(),
     lists:map(
       t(fun jose_jwt:issue/1),

       [{<<"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
           ".",
           "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcG"
           "xlLmNvbS9pc19yb290Ijp0cnVlfQ"
           "."
           "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk">>,

         #{header => <<"{\"typ\":\"JWT\",\r\n"
                       " \"alg\":\"HS256\"}">>,
           payload => Payload,
           key => jose_jwk:use(
                    jsx:decode(
                      read_file("test/jwk/example-002.json")))}},


        {<<"eyJhbGciOiJub25lIn0"
           ".",
           "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcG"
           "xlLmNvbS9pc19yb290Ijp0cnVlfQ"
           ".">>,

         #{header => <<"{\"alg\":\"none\"}">>,
           payload => Payload}}])}.


read_file(Filename) ->
    {ok, B} = file:read_file(Filename),
    B.


setup() ->
    fun () ->
            {ok, _} = application:ensure_all_started(jose)
    end.


cleanup() ->
    fun
        (_) ->
            application:stop(jose)
    end.


t(F) ->
    fun
        ({Expected, Input} = Test) ->
            {nm(Test), ?_assertEqual(Expected, F(Input))}
    end.


nm(Test) ->
    iolist_to_binary(io_lib:fwrite("~p", [Test])).
