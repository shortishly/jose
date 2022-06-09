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


-module(jose_jws_test).


-include_lib("eunit/include/eunit.hrl").


signature_test_() ->
    Payload = <<"{\"iss\":\"joe\",\r\n"
                " \"exp\":1300819380,\r\n"
                " \"http://example.com/is_root\":true}">>,

    {foreach,
     setup(),
     cleanup(),
     lists:map(

       t(fun jose_jws:sign/1),

       [{<<"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk">>,
         #{header => <<"{\"typ\":\"JWT\",\r\n"
                       " \"alg\":\"HS256\"}">>,
           payload => Payload,
           key => jose_jwk:use(
                    jose_jsx:read_file("test/jws/a.1.json"))}}])}.



verify_test_() ->
    {foreach,
     setup(),
     cleanup(),
     lists:map(
       t(fun jose_jws:verify/1),
       phrase_file:consult("test/jws/verify.terms"))}.


issue_verify_test_() ->
    Payload = <<"{\"iss\":\"joe\",\r\n"
                " \"exp\":1300819380,\r\n"
                " \"http://example.com/is_root\":true}">>,

    {foreach,
     setup(),
     cleanup(),
     lists:map(

       t(fun
             (Arg) ->
                 jose_jws:verify(Arg#{jws => jose_jws:issue(Arg)})
         end),

       [{true,
         #{header => <<"{\"typ\":\"JWT\",\r\n"
                       " \"alg\":\"HS256\"}">>,
           payload => Payload,
           key => jose_jwk:use(
                    jose_jsx:read_file("test/jws/a.1.json"))}},

        {true,
         #{header => <<"{\"alg\":\"RS256\"}">>,
           payload => Payload,
           key => jose_jwk:use(
                    jose_jsx:read_file("test/jws/a.2.json"))}},

        {true,
         #{header => <<"{\"alg\":\"ES256\"}">>,
           payload => Payload,
           key => jose_jwk:use(
                    jose_jsx:read_file("test/jws/a.3.json"))}},

        {true,
         #{header => <<"{\"alg\":\"ES512\"}">>,
           payload => Payload,
           key => jose_jwk:use(
                    jose_jsx:read_file("test/jws/a.3.json"))}}])}.


setup() ->
    fun () ->
            {ok, _} = application:ensure_all_started(jose)
    end.


cleanup() ->
    fun
        (_) ->
            application:stop(jose)
    end.


representation_test_() ->
    lists:map(

      t(fun (X) -> X end),

      [{[123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32,
         34, 97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125],

        "{\"typ\":\"JWT\",\r\n"
        " \"alg\":\"HS256\"}"},


       {[123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
         32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
         48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
         109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
         111, 116, 34, 58, 116, 114, 117, 101, 125],

        "{\"iss\":\"joe\",\r\n"
        " \"exp\":1300819380,\r\n"
        " \"http://example.com/is_root\":true}"},


      {[101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81,
        105, 76, 65, 48, 75, 73, 67, 74, 104, 98, 71, 99, 105, 79, 105, 74,
        73, 85, 122, 73, 49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99, 51,
        77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67,
        74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84,
        107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100,
        72, 65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76,
        109, 78, 118, 98, 83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73,
        106, 112, 48, 99, 110, 86, 108, 102, 81],

       "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
       "."
       "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
       "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"}]).

t(F) ->
    fun
        ({Expected, Input} = Test) ->
            {nm(Test), ?_assertEqual(Expected, F(Input))}
    end.


nm(Test) ->
    iolist_to_binary(io_lib:fwrite("~p", [Test])).
