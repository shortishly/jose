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


-module(jose_pem).


-export([decode/1]).
-export([read_file/1]).


decode(PEM) ->
    case public_key:pem_decode(PEM) of
        [{'PrivateKeyInfo', _, not_encrypted} = Key] ->
            jose_jwk:use(public_key:pem_entry_decode(Key));

        [{'SubjectPublicKeyInfo', _, not_encrypted} = Key] ->
            jose_jwk:use(public_key:pem_entry_decode(Key))
    end.


read_file(Filename) ->
    {ok, PEM} = file:read_file(Filename),
    decode(PEM).
