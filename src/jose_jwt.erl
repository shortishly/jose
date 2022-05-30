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


-export([issue/1]).
-export_type([header/0]).
-export_type([registered_claim_names/0]).


-type header() :: #{typ => binary(), cty => binary()}.


-type registered_claim_names() :: #{iss => binary(),
                                    sub => binary(),
                                    aud => binary(),
                                    exp => pos_integer(),
                                    nbf => pos_integer(),
                                    iat => pos_integer(),
                                    jti => binary()}.


issue(#{header := Header, payload := Payload} = Arg) ->
    iolist_to_binary(
      lists:join(".",
                 [jose_base64url:encode(Header),
                  jose_base64url:encode(Payload),
                  jose_jws:sign(Arg)])).
