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


-module(jose_jwk_set).


-export([read_file/1]).


read_file(Filename) ->
    #{<<"keys">> := Keys} = jose_jsx:read_file(Filename),
    lists:foldl(
      fun
          (#{<<"kid">> := KID} = Arg, A) ->
              A#{KID => jose_jwk:use(Arg)}
      end,
      #{},
      Keys).
