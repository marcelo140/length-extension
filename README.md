# Length extension attack

WIP.
Tool to perform length extension attacks on SHA-256 digests. 

#### Transforming the digest in 32-bytes
Elixir really works well with binaries. This is how I actually got the results to assure digest\_to\_state was working properly.
```elixir
> b = Base.decode16!("dc83f83e509a65d36e1dc2a5228df34539c60db474c966f99d7a16f28696b703", case: :lower)                           
<<220, 131, 248, 62, 80, 154, 101, 211, 110, 29, 194, 165, 34, 141, 243, 69, 57,
  198, 13, 180, 116, 201, 102, 249, 157, 122, 22, 242, 134, 150, 183, 3>>

> <<a1::32-integer,a2::32-integer,a3::32-integer,a4::32-integer,a5::32-integer,a6::32-integer,a7::32-integer,a8::32-integer>> = b
<<220, 131, 248, 62, 80, 154, 101, 211, 110, 29, 194, 165, 34, 141, 243, 69, 57,
  198, 13, 180, 116, 201, 102, 249, 157, 122, 22, 242, 134, 150, 183, 3>>

> [a1,a2,a3,a4,a5,a6,a7,a8]
[3699636286, 1352295891, 1847444133, 579728197, 969280948, 1959356153, 2642024178, 2258024195]
```

