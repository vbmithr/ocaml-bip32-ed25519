open Tweetnacl

type _ key

val key : 'a key -> 'a
val equal : 'a Sign.key key -> 'a Sign.key key -> bool

val pp : Format.formatter -> _ key -> unit

val of_seed : Cstruct.t -> Sign.extended Sign.key key
val neuterize : _ Sign.key key -> Sign.public Sign.key key

val derive : 'a key -> Int32.t -> 'a key
val derive_path : 'a key -> Int32.t list -> 'a key
