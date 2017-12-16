open Sodium

type secret
type public = Sign.public_key

type 'a key

val key : 'a key -> 'a

val pp : Format.formatter -> _ key -> unit

val of_seed : Sign.seed -> secret key
val neuterize : _ key -> public key

val derive : 'a key -> Int32.t -> 'a key
val derive_path : 'a key -> Int32.t list -> 'a key
