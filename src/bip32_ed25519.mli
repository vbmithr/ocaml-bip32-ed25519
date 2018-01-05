module type CRYPTO = sig
  val sha256 : Cstruct.t -> Cstruct.t
  val hmac_sha512 : key:Cstruct.t -> Cstruct.t -> Cstruct.t
end

open Tweetnacl

type _ key

val key : 'a key -> 'a
val equal : 'a Sign.key key -> 'a Sign.key key -> bool

val pp : Format.formatter -> _ key -> unit

val of_seed :
  (module CRYPTO) -> Cstruct.t -> Sign.extended Sign.key key
val neuterize : _ Sign.key key -> Sign.public Sign.key key

val derive :
  (module CRYPTO) -> 'a key -> Int32.t -> 'a key
val derive_path :
  (module CRYPTO) -> 'a key -> Int32.t list -> 'a key

val hardened : Int32.t -> bool
val of_hardened : Int32.t -> Int32.t
val to_hardened : Int32.t -> Int32.t

module Human_readable : sig
  type t = Int32.t list

  val of_string_exn : string -> t
  val of_string : string -> t option
  val to_string : t -> string
  val pp : Format.formatter -> t -> unit
end
