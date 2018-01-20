(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

module type CRYPTO = sig
  val sha256 : Cstruct.t -> Cstruct.t
  val hmac_sha512 : key:Cstruct.t -> Cstruct.t -> Cstruct.t
  val blake2b : size:int -> Cstruct.t -> Cstruct.t
end

open Tweetnacl

type _ kind
type 'a key = private {
  depth : int ;
  parent_fp : Cstruct.t ;
  i : Int32.t ;
  k : 'a kind ;
  c : Cstruct.t ;
}

val equal : 'a Sign.key key -> 'a Sign.key key -> bool
val pp : Format.formatter -> _ key -> unit

(** {2 Accessors} *)

val depth : 'a key -> int
val parent_fingerprint : 'a key -> Cstruct.t
val child_number : 'a key -> Int32.t
val key : 'a key -> 'a
val chaincode : 'a key -> Cstruct.t

(** {2 Creation} *)

val random : (module CRYPTO) -> Cstruct.t * Sign.extended Sign.key key
val of_seed : (module CRYPTO) -> ?pos:int -> Cstruct.t -> Sign.extended Sign.key key option
val of_seed_exn : (module CRYPTO) -> ?pos:int -> Cstruct.t -> Sign.extended Sign.key key
val of_pk : ?pos:int -> Cstruct.t -> Sign.public Sign.key key option
val of_pk_exn : ?pos:int -> Cstruct.t -> Sign.public Sign.key key
val of_ek : ?pos:int -> Cstruct.t -> Sign.extended Sign.key key option
val of_ek_exn : ?pos:int -> Cstruct.t -> Sign.extended Sign.key key

(** {2 Serialization} *)

val ek_bytes : int
val pk_bytes : int
val write : ?pos:int -> _ Sign.key key -> Cstruct.t -> int
val to_bytes : _ Sign.key key -> Cstruct.t

(** {2 Operation} *)

val neuterize : _ Sign.key key -> Sign.public Sign.key key

val derive :
  (module CRYPTO) -> 'a key -> Int32.t -> 'a key option
val derive_exn :
  (module CRYPTO) -> 'a key -> Int32.t -> 'a key

val derive_path :
  (module CRYPTO) -> 'a key -> Int32.t list -> 'a key option
val derive_path_exn :
  (module CRYPTO) -> 'a key -> Int32.t list -> 'a key

val hardened : Int32.t -> bool
val of_hardened : Int32.t -> Int32.t
val to_hardened : Int32.t -> Int32.t

(** {2 Path IO} *)

module Human_readable : sig
  type t = Int32.t list

  val of_string_exn : string -> t
  val of_string : string -> t option
  val to_string : t -> string
  val pp : Format.formatter -> t -> unit
end

(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  ---------------------------------------------------------------------------*)
