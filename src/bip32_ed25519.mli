(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

module type CRYPTO = sig
  val sha256 : Bigstring.t -> Bigstring.t
  val hmac_sha512 : key:Bigstring.t -> Bigstring.t -> Bigstring.t
end

open Monocypher

type _ t

val wipe : _ Sign.key t -> unit
val equal : 'a Sign.key t -> 'a Sign.key t -> bool

(** {2 Accessors} *)

val key : 'a t -> 'a
val chaincode : _ t -> Bigstring.t

(** {2 Creation} *)

val random : (module CRYPTO) -> Bigstring.t * extended Sign.key t
val of_seed : (module CRYPTO) -> ?pos:int -> Bigstring.t -> extended Sign.key t option
val of_seed_exn : (module CRYPTO) -> ?pos:int -> Bigstring.t -> extended Sign.key t

(** {2 IO} *)

val ek_bytes : int
val pk_bytes : int

val unsafe_pk_of_bytes : ?pos:int -> Bigstring.t -> public Sign.key t
val pk_of_bytes : ?pos:int -> Bigstring.t -> public Sign.key t

val unsafe_ek_of_bytes : ?pos:int -> Bigstring.t -> extended Sign.key t
val ek_of_bytes : ?pos:int -> Bigstring.t -> extended Sign.key t

val blit_to_bytes : _ Sign.key t -> ?pos:int -> Bigstring.t -> int
val to_bytes : _ Sign.key t -> Bigstring.t

(** {2 Operation} *)

val neuterize : _ Sign.key t -> public Sign.key t

val derive :
  (module CRYPTO) -> 'a t -> Int32.t -> 'a t option
val derive_exn :
  (module CRYPTO) -> 'a t -> Int32.t -> 'a t

val derive_path :
  (module CRYPTO) -> 'a t -> Int32.t list -> 'a t option
val derive_path_exn :
  (module CRYPTO) -> 'a t -> Int32.t list -> 'a t

val hardened : Int32.t -> bool
val of_hardened : Int32.t -> Int32.t
val to_hardened : Int32.t -> Int32.t

(** {2 Path IO} *)

module Human_readable : sig
  type node = Int32.t

  val node_of_string : string -> node option
  val node_of_string_exn : string -> node
  val pp_node : node Fmt.t
  val string_of_node : node -> string

  type path = node list

  val path_of_string : string -> path option
  val path_of_string_exn : string -> path
  val pp_path : path Fmt.t
  val string_of_path : path -> string
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
