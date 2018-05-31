(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

module type CRYPTO = sig
  val sha256 : Bigstring.t -> Bigstring.t
  val hmac_sha512 : key:Bigstring.t -> Bigstring.t -> Bigstring.t
end

open Tweetnacl

type _ key =
  | P : Sign.public Sign.key -> Sign.public Sign.key key
  | E : Sign.extended Sign.key -> Sign.extended Sign.key key

let length_of_kind : type a. a key -> int = function
  | P _ -> 32
  | E _ -> 64

let tweet_of_kind : type a. a key -> a = function
  | P pk -> pk
  | E ek -> ek

type 'a t = {
  c : Bigstring.t ;
  k : 'a key ;
}

let ek_bytes = 64 + 32
let pk_bytes = 32 + 32

let blit_to_bytes { k ; c } ?(pos=0) buf =
  let buflen = Bigstring.length buf in
  let min_buflen = length_of_kind k in
  if buflen < pos + min_buflen then 0
  else begin
    Bigstring.blit c 0 buf pos 32 ;
    Sign.blit_to_bytes (tweet_of_kind k) ~pos:(pos+32) buf ;
    32 + length_of_kind k
  end

let to_bytes ({ k ; _ } as key) =
  let buf = Bigstring.create (32 + length_of_kind k) in
  let (_:int) = blit_to_bytes key buf in
  buf

let unsafe_pk_of_bytes ?(pos=0) buf =
  let buflen = Bigstring.length buf in
  if pos < 0 || buflen - pos < pk_bytes then None
  else
    let c = Bigstring.sub buf pos 32 in
    match Sign.unsafe_pk_of_bytes (Bigstring.sub buf (pos+32) 32) with
    | None -> None
    | Some pk -> Some { c ; k = (P pk) }

let unsafe_pk_of_bytes_exn ?pos buf =
  match unsafe_pk_of_bytes ?pos buf with
  | None -> invalid_arg "unsafe_pk_of_bytes_exn"
  | Some pk -> pk

let pk_of_bytes ?(pos=0) buf =
  let buflen = Bigstring.length buf in
  if pos < 0 || buflen - pos < pk_bytes then None
  else
    let buf2 = Bigstring.create pk_bytes in
    Bigstring.blit buf pos buf2 0 pk_bytes ;
    unsafe_pk_of_bytes buf2

let pk_of_bytes_exn ?pos buf =
  match pk_of_bytes ?pos buf with
  | None -> invalid_arg "pk_of_bytes_exn"
  | Some pk -> pk

let unsafe_ek_of_bytes ?(pos=0) buf =
  let buflen = Bigstring.length buf in
  if pos < 0 || buflen - pos < ek_bytes then None
  else
    let c = Bigstring.sub buf pos 32 in
    match Sign.unsafe_ek_of_bytes (Bigstring.sub buf (pos+32) 64) with
    | None -> None
    | Some ek -> Some { c ; k = (E ek) }

let unsafe_ek_of_bytes_exn ?pos buf =
  match unsafe_ek_of_bytes ?pos buf with
  | None -> invalid_arg "unsafe_ek_of_bytes_exn"
  | Some pk -> pk

let ek_of_bytes ?(pos=0) buf =
  let buflen = Bigstring.length buf in
  if pos < 0 || buflen - pos < ek_bytes then None
  else
    let buf2 = Bigstring.create ek_bytes in
    Bigstring.blit buf pos buf2 0 ek_bytes ;
    unsafe_ek_of_bytes buf2

let ek_of_bytes_exn ?pos buf =
  match ek_of_bytes ?pos buf with
  | None -> invalid_arg "ek_of_bytes_exn"
  | Some pk -> pk

let equal { k ; c } { k = k' ; c = c' } =
  Sign.equal (tweet_of_kind k) (tweet_of_kind k') &&
  Bigstring.equal c c'

let key { k ; _ } = tweet_of_kind k
let chaincode { c } = c

let neuterize :
  type a. a Sign.key t -> Sign.public Sign.key t = fun ({ k ; _ } as key) ->
  match k with
  | P _ as pk -> { key with k = pk }
  | E ek -> { key with k = P (Sign.public ek) }

let hardened i = Int32.logand i 0x8000_0000l <> 0l
let of_hardened = Int32.logand 0x7fff_ffffl
let to_hardened = Int32.logor 0x8000_0000l

let create k c =
  { k ; c }

let of_seed crypto ?(pos=0) seed =
  let _pk, sk = Sign.keypair ~seed:(Bigstring.sub seed pos 32) () in
  let ek = Sign.extended sk in
  match (Char.code (Bigstring.get (Sign.to_bytes ek) 31)) land 0x20 with
  | 0 ->
    let module Crypto = (val crypto : CRYPTO) in
    let chaincode_preimage = Bigstring.create 33 in
    Bigstring.set chaincode_preimage 0 '\x01' ;
    Bigstring.blit seed 0 chaincode_preimage 1 32 ;
    let c = Crypto.sha256 chaincode_preimage in
    Some (create (E ek) c)
  | _ -> None

let of_seed_exn crypto ?pos seed =
  match of_seed ?pos crypto seed with
  | Some k -> k
  | None -> invalid_arg "of_seed_exn"

let rec random crypto =
  let seed = Rand.gen 32 in
  match of_seed crypto seed with
  | Some ek -> seed, ek
  | None -> random crypto

let derive_zc :
  type a. (module CRYPTO) -> bool -> a key ->
  Bigstring.t -> Int32.t -> Bigstring.t = fun crypto derive_c kp cp i ->
  begin match kp with
    | E ek ->
      let buf = Bigstring.create 69 in
      Bigstring.fill buf '\x00' ;
      if derive_c then Bigstring.set buf 0 '\x01' ;
      Bigstring.blit (Sign.to_bytes ek) 0 buf 1 64 ;
      EndianBigstring.LittleEndian.set_int32 buf 65 i ;
      buf
    | P pk ->
      let buf = Bigstring.create 37 in
      Bigstring.fill buf '\x00' ;
      Bigstring.set buf 0 (if derive_c then '\x03' else '\x02') ;
      Bigstring.blit (Sign.to_bytes pk) 0 buf 1 32 ;
      EndianBigstring.LittleEndian.set_int32 buf 33 i ;
      buf
  end |> fun buf ->
  let module Crypto = (val crypto : CRYPTO) in
  Crypto.hmac_sha512 ~key:cp buf

let derive_z crypto k c i =
  derive_zc crypto false k c i

let derive_c crypto kp cp i =
  Bigstring.sub (derive_zc crypto true kp cp i) 32 32

let order =
  Z.(of_int 2 ** 252 + of_string "27742317777372353535851937790883648493")

let derive_k z (kp : Sign.extended Sign.key) =
  let kp = Sign.to_bytes kp in
  let kpl = Bigstring.(sub kp 0 32 |> to_string |> Z.of_bits) in
  let kpr = Bigstring.(sub kp 32 32 |> to_string |> Z.of_bits) in
  if Z.(kpl mod order = Z.zero) then None
  else
    let zl = Bigstring.(sub z 0 28 |> to_string |> Z.of_bits) in
    let zr = Bigstring.(sub z 32 32 |> to_string |> Z.of_bits) in
    let kl = Z.(of_int 8 * zl + kpl) in
    let kr = Z.((zr + kpr) mod (pow (of_int 2)) 256) in
    let buf = Bigstring.create 64 in
    Bigstring.blit_of_string (Z.to_bits kl) 0 buf 0 32 ;
    Bigstring.blit_of_string (Z.to_bits kr) 0 buf 32 32 ;
    Sign.ek_of_bytes buf

let derive_a z ap =
  let zl8 = Z.(Bigstring.(sub z 0 28 |> to_string |> of_bits |> mul (of_int 8))) in
  let tweak = Sign.base zl8 in
  let sum = Sign.add ap tweak in
  if Sign.(equal sum (add sum sum)) then None
  else Some sum

let derive :
  type a. (module CRYPTO) -> a t -> Int32.t -> a t option = fun crypto { k ; c = cp } i ->
  match k, (hardened i) with
  | P _, true ->
    invalid_arg "derive: cannot derive an hardened key from a public key"
  | P kp, false ->
    let z = derive_z crypto k cp i in
    let c = derive_c crypto k cp i in
    begin match derive_a z kp with
      | None -> None
      | Some k -> Some (create (P k) c)
    end
  | E kp, false ->
    let pkp = P (Sign.public kp) in
    let z = derive_z crypto pkp cp i in
    let c = derive_c crypto pkp cp i in
    begin match derive_k z kp with
      | None -> None
      | Some k -> Some (create (E k) c)
    end
  | E kp, true ->
    let z = derive_z crypto k cp i in
    let c = derive_c crypto k cp i in
    begin match derive_k z kp with
      | None -> None
      | Some k -> Some (create (E k) c)
    end

let derive_exn crypto k i =
  match derive crypto k i with
  | Some k -> k
  | None -> invalid_arg "derive_exn"

let derive_path :
  type a. (module CRYPTO) -> a t -> Int32.t list -> a t option = fun crypto k path ->
  ListLabels.fold_left path ~init:(Some k) ~f:begin fun a p ->
    match a with
    | None -> None
    | Some a -> derive crypto a p
  end

let derive_path_exn crypto k is =
  match derive_path crypto k is with
  | Some k -> k
  | None -> invalid_arg "derive_path_exn"


module Human_readable = struct
  let derivation_of_string d =
    match String.(get d (length d - 1)) with
    | '\'' ->
      let v = String.(sub d 0 (length d - 1)) |> Int32.of_string in
      to_hardened v
    | _ ->
      Int32.of_string d

  let string_of_derivation = function
    | i when hardened i -> Int32.to_string (of_hardened i) ^ "'"
    | i -> Int32.to_string i

  type t = Int32.t list

  let of_string_exn s =
    match String.split_on_char '/' s with
    | [""] -> []
    | derivations -> List.map derivation_of_string derivations
    | exception _ ->
        invalid_arg (Printf.sprintf "Human_readable.of_string_exn: got %S" s)

  let of_string s =
    try Some (of_string_exn s) with _ -> None

  let to_string t =
    List.map string_of_derivation t |>
    String.concat "/"

  let pp ppf t =
    Format.pp_print_string ppf (to_string t)
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
