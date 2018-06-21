(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

module type CRYPTO = sig
  val sha256 : Bigstring.t -> Bigstring.t
  val hmac_sha512 : key:Bigstring.t -> Bigstring.t -> Bigstring.t
end

open Monocypher

type _ key =
  | P : public Sign.key -> public Sign.key key
  | E : extended Sign.key -> extended Sign.key key

let length_of_key : type a. a key -> int = function
  | P _ -> 32
  | E _ -> 64

let underlying_key : type a. a key -> a = function
  | P pk -> pk
  | E ek -> ek

let copy_key : type a. a key -> a key = function
  | P pk -> P (Sign.copy pk)
  | E ek -> E (Sign.copy ek)

type 'a t = {
  c : Bigstring.t ;
  k : 'a key ;
}

let copy { c ; k } =
  { c = Bigstring.copy c ;
    k = copy_key k }

let wipe { c ; k } =
  wipe c ;
  Sign.wipe (underlying_key k)

let ek_bytes = 64 + 32
let pk_bytes = 32 + 32

let blit_to_bytes { k ; c } ?(pos=0) buf =
  let buflen = Bigstring.length buf in
  let min_buflen = length_of_key k in
  if buflen < pos + min_buflen then 0
  else begin
    Bigstring.blit c 0 buf pos 32 ;
    let (_:int) = Sign.blit (underlying_key k) buf (pos+32) in
    32 + length_of_key k
  end

let to_bytes ({ k ; _ } as key) =
  let buf = Bigstring.create (32 + length_of_key k) in
  let (_:int) = blit_to_bytes key buf in
  buf

let unsafe_pk_of_bytes ?(pos=0) buf =
  let buflen = Bigstring.length buf in
  if pos < 0 || buflen - pos < pk_bytes then
    invalid_arg "unsafe_pk_of_bytes" ;
  let c = Bigstring.sub buf pos 32 in
  let pk = Sign.unsafe_pk_of_bytes (Bigstring.sub buf (pos+32) 32) in
  { c ; k = (P pk) }

let pk_of_bytes ?(pos=0) buf =
  let buflen = Bigstring.length buf in
  if pos < 0 || buflen - pos < pk_bytes then
    invalid_arg "pk_of_bytes" ;
  let buf2 = Bigstring.create pk_bytes in
  Bigstring.blit buf pos buf2 0 pk_bytes ;
  unsafe_pk_of_bytes buf2

let unsafe_ek_of_bytes ?(pos=0) buf =
  let buflen = Bigstring.length buf in
  if pos < 0 || buflen - pos < ek_bytes then
    invalid_arg "unsafe_ek_of_bytes" ;
  let c = Bigstring.sub buf pos 32 in
  let ek = Sign.unsafe_ek_of_bytes (Bigstring.sub buf (pos+32) 64) in
  { c ; k = (E ek) }

let ek_of_bytes ?(pos=0) buf =
  let buflen = Bigstring.length buf in
  if pos < 0 || buflen - pos < ek_bytes then
    invalid_arg "ek_of_bytes" ;
  let buf2 = Bigstring.create ek_bytes in
  Bigstring.blit buf pos buf2 0 ek_bytes ;
  unsafe_ek_of_bytes buf2

let equal { k ; c } { k = k' ; c = c' } =
  Sign.equal (underlying_key k) (underlying_key k') &&
  Bigstring.equal c c'

let key { k ; _ } = underlying_key k
let chaincode { c } = c

let neuterize :
  type a. a Sign.key t -> public Sign.key t = fun ({ k ; _ } as key) ->
  match k with
  | P _ as pk -> { key with k = pk }
  | E ek -> { key with k = P (Sign.neuterize ek) }

let hardened i = Int32.logand i 0x8000_0000l <> 0l
let of_hardened = Int32.logand 0x7fff_ffffl
let to_hardened = Int32.logor 0x8000_0000l

let create k c =
  { k ; c }

let of_seed crypto ?(pos=0) seed =
  let seedlen = Bigstring.length seed in
  if seedlen - pos < Sign.skbytes then
    invalid_arg "of_seed" ;
  let sk =
    Sign.unsafe_sk_of_bytes (Bigstring.sub seed pos Sign.skbytes) in
  let ek = Sign.extend sk in
  let ekbuf = Sign.buffer ek in
  match (Char.code (Bigstring.get ekbuf 31)) land 0x20 with
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
      Bigstring.blit (Sign.buffer ek) 0 buf 1 64 ;
      EndianBigstring.LittleEndian.set_int32 buf 65 i ;
      buf
    | P pk ->
      let buf = Bigstring.create 37 in
      Bigstring.fill buf '\x00' ;
      Bigstring.set buf 0 (if derive_c then '\x03' else '\x02') ;
      Bigstring.blit (Sign.buffer pk) 0 buf 1 32 ;
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

let derive_k z (kp : extended Sign.key) =
  let kp = Sign.buffer kp in
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
    Some (Sign.unsafe_ek_of_bytes buf)

let derive_a z ap =
  let zl8 = Z.(Bigstring.(sub z 0 28 |> to_string |> of_bits |> mul (of_int 8))) in
  let tweak = Ed25519.scalarmult_base zl8 in
  let sum = Ed25519.add ap tweak in
  if Ed25519.(equal sum (add sum sum)) then None
  else Some sum

let derive :
  type a. (module CRYPTO) -> a t -> Int32.t -> a t option = fun crypto { k ; c = cp } i ->
  match k, (hardened i) with
  | P _, true ->
    invalid_arg "derive: cannot derive an hardened key from a public key"
  | P kp, false ->
    let z = derive_z crypto k cp i in
    let c = derive_c crypto k cp i in
    begin match derive_a z (Ed25519.of_pk kp) with
      | None -> None
      | Some k -> Some (create (P (Ed25519.to_pk k)) c)
    end
  | E kp, false ->
    let pkp = P (Sign.neuterize kp) in
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
  type node = Int32.t

  let node_of_string str =
    match Int32.of_string_opt str with
    | Some node -> Some node
    | None ->
      match Int32.of_string_opt String.(sub str 0 ((length str) - 1)) with
      | None -> None
      | Some node -> Some (to_hardened node)

  let node_of_string_exn str =
    match node_of_string str with
    | None ->
      invalid_arg (Printf.sprintf "node_of_string_exn: got %S" str)
    | Some str -> str

  let pp_node ppf node =
    match hardened node with
    | true -> Fmt.pf ppf "%ld'" (of_hardened node)
    | false -> Fmt.pf ppf "%ld" node

  let string_of_node = Fmt.to_to_string pp_node

  type path = Int32.t list

  let path_of_string_exn s =
    match String.split_on_char '/' s with
    | [""] -> []
    | nodes ->
      List.map node_of_string_exn nodes

  let path_of_string s =
    try Some (path_of_string_exn s) with _ -> None

  let pp_path =
    Fmt.(list ~sep:(const char '/') pp_node)

  let string_of_path = Fmt.to_to_string pp_path
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
