(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

module type CRYPTO = sig
  val sha256 : Cstruct.t -> Cstruct.t
  val hmac_sha512 : key:Cstruct.t -> Cstruct.t -> Cstruct.t
end

open Tweetnacl

type _ kind =
  | P : Sign.public Sign.key -> Sign.public Sign.key kind
  | E : Sign.extended Sign.key -> Sign.extended Sign.key kind

let tweet_of_kind : type a. a kind -> a = function
  | P pk -> pk
  | E ek -> ek

let pp_kind :
  type a. Format.formatter -> a kind -> unit = fun ppf -> function
  | P pk -> Sign.pp ppf pk
  | E ek -> Sign.pp ppf ek

type 'a key = {
  c : Cstruct.t ;
  k : 'a kind ;
}

let ek_bytes = 64 + 32
let pk_bytes = 32 + 32

let write : type a. ?pos:int -> a key -> Cstruct.t -> int =
  fun ?(pos=0) { k ; c } cs ->
    let cs = Cstruct.shift cs pos in
    Cstruct.blit c 0 cs 0 32 ;
    match k with
    | P pk -> Sign.blit_to_cstruct pk cs ~pos:32 ; pos + pk_bytes
    | E ek -> Sign.blit_to_cstruct ek cs ~pos:32 ; pos + ek_bytes

let to_bytes : type a. a key -> Cstruct.t = fun ({ k ; _ } as key) ->
  match k with
  | P _ ->
    let cs = Cstruct.create_unsafe pk_bytes in
    let (_:int) = write key cs in
    cs
  | E _ ->
    let cs = Cstruct.create_unsafe ek_bytes in
    let (_:int) = write key cs in
    cs

let of_pk ?(pos=0) cs =
  let cs = Cstruct.shift cs pos in
  let c = Cstruct.sub cs 0 32 in
  match Sign.pk_of_cstruct (Cstruct.sub cs 32 32) with
  | None -> None
  | Some pk -> Some { c ; k = (P pk) }

let of_pk_exn ?pos cs =
  match of_pk ?pos cs with
  | None -> invalid_arg "of_pk_exn"
  | Some pk -> pk

let of_ek ?(pos=0) cs =
  let cs = Cstruct.shift cs pos in
  let c = Cstruct.sub cs 0 32 in
  match Sign.ek_of_cstruct (Cstruct.sub cs 32 64) with
  | None -> None
  | Some ek -> Some { c ; k = (E ek) }

let of_ek_exn ?pos cs =
  match of_ek ?pos cs with
  | None -> invalid_arg "of_ek_exn"
  | Some ek -> ek

let equal { k ; c } { k = k' ; c = c' } =
  Sign.equal (tweet_of_kind k) (tweet_of_kind k') &&
  Cstruct.equal c c'

let key { k ; _ } = tweet_of_kind k
let chaincode { c } = c

let neuterize : type a. a Sign.key key -> Sign.public Sign.key key = fun ({ k ; _ } as key) ->
  match k with
  | P _ as pk -> { key with k = pk }
  | E ek -> { key with k = P (Sign.public ek) }

let hardened i = Int32.logand i 0x8000_0000l <> 0l
let of_hardened = Int32.logand 0x7fff_ffffl
let to_hardened = Int32.logor 0x8000_0000l

let pp_print_path ppf i =
  if hardened i then Format.fprintf ppf "%ld'" (of_hardened i)
  else Format.fprintf ppf "%ld" i

let pp ppf { k ; c } =
  Format.fprintf ppf "@[<hov 0>key %a@ chaincode %a@]"
    pp_kind k
    Hex.pp (Hex.of_cstruct c)

let create k c =
  { k ; c }

let of_seed crypto ?(pos=0) seed =
  let seed = Cstruct.shift seed pos in
  let _pk, sk = Sign.keypair ~seed () in
  let ek = Sign.extended sk in
  match Cstruct.get_uint8 (Sign.to_cstruct ek) 31 land 0x20 with
  | 0 ->
    let module Crypto = (val crypto : CRYPTO) in
    let chaincode_preimage = Cstruct.create 33 in
    Cstruct.set_uint8 chaincode_preimage 0 1 ;
    Cstruct.blit seed 0 chaincode_preimage 1 32 ;
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
  type a. (module CRYPTO) -> bool -> a kind -> Cstruct.t -> Int32.t -> Cstruct.t = fun crypto derive_c kp cp i ->
  begin match kp with
    | E ek ->
      let cs = Cstruct.create 69 in
      if derive_c then Cstruct.set_uint8 cs 0 1 ;
      Cstruct.blit (Sign.to_cstruct ek) 0 cs 1 64 ;
      Cstruct.LE.set_uint32 cs 65 i ;
      cs
    | P pk ->
      let cs = Cstruct.create 37 in
      Cstruct.set_uint8 cs 0 (if derive_c then 3 else 2) ;
      Cstruct.blit (Sign.to_cstruct pk) 0 cs 1 32 ;
      Cstruct.LE.set_uint32 cs 33 i ;
      cs
  end |> fun cs ->
  let module Crypto = (val crypto : CRYPTO) in
  Crypto.hmac_sha512 ~key:cp cs

let derive_z crypto k c i =
  derive_zc crypto false k c i

let derive_c crypto kp cp i =
  Cstruct.sub (derive_zc crypto true kp cp i) 32 32

let order =
  Z.(of_int 2 ** 252 + of_string "27742317777372353535851937790883648493")

let derive_k z (kp : Sign.extended Sign.key) =
  let kp = Sign.to_cstruct kp in
  let kpl = Cstruct.(sub kp 0 32 |> to_string |> Z.of_bits) in
  let kpr = Cstruct.(sub kp 32 32 |> to_string |> Z.of_bits) in
  if Z.(kpl mod order = Z.zero) then None
  else
    let zl = Cstruct.(sub z 0 28 |> to_string |> Z.of_bits) in
    let zr = Cstruct.(sub z 32 32 |> to_string |> Z.of_bits) in
    let kl = Z.(of_int 8 * zl + kpl) in
    let kr = Z.((zr + kpr) mod (pow (of_int 2)) 256) in
    let cs = Cstruct.create 64 in
    Cstruct.blit_from_string (Z.to_bits kl) 0 cs 0 32 ;
    Cstruct.blit_from_string (Z.to_bits kr) 0 cs 32 32 ;
    Sign.ek_of_cstruct cs

let derive_a z ap =
  let zl8 = Z.(Cstruct.(sub z 0 28 |> to_string |> of_bits |> mul (of_int 8))) in
  let tweak = Sign.base zl8 in
  let sum = Sign.add ap tweak in
  if Sign.(equal sum (add sum sum)) then None
  else Some sum

let derive :
  type a. (module CRYPTO) -> a key -> Int32.t -> a key option = fun crypto { k ; c = cp } i ->
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
  type a. (module CRYPTO) -> a key -> Int32.t list -> a key option = fun crypto k path ->
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
