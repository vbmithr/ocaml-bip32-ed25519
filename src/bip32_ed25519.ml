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
  k : 'a kind ;
  c : Cstruct.t ;
  path : Int32.t list ;
  parent : Cstruct.t ;
}

let equal { k ; _ } { k = k' ; _ } =
  Sign.equal (tweet_of_kind k) (tweet_of_kind k')

let key { k ; _ } = tweet_of_kind k

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

let pp ppf { k ; c ; path ; parent } =
  Format.fprintf ppf "@[<hov 0>key %a@ chaincode %a@ path %a@ parent %a@]"
    pp_kind k
    Hex.pp (Hex.of_cstruct c)
    (Format.pp_print_list
       ~pp_sep:(fun ppf () -> Format.pp_print_char ppf '/')
       pp_print_path) (List.rev path)
    Hex.pp (Hex.of_cstruct parent)

let create ?(parent=Cstruct.create 20) k c path =
  { k ; c ; path ; parent }

let check_seed seed =
  let _pk, sk = Sign.keypair ~seed () in
  let ek = Sign.extended sk in
  if Cstruct.get_uint8 (Sign.to_cstruct ek) 31 land 0x20 <> 0 then
    invalid_arg "check_seed: bad_entropy" ;
  ek

let of_seed crypto seed =
  let module Crypto = (val crypto : CRYPTO) in
  let sk = check_seed seed in
  let chaincode_preimage = Cstruct.create 33 in
  Cstruct.set_uint8 chaincode_preimage 0 1 ;
  Cstruct.blit seed 0 chaincode_preimage 1 32 ;
  let c = Crypto.sha256 chaincode_preimage in
  create (E sk) c []

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
  if Z.(kpl mod order = zero) then
    invalid_arg "derive: bad secret child" ;
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
  if Sign.(equal sum (add sum sum)) then
    invalid_arg "derive: bad public child" ;
  sum

let derive : type a. (module CRYPTO) -> a key -> Int32.t -> a key = fun crypto { k ; c = cp ; path ; _ } i ->
  match k, (hardened i) with
  | P _, true ->
    invalid_arg "derive: cannot derive an hardened key from a public key"
  | P kp, false ->
    let z = derive_z crypto k cp i in
    let c = derive_c crypto k cp i in
    let k = derive_a z kp in
    create (P k) c (i :: path)
  | E kp, false ->
    let pkp = P (Sign.public kp) in
    let z = derive_z crypto pkp cp i in
    let c = derive_c crypto pkp cp i in
    let k = derive_k z kp in
    create (E k) c (i :: path)
  | E kp, true ->
    let z = derive_z crypto k cp i in
    let c = derive_c crypto k cp i in
    let k = derive_k z kp in
    create (E k) c (i :: path)

let derive_path : type a. (module CRYPTO) -> a key -> Int32.t list -> a key = fun crypto k path ->
  ListLabels.fold_left path ~init:k ~f:(derive crypto)

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
