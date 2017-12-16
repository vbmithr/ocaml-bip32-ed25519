open Sodium

module S256 = Hash.Sha256
module S512 = Hash.Sha512
module H512 = Auth.Hmac_sha512
module SM = Scalar_mult.Ed25519

type public = Sign.public_key
type secret = Cstruct.t

type _ kind =
  | Sk : secret -> secret kind
  | Pk : public -> public kind

type 'a key = {
  k : 'a kind ;
  c : H512.secret_key ;
  path : Int32.t list ;
  parent : Cstruct.t ;
}

let pk_of_sk cs =
  SM.Bigbytes.to_integer Cstruct.(sub cs 0 32 |> to_bigarray) |>
  SM.base |>
  SM.Bigbytes.of_group_elt |>
  Sign.Bigbytes.to_public_key

let key : type a. a key -> a = fun { k } ->
  match k with
  | Sk sk -> sk
  | Pk pk -> pk

let neuterize : type a. a key -> public key = fun ({ k } as key) ->
  match k with
  | Pk _ -> key
  | Sk sk -> { key with k = Pk (pk_of_sk sk) }

let hardened i =
  Int32.logand i 0x8000_0000l <> 0l

let pp_print_path ppf i =
  if hardened i then
    Format.fprintf ppf "%ld'" Int32.(logand i 0x7fff_ffffl)
  else
    Format.fprintf ppf "%ld" i

let pp_kind :
  type a. Format.formatter -> a kind -> unit = fun ppf k ->
  let repr = match k with
    | Sk sk -> sk
    | Pk pk -> Sign.Bigbytes.of_public_key pk |> Cstruct.of_bigarray in
  Hex.pp ppf (repr |> Hex.of_cstruct)

let pp ppf { k ; c ; path ; parent } =
  Format.fprintf ppf "@[<hov 0>key %a@ chaincode %a@ path %a@ parent %a@]"
    pp_kind k
    Hex.pp (H512.Bigbytes.of_key c |> Cstruct.of_bigarray |> Hex.of_cstruct)
    (Format.pp_print_list
       ~pp_sep:(fun ppf () -> Format.pp_print_char ppf '/')
       pp_print_path) (List.rev path)
    Hex.pp (Hex.of_cstruct parent)

let create ?(parent=Cstruct.create 20) k c path =
  { k ; c ; path ; parent }

let sk_of_seed seed =
  Sign.Bigbytes.of_seed seed |>
  S512.Bigbytes.digest |>
  S512.Bigbytes.of_hash |>
  Cstruct.of_bigarray

let check_seed seed =
  let sk = sk_of_seed seed in
  if Cstruct.get_uint8 sk 31 land 0x20 <> 0 then
    invalid_arg "check_seed: bad_entropy"

let of_seed seed =
  check_seed seed ;
  let sk = sk_of_seed seed in
  let chaincode_preimage = Cstruct.create 33 in
  Cstruct.set_uint8 chaincode_preimage 0 1 ;
  Cstruct.blit (Sign.Bigbytes.of_seed seed |> Cstruct.of_bigarray) 0 chaincode_preimage 1 32 ;
  let c = S256.Bigbytes.(digest (Cstruct.to_bigarray chaincode_preimage) |> of_hash) |>
          H512.Bigbytes.to_key in
  create (Sk sk) c []

let derive_zc :
  type a. bool -> a kind -> H512.secret_key -> Int32.t -> Cstruct.t = fun derive_c kp cp i ->
  begin match kp with
    | Sk sk ->
      let cs = Cstruct.create 69 in
      if derive_c then Cstruct.set_uint8 cs 0 1 ;
      Cstruct.blit sk 0 cs 1 64 ;
      Cstruct.LE.set_uint32 cs 65 i ;
      cs
    | Pk pk ->
      let pk_bytes = Sign.Bigbytes.of_public_key pk |> Cstruct.of_bigarray in
      let cs = Cstruct.create 37 in
      Cstruct.set_uint8 cs 0 (if derive_c then 3 else 2) ;
      Cstruct.blit pk_bytes 0 cs 1 32 ;
      Cstruct.LE.set_uint32 cs 33 i ;
      cs
  end |> fun cs ->
  H512.Bigbytes.(auth cp (Cstruct.to_bigarray cs) |> of_auth) |>
  Cstruct.of_bigarray

let derive_z k c i =
  derive_zc false k c i

let derive_c kp cp i =
  Cstruct.sub (derive_zc true kp cp i) 32 32 |>
  Cstruct.to_bigarray |>
  H512.Bigbytes.to_key

let point_of_group_elt ge =
  ge |> SM.Bigbytes.of_group_elt |> ECArith.Bigbytes.to_point

let group_elt_of_point p =
  p |> ECArith.Bigbytes.of_point |> SM.Bigbytes.to_group_elt

let point_of_pk pk =
  pk |> Sign.Bigbytes.of_public_key |> ECArith.Bigbytes.to_point

let pk_of_point point =
  point |> ECArith.Bigbytes.of_point |> Sign.Bigbytes.to_public_key

let order =
  Z.(of_int 2 ** 252 + of_string "27742317777372353535851937790883648493")

let derive_k z kp =
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
  cs

let derive_a z kp =
  let zl = Z.(Cstruct.(sub z 0 28 |> to_string |> of_bits |> mul (of_int 8))) in
  let zl_bits = Z.to_bits zl in
  let zl_len = String.length zl_bits in
  let scalar = Cstruct.create 32 in
  Cstruct.blit_from_string zl_bits 0 scalar 0 zl_len ;
  let xl_8_b = SM.(base (Bigbytes.to_integer scalar.buffer)) in
  let sum = ECArith.add (point_of_pk kp) (point_of_group_elt xl_8_b) in
  if not (ECArith.is_valid_point sum) then
    invalid_arg "derive: bad public child" ;
  pk_of_point sum

let derive : type a. a key -> Int32.t -> a key = fun { k ; c = cp ; path } i ->
  match k, (hardened i) with
  | Pk _, true ->
    invalid_arg "derive: cannot derive an hardened key from a public key"
  | Pk kp, false ->
    let z = derive_z k cp i in
    let c = derive_c k cp i in
    let k = derive_a z kp in
    create (Pk k) c (i :: path)
  | Sk kp, false ->
    let pkp = Pk (pk_of_sk kp) in
    let z = derive_z pkp cp i in
    let c = derive_c pkp cp i in
    let k = derive_k z kp in
    create (Sk k) c (i :: path)
  | Sk kp, true ->
    let z = derive_z k cp i in
    let c = derive_c k cp i in
    let k = derive_k z kp in
    create (Sk k) c (i :: path)

let derive_path : type a. a key -> Int32.t list -> a key = fun k path ->
  ListLabels.fold_left path ~init:k ~f:derive
