open Tweetnacl

module H512 = Digestif.SHA512.Bigstring
module S256 = Digestif.SHA256.Bigstring

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
  c : H512.buffer ;
  path : Int32.t list ;
  parent : Cstruct.t ;
}

let equal { k } { k = k' } =
  Sign.equal (tweet_of_kind k) (tweet_of_kind k')

let key { k } = tweet_of_kind k

let neuterize : type a. a Sign.key key -> Sign.public Sign.key key = fun ({ k } as key) ->
  match k with
  | P _ as pk -> { key with k = pk }
  | E ek -> { key with k = P (Sign.public ek) }

let hardened i =
  Int32.logand i 0x8000_0000l <> 0l

let pp_print_path ppf i =
  if hardened i then
    Format.fprintf ppf "%ld'" Int32.(logand i 0x7fff_ffffl)
  else
    Format.fprintf ppf "%ld" i

let pp ppf { k ; c ; path ; parent } =
  Format.fprintf ppf "@[<hov 0>key %a@ chaincode %a@ path %a@ parent %a@]"
    pp_kind k
    Hex.pp (c |> Cstruct.of_bigarray |> Hex.of_cstruct)
    (Format.pp_print_list
       ~pp_sep:(fun ppf () -> Format.pp_print_char ppf '/')
       pp_print_path) (List.rev path)
    Hex.pp (Hex.of_cstruct parent)

let create ?(parent=Cstruct.create 20) k c path =
  { k ; c ; path ; parent }

let check_seed seed =
  let pk, sk = Sign.keypair ~seed () in
  let ek = Sign.extended sk in
  if Cstruct.get_uint8 (Sign.to_cstruct ek) 31 land 0x20 <> 0 then
    invalid_arg "check_seed: bad_entropy" ;
  ek

let of_seed seed =
  let sk = check_seed seed in
  let chaincode_preimage = Cstruct.create 33 in
  Cstruct.set_uint8 chaincode_preimage 0 1 ;
  Cstruct.blit seed 0 chaincode_preimage 1 32 ;
  let c = Cstruct.(S256.(digest (to_bigarray chaincode_preimage))) in
  create (E sk) c []

let derive_zc :
  type a. bool -> a kind -> Cstruct.buffer -> Int32.t -> Cstruct.t = fun derive_c kp cp i ->
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
  Cstruct.(H512.hmac cp (to_bigarray cs) |> of_bigarray)

let derive_z k c i =
  derive_zc false k c i

let derive_c kp cp i =
  Cstruct.sub (derive_zc true kp cp i) 32 32 |>
  Cstruct.to_bigarray

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

let derive : type a. a key -> Int32.t -> a key = fun { k ; c = cp ; path } i ->
  match k, (hardened i) with
  | P _, true ->
    invalid_arg "derive: cannot derive an hardened key from a public key"
  | P kp, false ->
    let z = derive_z k cp i in
    let c = derive_c k cp i in
    let k = derive_a z kp in
    create (P k) c (i :: path)
  | E kp, false ->
    let pkp = P (Sign.public kp) in
    let z = derive_z pkp cp i in
    let c = derive_c pkp cp i in
    let k = derive_k z kp in
    create (E k) c (i :: path)
  | E kp, true ->
    let z = derive_z k cp i in
    let c = derive_c k cp i in
    let k = derive_k z kp in
    create (E k) c (i :: path)

let derive_path : type a. a key -> Int32.t list -> a key = fun k path ->
  ListLabels.fold_left path ~init:k ~f:derive
